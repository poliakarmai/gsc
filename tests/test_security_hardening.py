"""Tests for DD-07 (rate limiting) and DD-08 (security headers).

Unit-level: the limiter and the middleware are tested in isolation — no DB,
no network. They exercise the pure logic (sliding window, header injection)
without spinning up the full FastAPI app (which requires PostgreSQL).
"""
import pytest

from gsc_cloud.rate_limit import SlidingWindowLimiter, rate_limit, _LIMITER
from gsc_cloud.security_headers import SecurityHeadersMiddleware, _SECURITY_HEADERS


# ── DD-07: SlidingWindowLimiter ───────────────────────────────

def test_limiter_allows_up_to_limit():
    lim = SlidingWindowLimiter()
    for _ in range(3):
        assert lim.allow("k", limit=3, window=60) is True
    assert lim.allow("k", limit=3, window=60) is False


def test_limiter_keys_are_independent():
    lim = SlidingWindowLimiter()
    for _ in range(5):
        lim.allow("tenant-a", limit=5, window=60)
    # exhaust tenant-a, tenant-b still passes
    assert lim.allow("tenant-a", limit=5, window=60) is False
    assert lim.allow("tenant-b", limit=5, window=60) is True


def test_limiter_window_resets():
    lim = SlidingWindowLimiter()
    assert lim.allow("k", limit=1, window=60) is True
    assert lim.allow("k", limit=1, window=60) is False
    # simulate the window elapsing by shifting the recorded timestamp back
    with lim._lock:
        lim._hits["k"][0] -= 61.0
    assert lim.allow("k", limit=1, window=60) is True


def test_limiter_window_does_not_accumulate_stale_hits():
    # Expired timestamps are popped; the deque never grows past `limit`
    # entries, so per-key memory stays bounded by `limit`.
    lim = SlidingWindowLimiter()
    for _ in range(3):
        lim.allow("k", limit=3, window=60)
    assert len(lim._hits["k"]) == 3
    with lim._lock:
        for i in range(len(lim._hits["k"])):
            lim._hits["k"][i] -= 61.0
    lim.allow("k", limit=3, window=60)
    # all 3 stale entries popped, exactly one fresh entry remains
    assert len(lim._hits["k"]) == 1


# ── DD-08: SecurityHeadersMiddleware ──────────────────────────

def test_security_headers_contain_expected_names():
    names = {name.lower() for name, _ in _SECURITY_HEADERS}
    assert {"strict-transport-security", "x-frame-options",
            "x-content-type-options", "content-security-policy"} <= names


def test_middleware_does_not_overwrite_existing_header():
    # Pure-ASGI contract: an existing header (e.g. set by a reverse proxy)
    # must win over the middleware default.
    async def _app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"x-frame-options", b"SAMEORIGIN")],
        })
        await send({"type": "http.response.body", "body": b""})

    middleware = SecurityHeadersMiddleware(_app)

    captured = {}

    async def _receive():
        return {"type": "http.request"}

    async def _send(message):
        if message["type"] == "http.response.start":
            captured["headers"] = dict(message["headers"])

    import asyncio
    asyncio.run(middleware(
        {"type": "http", "method": "GET"},
        _receive,
        _send,
    ))

    # existing header preserved verbatim
    assert captured["headers"][b"x-frame-options"] == b"SAMEORIGIN"
    # new headers still added (HTTP headers are case-insensitive)
    lower = {k.lower(): v for k, v in captured["headers"].items()}
    assert b"strict-transport-security" in lower
    assert b"x-content-type-options" in lower


def test_rate_limit_dependency_returns_429_when_exhausted():
    # Reset the global limiter so the test is deterministic.
    with _LIMITER._lock:
        _LIMITER._hits.clear()

    dep = rate_limit(2, window=60.0, resource="scan")

    # First two pass (no exception), third raises HTTPException(429).
    dep("gsk_key_abc")
    dep("gsk_key_abc")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        dep("gsk_key_abc")
    assert exc.value.status_code == 429
    assert exc.value.headers.get("Retry-After") == "60"
