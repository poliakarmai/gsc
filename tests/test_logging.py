# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for ``gsc_cloud.logging`` (structured JSON logging + request-id).

Unit-level: the formatter and the middleware are exercised in isolation —
no DB, no network, no FastAPI app.
"""
from __future__ import annotations

import asyncio
import json
import logging

import pytest

from gsc_cloud.logging import (
    JsonFormatter,
    RequestIdMiddleware,
    configure_logging,
    get_request_id,
    request_id_var,
    set_request_id,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _fmt(record: logging.LogRecord) -> dict:
    return json.loads(JsonFormatter().format(record))


def _make_record(msg: str = "hello") -> logging.LogRecord:
    return logging.LogRecord(
        name="gsc_cloud.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


def _make_app():
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    return app


def _drive(mw, scope) -> list:
    """Drive middleware over one scope, return captured response headers."""
    captured: dict = {"headers": []}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["headers"] = list(message.get("headers", []))

    async def run():
        await mw(scope, receive, send)

    asyncio.run(run())
    return captured["headers"]


def _lower(headers) -> dict:
    return {k.lower(): v for k, v in headers}


# ── JsonFormatter ─────────────────────────────────────────────────────


def test_json_formatter_emits_valid_json_with_core_fields():
    data = _fmt(_make_record())
    assert data["level"] == "INFO"
    assert data["logger"] == "gsc_cloud.test"
    assert data["message"] == "hello"
    assert "timestamp" in data


def test_extra_fields_surface_in_json():
    rec = _make_record()
    rec.component = "api"
    rec.ok = True
    data = _fmt(rec)
    assert data["component"] == "api"
    assert data["ok"] is True


def test_exc_info_is_serialized():
    rec = logging.LogRecord(
        name="gsc_cloud.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="boom",
        args=(),
        exc_info=(ValueError, ValueError("bad"), None),
    )
    data = _fmt(rec)
    assert "exc_info" in data
    assert "ValueError" in data["exc_info"]


def test_request_id_from_contextvar_is_included():
    token = set_request_id("req-abc123")
    try:
        data = _fmt(_make_record())
        assert data["request_id"] == "req-abc123"
    finally:
        request_id_var.reset(token)


def test_no_request_id_field_when_unset():
    data = _fmt(_make_record())
    assert "request_id" not in data


# ── configure_logging ─────────────────────────────────────────────────


def test_configure_logging_json_sets_json_formatter():
    configure_logging(level=logging.INFO, fmt="json")
    logger = logging.getLogger("gsc_cloud")
    assert any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers)


def test_configure_logging_text_sets_plain_formatter():
    configure_logging(level=logging.INFO, fmt="text")
    logger = logging.getLogger("gsc_cloud")
    assert logger.handlers
    assert not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers)


def test_configure_logging_unknown_fmt_raises():
    with pytest.raises(ValueError):
        configure_logging(fmt="yaml")


# ── RequestIdMiddleware ───────────────────────────────────────────────


def test_middleware_mints_request_id_when_absent():
    mw = RequestIdMiddleware(_make_app())
    headers = _lower(_drive(mw, {"type": "http", "method": "GET", "headers": []}))
    assert b"x-request-id" in headers
    assert len(headers[b"x-request-id"]) == 16  # uuid4().hex[:16]


def test_middleware_adopts_incoming_request_id():
    mw = RequestIdMiddleware(_make_app())
    scope = {
        "type": "http",
        "method": "GET",
        "headers": [(b"x-request-id", b"client-supplied-123")],
    }
    headers = _lower(_drive(mw, scope))
    assert headers[b"x-request-id"] == b"client-supplied-123"


def test_middleware_binds_request_id_during_request_and_resets_after():
    seen: dict = {}

    async def app(scope, receive, send):
        seen["id"] = get_request_id()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = RequestIdMiddleware(app)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        pass

    async def run():
        await mw({"type": "http", "method": "GET", "headers": []}, receive, send)

    asyncio.run(run())
    assert seen["id"] is not None and len(seen["id"]) == 16
    # contextvar is reset after the request completes
    assert get_request_id() is None


def test_middleware_passes_through_non_http_scope():
    calls: list = []

    async def app(scope, receive, send):
        calls.append(scope["type"])

    mw = RequestIdMiddleware(app)

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        pass

    async def run():
        await mw({"type": "lifespan"}, receive, send)

    asyncio.run(run())
    assert calls == ["lifespan"]
    assert get_request_id() is None
