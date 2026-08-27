#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for ``gsc_cloud.metrics`` (Prometheus-compatible stdlib metrics).

Each test uses a fresh ``MetricsRegistry`` (via fixture) so the global
``REGISTRY`` does not bleed state between tests.
"""
from __future__ import annotations

import asyncio
import threading
from typing import List

import pytest

from gsc_cloud import metrics as M


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def reg():
    """Fresh registry per test."""
    return M.MetricsRegistry()


def _make_app(status_code: int = 200):
    """Build a minimal ASGI app that emits a single 200 (or other) response."""
    async def app(_scope, _receive, send):
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [],
        })
        await send({"type": "http.response.body", "body": b""})
    return app


def _drive_middleware(mw, scopes: List[dict]) -> List[dict]:
    """Drive ``mw`` synchronously over a list of http scopes.

    Returns the list of ``http.response.start`` messages seen, useful
    for asserting that the middleware did (or did not) call send.
    """
    started: List[dict] = []

    async def run_one(scope):
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                started.append(dict(message))

        await mw(scope, receive, send)

    for s in scopes:
        asyncio.run(run_one(s))
    return started


# ── Counter ────────────────────────────────────────────────────────────


def test_counter_inc_and_labels_appear_in_render(reg):
    """Counter increments and labels must surface in the rendered output."""
    c = reg.counter("gsc_requests_total", "Total requests")
    c.inc()
    c.inc(amount=2)
    c.inc(amount=1, labels={"method": "GET", "path": "/health"})

    body = M.render_metrics(reg)
    assert "# HELP gsc_requests_total Total requests" in body
    assert "# TYPE gsc_requests_total counter" in body
    # Unlabelled sample (the 3 from inc() + inc(2)).
    assert "\ngsc_requests_total 3\n" in body
    # Labelled sample is escaped and sorted by key.
    assert '\ngsc_requests_total{method="GET",path="/health"} 1\n' in body


def test_counter_negative_amount_ignored(reg):
    """Negative increments on a counter are dropped (counters are monotonic)."""
    c = reg.counter("gsc_monotonic", "monotonic")
    c.inc(5)
    c.inc(-3)
    body = M.render_metrics(reg)
    assert "gsc_monotonic 5" in body
    assert "gsc_monotonic 2" not in body


def test_counter_re_registration_is_idempotent(reg):
    """Re-registering the same counter returns the existing instance."""
    c1 = reg.counter("gsc_idem", "help")
    c2 = reg.counter("gsc_idem", "help")
    assert c1 is c2
    c1.inc(2)
    assert c2.value() == 2.0


def test_counter_kind_conflict_raises(reg):
    """Re-registering a different kind under the same name raises."""
    reg.counter("gsc_kinds", "as counter")
    with pytest.raises(ValueError):
        reg.gauge("gsc_kinds", "as gauge")


# ── Gauge ──────────────────────────────────────────────────────────────


def test_gauge_set_inc_dec(reg):
    g = reg.gauge("gsc_depth", "queue depth")
    g.set(10)
    assert g.value() == 10.0
    g.inc(5)
    assert g.value() == 15.0
    g.dec(3)
    assert g.value() == 12.0
    g.dec(20)
    # Dec can drive the value negative — gauges are not bounded below.
    assert g.value() == -8.0

    body = M.render_metrics(reg)
    assert "# TYPE gsc_depth gauge" in body
    assert "gsc_depth -8" in body


def test_gauge_with_labels(reg):
    g = reg.gauge("gsc_workers", "active workers")
    g.set(2, labels={"pool": "scan"})
    g.set(1, labels={"pool": "webhook"})
    g.inc(3, labels={"pool": "scan"})
    body = M.render_metrics(reg)
    assert 'gsc_workers{pool="scan"} 5' in body
    assert 'gsc_workers{pool="webhook"} 1' in body


# ── Histogram ──────────────────────────────────────────────────────────


def test_histogram_buckets_sum_count(reg):
    """Buckets are cumulative; +Inf must equal count; sum/count add up."""
    h = reg.histogram(
        "gsc_latency_seconds",
        "request latency",
        buckets=(0.1, 0.5, 1.0),
    )
    h.observe(0.05)   # -> bucket 0.1, 0.5, 1.0, +Inf
    h.observe(0.3)    # -> bucket 0.5, 1.0, +Inf
    h.observe(2.0)    # -> only +Inf

    body = M.render_metrics(reg)
    assert "# TYPE gsc_latency_seconds histogram" in body
    # Cumulative counts: bucket le=0.1 -> 1, 0.5 -> 2, 1.0 -> 2, +Inf -> 3
    assert 'gsc_latency_seconds_bucket{le="0.1"} 1' in body
    assert 'gsc_latency_seconds_bucket{le="0.5"} 2' in body
    assert 'gsc_latency_seconds_bucket{le="1"} 2' in body
    assert 'gsc_latency_seconds_bucket{le="+Inf"} 3' in body
    assert "gsc_latency_seconds_sum 2.35" in body
    assert "gsc_latency_seconds_count 3" in body


def test_histogram_with_labels(reg):
    h = reg.histogram("gsc_h", "h", buckets=(1.0,))
    h.observe(0.5, labels={"route": "/a"})
    h.observe(0.5, labels={"route": "/a"})
    h.observe(1.5, labels={"route": "/b"})
    body = M.render_metrics(reg)
    # /a: both observations <= 1.0 → count 2
    assert 'gsc_h_bucket{le="1",route="/a"} 2' in body
    assert 'gsc_h_count{route="/a"} 2' in body
    # /b: both observations fall in +Inf bucket only
    assert 'gsc_h_bucket{le="+Inf",route="/b"} 1' in body
    assert 'gsc_h_count{route="/b"} 1' in body


# ── Sanitisation ───────────────────────────────────────────────────────


def test_invalid_metric_and_label_chars_are_sanitised(reg):
    """Invalid characters in metric/label names become ``_``."""
    c = reg.counter("gsc/reqs.total", "with slashes and dot")
    c.inc(1, labels={"meth od": "GET", "x-foo": "1"})
    body = M.render_metrics(reg)
    # "gsc/reqs.total" -> "gsc_reqs_total"
    assert "# HELP gsc_reqs_total" in body
    # Label key "meth od" -> "meth_od"; "x-foo" -> "x_foo"
    assert '{meth_od="GET",x_foo="1"} 1' in body


def test_label_value_escaping(reg):
    """Backslash, quote, and newline in label values are escaped."""
    c = reg.counter("gsc_escape", "escape test")
    c.inc(1, labels={"k": 'a"b\\c\nd'})
    body = M.render_metrics(reg)
    # The escaped form must appear in the rendered output.
    assert 'k="a\\"b\\\\c\\nd"' in body


# ── Thread safety ─────────────────────────────────────────────────────


def test_counter_is_thread_safe(reg):
    """8 threads x 1000 increments -> exactly 8000."""
    c = reg.counter("gsc_thread", "thread-safe counter")
    n_threads = 8
    per_thread = 1000
    barrier = threading.Barrier(n_threads)

    def hammer() -> None:
        barrier.wait()
        for _ in range(per_thread):
            c.inc(1)

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert c.value() == float(n_threads * per_thread)
    assert "gsc_thread 8000" in M.render_metrics(reg)


def test_histogram_observe_is_thread_safe(reg):
    """Concurrent ``observe`` calls must yield the right sum and count."""
    h = reg.histogram("gsc_h_thr", "h", buckets=(1.0, 10.0))
    n_threads = 4
    per_thread = 500
    barrier = threading.Barrier(n_threads)

    def hammer() -> None:
        barrier.wait()
        for _ in range(per_thread):
            h.observe(0.5)

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = n_threads * per_thread
    body = M.render_metrics(reg)
    assert f"gsc_h_thr_count {total}" in body
    # 0.5 falls in bucket 1.0 and +Inf
    assert f'gsc_h_thr_bucket{{le="1"}} {total}' in body
    assert f'gsc_h_thr_bucket{{le="+Inf"}} {total}' in body
    # sum = total * 0.5; integer-valued floats render without a trailing ".0".
    assert f"gsc_h_thr_sum {int(total * 0.5)}" in body


# ── Render output format ──────────────────────────────────────────────


def test_render_metrics_contains_help_type_and_values(reg):
    c = reg.counter("gsc_x", "x help")
    c.inc(7)
    body = M.render_metrics(reg)
    assert "# HELP gsc_x x help" in body
    assert "# TYPE gsc_x counter" in body
    assert "gsc_x 7" in body
    # Prometheus requires a trailing newline.
    assert body.endswith("\n")


def test_render_empty_registry_is_just_newline(reg):
    """An empty registry must render as a single trailing newline."""
    body = M.render_metrics(reg)
    assert body == "\n"


# ── Middleware ────────────────────────────────────────────────────────


def _make_http_scope(method: str = "GET", path: str = "/") -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
        "query_string": b"",
    }


def test_middleware_increments_counter_on_http_scope(reg):
    """Each http request must bump the requests_total counter."""
    mw = M.MetricsMiddleware(app=_make_app(200), registry=reg)
    scopes = [
        _make_http_scope("GET", "/health"),
        _make_http_scope("GET", "/health"),
        _make_http_scope("POST", "/api/v2/scan"),
    ]
    _drive_middleware(mw, scopes)

    body = M.render_metrics(reg)
    # Two GETs to /health
    assert 'gsc_http_requests_total{method="GET",path="/health"} 2' in body
    # One POST to /api/v2/scan
    assert 'gsc_http_requests_total{method="POST",path="/api/v2/scan"} 1' in body
    # 200 responses -> no error count
    assert 'gsc_http_errors_total{method="GET",path="/health"} 0' not in body
    assert 'gsc_http_errors_total{method="POST",path="/api/v2/scan"} 0' not in body


def test_middleware_records_5xx_into_errors_total(reg):
    """5xx responses must increment the errors counter."""
    mw = M.MetricsMiddleware(app=_make_app(500), registry=reg)
    scopes = [
        _make_http_scope("GET", "/boom"),
        _make_http_scope("GET", "/boom"),
    ]
    _drive_middleware(mw, scopes)

    body = M.render_metrics(reg)
    assert 'gsc_http_requests_total{method="GET",path="/boom"} 2' in body
    assert 'gsc_http_errors_total{method="GET",path="/boom"} 2' in body


def test_middleware_does_not_count_4xx_as_error(reg):
    """4xx is a client error, not a server error — must NOT bump errors_total."""
    mw = M.MetricsMiddleware(app=_make_app(404), registry=reg)
    _drive_middleware(mw, [_make_http_scope("GET", "/nope")])

    body = M.render_metrics(reg)
    assert 'gsc_http_requests_total{method="GET",path="/nope"} 1' in body
    # 404 is a client error, not a server error: the errors counter stays
    # at its zero value (registered by the middleware, never incremented).
    assert "gsc_http_errors_total 0" in body
    assert 'gsc_http_errors_total{method="GET",path="/nope"}' not in body


def test_middleware_observes_latency(reg):
    """Latency must always be observed, regardless of status code."""
    mw = M.MetricsMiddleware(app=_make_app(200), registry=reg)
    _drive_middleware(mw, [_make_http_scope("GET", "/slow")])

    body = M.render_metrics(reg)
    # _count must be 1; +Inf bucket must also be 1.
    assert 'gsc_http_request_duration_seconds_count{method="GET",path="/slow"} 1' in body
    assert 'gsc_http_request_duration_seconds_bucket{le="+Inf",method="GET",path="/slow"} 1' in body


def test_middleware_passes_through_non_http_scope(reg):
    """Lifespan / websocket scopes must NOT touch any counter or histogram."""
    seen: List[str] = []

    async def fake_app(scope, receive, send):
        seen.append(scope["type"])

    mw = M.MetricsMiddleware(app=fake_app, registry=reg)

    async def run_one(scope_type: str) -> None:
        async def receive():
            return {"type": "lifespan.startup"}

        async def send(_message):
            pass

        await mw({"type": scope_type}, receive, send)

    asyncio.run(run_one("lifespan"))
    asyncio.run(run_one("websocket"))

    # Inner app was called for both non-http scopes.
    assert seen == ["lifespan", "websocket"]
    # Metrics are registered on middleware __init__, but non-http scopes
    # must not increment them: counters stay at zero.
    body = M.render_metrics(reg)
    assert "gsc_http_requests_total 0" in body
    assert "gsc_http_errors_total 0" in body
    # The histogram was declared but never observed -> no sample lines.
    assert "gsc_http_request_duration_seconds_count" not in body
    assert "gsc_http_request_duration_seconds_bucket" not in body
