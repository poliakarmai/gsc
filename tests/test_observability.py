#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""tests/test_observability.py — Prometheus text format on /metrics (DD-09)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gsc_cloud import observability as obs


@pytest.fixture(autouse=True)
def _reset_state():
    """Each test starts from zero counters (gauges untouched — they're live state)."""
    obs.reset_metrics()
    yield
    obs.reset_metrics()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(obs.router)
    return TestClient(app)


# ── Prometheus text format ───────────────────────────────

def test_metrics_endpoint_returns_prometheus_text(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    # Prometheus exposition Content-Type
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    # Every counter / gauge must have HELP + TYPE preamble.
    assert "# HELP gsc_scans_total" in body
    assert "# TYPE gsc_scans_total counter" in body
    assert "# HELP gsc_requests_total" in body
    assert "# TYPE gsc_requests_total counter" in body
    assert "# HELP gsc_findings_total" in body
    assert "# TYPE gsc_findings_total counter" in body
    # Body must end with newline (Prometheus spec).
    assert body.endswith("\n")


def test_metrics_includes_gauge_blocks(client):
    """Legacy gauges (scan_queue_depth, worker_last_heartbeat, …) remain exposed."""
    r = client.get("/metrics")
    body = r.text
    for name in (
        "scan_queue_depth",
        "worker_last_heartbeat",
        "webhook_signature_failures_total",
        "healthchecks_failed_total",
    ):
        assert f"# HELP {name}" in body, f"missing HELP for gauge {name}"
        assert f"# TYPE {name} gauge" in body, f"missing TYPE for gauge {name}"


# ── Counter increments ───────────────────────────────────

def test_increment_scan_increases_counter(client):
    assert "gsc_scans_total 0" in client.get("/metrics").text
    obs.increment_scan()
    obs.increment_scan()
    obs.increment_scan()
    body = client.get("/metrics").text
    assert "gsc_scans_total 3" in body


def test_increment_request_increases_counter(client):
    obs.increment_request()
    obs.increment_request()
    body = client.get("/metrics").text
    assert "gsc_requests_total 2" in body


def test_increment_finding_per_severity(client):
    obs.increment_finding("critical")
    obs.increment_finding("critical")
    obs.increment_finding("high")
    obs.increment_finding("medium")
    obs.increment_finding("low")
    obs.increment_finding("info")
    body = client.get("/metrics").text
    # Each severity appears exactly once as a labelled sample line.
    assert 'gsc_findings_total{severity="critical"} 2' in body
    assert 'gsc_findings_total{severity="high"} 1' in body
    assert 'gsc_findings_total{severity="medium"} 1' in body
    assert 'gsc_findings_total{severity="low"} 1' in body
    assert 'gsc_findings_total{severity="info"} 1' in body


def test_increment_finding_normalises_severity_case(client):
    """Uppercase / mixed-case severities should map to the lowercase bucket."""
    obs.increment_finding("CRITICAL")
    obs.increment_finding("Critical")
    obs.increment_finding("  high  ")
    body = client.get("/metrics").text
    assert 'gsc_findings_total{severity="critical"} 2' in body
    assert 'gsc_findings_total{severity="high"} 1' in body


def test_increment_finding_unknown_severity_is_bucketed(client):
    """Unknown severities land in an 'unknown' bucket, never silently dropped."""
    obs.increment_finding("banana")
    body = client.get("/metrics").text
    assert 'gsc_findings_total{severity="unknown"} 1' in body


# ── Thread-safety smoke test ────────────────────────────

def test_increment_scan_is_thread_safe():
    """Slam the counter from many threads; final value must equal total attempts."""
    import threading
    n_threads = 8
    per_thread = 250
    barrier = threading.Barrier(n_threads)

    def hammer():
        barrier.wait()
        for _ in range(per_thread):
            obs.increment_scan()

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert obs._counters["gsc_scans_total"] == float(n_threads * per_thread)


# ── Backward compatibility ──────────────────────────────

def test_metrics_json_backward_compat(client):
    """/metrics/json returns the legacy JSON snapshot (gauge dict + counters)."""
    obs.increment_scan()
    obs.increment_finding("high")
    r = client.get("/metrics/json")
    assert r.status_code == 200
    data = r.json()
    # Legacy gauges still present.
    assert "scan_queue_depth" in data
    assert "worker_last_heartbeat" in data
    # New counters exposed at top level.
    assert data["gsc_scans_total"] == 1
    assert data["gsc_requests_total"] == 0
    # Severity buckets nested under one key (not as a list of samples).
    assert data["gsc_findings_by_severity"]["high"] == 1
    assert data["gsc_findings_by_severity"]["critical"] == 0


# ── Health endpoints must keep working ──────────────────

def test_health_liveness_still_works(client):
    """DD-09 must not regress /health or /health/ready."""
    r = client.get("/api/v2/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_health_ready_still_works(monkeypatch, client):
    """/health/ready runs pg_ping + redis_ping; mock both to True."""
    monkeypatch.setattr(obs, "_pg_ping", lambda: True)
    monkeypatch.setattr(obs, "_redis_ping", lambda: True)
    r = client.get("/api/v2/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["checks"] == {"pg_ping": True, "redis_ping": True}


def test_health_ready_returns_503_when_dependency_down(monkeypatch, client):
    monkeypatch.setattr(obs, "_pg_ping", lambda: False)
    monkeypatch.setattr(obs, "_redis_ping", lambda: True)
    r = client.get("/api/v2/health/ready")
    assert r.status_code == 503
    assert r.json()["ok"] is False
