# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Observability: health, readiness, metrics (Cloud 1.0).

DEPRECATED: this module serves the legacy ``gsc_cloud.api`` (Cloud 1.0).
Production ``gsc_cloud.server`` (v1.4.0) now exposes ``/metrics`` via
``gsc_cloud.metrics`` and structured logging via ``gsc_cloud.logging``.

Prometheus text exposition format on /metrics (default).
JSON snapshot kept on /metrics/json for backward compatibility.
"""
from __future__ import annotations

import threading
from typing import Dict, List

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()

# In-memory gauges (reset on restart). Kept as a dict for backward compat
# with code that may still mutate these keys directly (workers, webhook layer).
_gauges: Dict[str, float] = {
    "scan_queue_depth": 0,
    "worker_last_heartbeat": 0,
    "webhook_signature_failures_total": 0,
    "healthchecks_failed_total": 0,
}

# Backward-compat alias: legacy callers (tests/test_cloud_s4.py) imported the
# in-memory map as ``_metrics`` before the Prometheus split.
_metrics = _gauges

# Counters (Prometheus convention: _total suffix). Thread-safe via _lock.
# severity buckets are normalised to lowercase; unknown values fall under "unknown".
_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_counters: Dict[str, float] = {
    "gsc_scans_total": 0.0,
    "gsc_requests_total": 0.0,
}
# Findings are stored as a flat name+labels-keyed map (Prometheus-style) so we
# can read/write atomically under _lock without a nested dict race.
_flat: Dict[str, float] = {f"gsc_findings_total{{severity=\"{sev}\"}}": 0.0
                           for sev in _VALID_SEVERITIES}
_lock = threading.Lock()


# ── counter helpers (public API) ─────────────────────────

def increment_scan() -> None:
    """Bump gsc_scans_total by 1. Thread-safe."""
    with _lock:
        _counters["gsc_scans_total"] += 1.0


def increment_finding(severity: str) -> None:
    """Bump gsc_findings_total{severity=...} by 1. Thread-safe.

    Unknown severities are bucketed under "unknown" (visible only in flat
    Prometheus view) to avoid silently dropping the count.
    """
    raw = (severity or "").strip().lower()
    sev = raw if raw in _VALID_SEVERITIES else "unknown"
    key = f"gsc_findings_total{{severity=\"{sev}\"}}"
    with _lock:
        _flat[key] = _flat.get(key, 0.0) + 1.0


def increment_request() -> None:
    """Bump gsc_requests_total by 1. Thread-safe."""
    with _lock:
        _counters["gsc_requests_total"] += 1.0


def reset_metrics() -> None:
    """Zero all counters. Gauges untouched (live process state).
    Intended for tests; not exposed via HTTP."""
    with _lock:
        _counters["gsc_scans_total"] = 0.0
        _counters["gsc_requests_total"] = 0.0
        _flat.clear()
        for sev in _VALID_SEVERITIES:
            _flat[f"gsc_findings_total{{severity=\"{sev}\"}}"] = 0.0


# ── Prometheus exposition renderer ──────────────────────

# Each metric: (name, type, help, value_source).
# value_source is a callable returning (labels_dict, value).
def _gauge_lines():
    for name, value in _gauges.items():
        yield name, "gauge", _HELP.get(name, name), {}, float(value)


def _active_severity_buckets() -> List[str]:
    """Severity labels that currently have a counter entry (canonical + any
    non-canonical severities that hit increment_finding)."""
    out: List[str] = list(_VALID_SEVERITIES)
    with _lock:
        keys = list(_flat.keys())
    for key in keys:
        # key shape: gsc_findings_total{severity="<sev>"}
        try:
            sev = key.split('severity="', 1)[1].rstrip('"}')
        except IndexError:
            continue
        if sev not in out:
            out.append(sev)
    return out


def _counter_lines():
    yield ("gsc_scans_total", "counter", _HELP["gsc_scans_total"],
           {}, _counters["gsc_scans_total"])
    yield ("gsc_requests_total", "counter", _HELP["gsc_requests_total"],
           {}, _counters["gsc_requests_total"])
    for sev in _active_severity_buckets():
        key = f"gsc_findings_total{{severity=\"{sev}\"}}"
        yield ("gsc_findings_total", "counter", _HELP["gsc_findings_total"],
               {"severity": sev}, _flat.get(key, 0.0))


_HELP = {
    "scan_queue_depth": "Current depth of the scan queue (gauge).",
    "worker_last_heartbeat": "Unix timestamp of the last worker heartbeat (gauge).",
    "webhook_signature_failures_total": "Total webhook signature verification failures (gauge).",
    "healthchecks_failed_total": "Total failed healthcheck probes (gauge).",
    "gsc_scans_total": "Total number of scans performed (counter).",
    "gsc_requests_total": "Total HTTP requests served by the API (counter).",
    "gsc_findings_total": "Total findings produced, partitioned by severity (counter).",
}


def _render_prometheus() -> str:
    """Build a Prometheus text exposition format payload (v0.0.4).

    Format: https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
    Each metric block: optional # HELP, then # TYPE, then one or more sample lines.
    """
    blocks: Dict[str, list] = {}
    for name, kind, help_text, labels, value in _gauge_lines():
        blocks.setdefault(name, []).append((kind, help_text, labels, value))
    for name, kind, help_text, labels, value in _counter_lines():
        blocks.setdefault(name, []).append((kind, help_text, labels, value))

    lines: list = []
    for name, entries in blocks.items():
        # All entries for a metric share kind/help; first entry is authoritative.
        kind, help_text, _, _ = entries[0]
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for _kind, _help, labels, value in entries:
            if labels:
                label_str = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
                lines.append(f"{name}{{{label_str}}} {_format_value(value)}")
            else:
                lines.append(f"{name} {_format_value(value)}")
    # Prometheus requires trailing newline.
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    """Escape label value per Prometheus exposition spec."""
    return (str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n"))


def _format_value(value: float) -> str:
    """Format float per Prometheus conventions: inf/-inf/NaN spelled out."""
    # Avoid repr()'s "1.0" for ints — Prometheus accepts both, but plain ints read cleaner.
    if value != value:  # NaN
        return "NaN"
    if value == float("inf"):
        return "+Inf"
    if value == float("-inf"):
        return "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


# ── HTTP routes ──────────────────────────────────────────

@router.get("/api/v2/health")
def liveness():
    return {"ok": True}


@router.get("/api/v2/health/ready")
def readiness():
    checks = {
        "pg_ping": _pg_ping(),
        "redis_ping": _redis_ping(),
    }
    ok = all(checks.values())
    return JSONResponse({"ok": ok, "checks": checks},
                        status_code=200 if ok else 503)


@router.get("/metrics")
def metrics():
    """Prometheus text exposition format (version 0.0.4)."""
    return PlainTextResponse(
        _render_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/metrics/json")
def metrics_json():
    """Backward-compatible JSON snapshot (legacy /metrics body)."""
    snapshot: Dict[str, object] = dict(_gauges)
    snapshot["gsc_scans_total"] = _counters["gsc_scans_total"]
    snapshot["gsc_requests_total"] = _counters["gsc_requests_total"]
    findings: Dict[str, float] = {}
    with _lock:
        for sev in _VALID_SEVERITIES:
            key = f"gsc_findings_total{{severity=\"{sev}\"}}"
            findings[sev] = _flat.get(key, 0.0)
    snapshot["gsc_findings_by_severity"] = findings
    return snapshot


# ── helpers ──────────────────────────────────────────────

def _pg_ping() -> bool:
    try:
        from gsc_cloud.store import control_plane
        db = control_plane()
        db.fetchone("SELECT 1 AS ping")
        return True
    except Exception:
        return False


def _redis_ping() -> bool:
    try:
        from gsc_cloud.dedup import DeliveryDedup
        dd = DeliveryDedup()
        dd.r.ping()
        return True
    except Exception:
        return False
