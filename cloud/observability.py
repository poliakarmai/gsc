# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Observability: health, readiness, metrics (Cloud 1.0)."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

# In-memory gauges (reset on restart)
_metrics = {
    "scan_queue_depth": 0,
    "worker_last_heartbeat": 0,
    "webhook_signature_failures_total": 0,
    "healthchecks_failed_total": 0,
}


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
    return _metrics


# ── helpers ──────────────────────────────────────────────

def _pg_ping() -> bool:
    try:
        from cloud.store import control_plane
        db = control_plane()
        db.fetchone("SELECT 1 AS ping")
        return True
    except Exception:
        return False


def _redis_ping() -> bool:
    try:
        from cloud.dedup import DeliveryDedup
        dd = DeliveryDedup()
        dd.r.ping()
        return True
    except Exception:
        return False