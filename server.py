#!/usr/bin/env python3
"""GSC Cloud — Public API Server (FastAPI + Uvicorn).

SaaS S1-S5 endpoints: scan, findings, auth, billing, dash.
Deploy: docker compose up -d
"""

import os, sys, time, uuid
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Paths ──
GSC_DIR = Path(os.environ.get("GSC_DIR", "/app"))
sys.path.insert(0, str(GSC_DIR))
sys.path.insert(0, str(GSC_DIR / "cloud"))

# ── DB ──
from gsc_db import get_db, ensure_schema

db = get_db(Path(os.environ.get("GSC_DB", "/data/gsc_cloud.db")))
ensure_schema(db)

# ── FastAPI ──
app = FastAPI(
    title="GSC Cloud API",
    version="1.3.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str = Field(..., description="GitHub repo URL or local path")
    profile: str = Field(default="audit", description="Scan profile: audit|ci|deep")
    api_key: str = Field(..., description="Tenant API key (gsk_...)")

class ScanResponse(BaseModel):
    scan_id: str
    findings_count: int
    severity_breakdown: dict
    duration_sec: float

# ═══════════════════════════════════════════════════════════
# Auth
# ═══════════════════════════════════════════════════════════

def verify(api_key: str) -> int | None:
    """Verify tenant API key, return tenant_id or None."""
    from cloud.tenancy import verify_api_key
    return verify_api_key(db, api_key)

# ═══════════════════════════════════════════════════════════
# Health
# ═══════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """K8s liveness/readiness probe."""
    return {
        "status": "ok",
        "version": "1.3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_size_mb": round(Path(os.environ.get("GSC_DB", "/data/gsc_cloud.db")).stat().st_size / 1e6, 2),
    }

# ═══════════════════════════════════════════════════════════
# Scan
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    """Run GSC scan on a repository."""
    tid = verify(req.api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    from cloud.workers import enqueue_scan
    scan_id = enqueue_scan(db, tid, req.target, req.profile)
    return {"scan_id": scan_id, "findings_count": 0, "severity_breakdown": {}, "duration_sec": 0}

@app.get("/api/v2/scans/{scan_id}")
async def scan_status(scan_id: str, api_key: str = Query(...)):
    """Get scan status/results."""
    tid = verify(api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    from cloud.scanjobs import get_scan
    job = get_scan(db, scan_id, tid)
    if not job:
        raise HTTPException(404, "Scan not found")
    return job

# ═══════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/findings")
async def findings(
    api_key: str = Query(...),
    severity: str = Query(None),
    rule_id: str = Query(None),
    limit: int = Query(50, le=500),
):
    """List findings for tenant."""
    tid = verify(api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    from cloud.api_v2 import handle_findings_v2
    result, code = handle_findings_v2(db, api_key, severity=severity, rule_id=rule_id, limit=limit)
    return result

# ═══════════════════════════════════════════════════════════
# Billing
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/billing/plans")
async def billing_plans():
    """Available plans."""
    return {
        "plans": [
            {"id": "free", "name": "Free", "price": 0, "scans_per_month": 10, "repos": 1},
            {"id": "pro", "name": "Pro", "price": 49, "scans_per_month": 100, "repos": 10},
            {"id": "team", "name": "Team", "price": 199, "scans_per_month": 500, "repos": 50},
            {"id": "enterprise", "name": "Enterprise", "price": 999, "scans_per_month": 99999, "repos": 999},
        ]
    }

# ═══════════════════════════════════════════════════════════
# GitHub Auth
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/auth/github")
async def github_auth_url():
    """Get GitHub OAuth URL. State is tracked server-side."""
    from cloud.github_auth import get_auth_url
    return {"url": get_auth_url()}

@app.get("/api/v2/auth/github/callback")
async def github_callback(code: str, state: str):
    """GitHub OAuth callback — creates tenant + returns API key."""
    from cloud.github_auth import handle_callback
    result = handle_callback(db, code, state)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

# ═══════════════════════════════════════════════════════════
# Dashboard (FastAPI router from dash_api)
# ═══════════════════════════════════════════════════════════

from cloud.dash_api import router as dash_router
app.include_router(dash_router)

# ═══════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
