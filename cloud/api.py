# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""GSC Cloud API (S1). Пространство /api/v2 — внутренний /api/v1 не трогаем."""
from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from cloud import store
from cloud.apideps import tenant_ctx
from cloud.scan_queue import ScanQueue

app = FastAPI(title="GSC Cloud", version="0.27")
queue = ScanQueue()

VALID_PROFILES = {"developer-review", "pr-gate", "audit", "candidate-review"}


class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=300)
    profile: str = "pr-gate"
    with_poc: bool = False
    with_chains: bool = False


class VerdictRequest(BaseModel):
    finding_key: str = Field(pattern=r"^[a-f0-9]{12}$")
    verdict: str = Field(pattern=r"^(tp|fp|fixed)$")
    reason: str = Field(default="", max_length=500)


@app.post("/api/v2/scan", status_code=202)
def create_scan(req: ScanRequest, tenant_id: int = Depends(tenant_ctx)):
    if req.profile not in VALID_PROFILES:
        raise HTTPException(400, "unknown profile")
    db = store.control_plane(tenant_id)
    if not store.check_quota(db, tenant_id):
        raise HTTPException(402, "monthly scan quota exceeded")
    repo_id = store.get_or_create_repo(db, tenant_id, req.target)
    scan_id = store.create_scan(db, tenant_id, repo_id, req.profile)
    queue.enqueue({
        "scan_id": scan_id, "tenant_id": tenant_id,
        "target": req.target, "profile": req.profile,
        "with_poc": req.with_poc, "with_chains": req.with_chains,
    })
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/v2/scans/{scan_id}")
def scan_status(scan_id: int, tenant_id: int = Depends(tenant_ctx)):
    db = store.control_plane(tenant_id)
    row = store.get_scan(db, scan_id)        # запрос с tenant_id
    if not row:
        raise HTTPException(404, "scan not found")
    out = dict(row)
    if row["status"] == "done":
        out["findings"] = store.list_findings(db, scan_id, limit=200)
    return out


@app.post("/api/v2/verdicts")
def submit_verdict(req: VerdictRequest, tenant_id: int = Depends(tenant_ctx)):
    db = store.control_plane(tenant_id)
    if not store.finding_exists(db, tenant_id, req.finding_key):
        raise HTTPException(404, "finding not found for this tenant")
    db.execute("""
        INSERT INTO verdicts (tenant_id, finding_key, verdict, reason, source)
        VALUES (?, ?, ?, ?, 'api')
    """, (tenant_id, req.finding_key, req.verdict, req.reason))
    db.commit()
    return {"ok": True}