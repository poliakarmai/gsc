"""GitHub Marketplace → план тенанта.

Marketplace использует биллинг GitHub (не Stripe); источник плана
фиксируется в tenants.plan_source. Идемпотентность + подпись,
как в Stripe- и GitHub-вебхуках.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

from fastapi import APIRouter, HTTPException, Request

from cloud import audit
from cloud.store import control_plane

router = APIRouter()

PLAN_MAP = {
    "gsc-free": ("free", 50, 0),
    "gsc-team": ("team", 500, 200),
    "gsc-business": ("business", 5000, 1000),
}


@router.post("/api/v2/webhook/marketplace")
async def marketplace_webhook(request: Request):
    secret = os.environ.get("GSC_MARKETPLACE_SECRET", "")
    if not secret:
        raise HTTPException(500, "marketplace secret not configured")
    raw = await request.body()
    sig = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(secret.encode(), raw,
                                    hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(401, "invalid signature")

    payload = json.loads(raw)
    action = payload.get("action")
    if action not in ("purchased", "changed", "cancelled",
                      "pending_change_cancelled"):
        return {"ok": True, "ignored": action}

    account = payload["marketplace_purchase"]["account"]["login"]
    plan_slug = payload["marketplace_purchase"]["plan"]["slug"]

    db = control_plane()
    install = db.fetchone("""
        SELECT tenant_id FROM github_installs WHERE org_login = ?
    """, (account,))
    if not install:
        return {"ok": True, "no_install_for_account": account}
    tid = install["tenant_id"]

    if action == "cancelled":
        plan, scans, llm = PLAN_MAP["gsc-free"]
    else:
        if plan_slug not in PLAN_MAP:
            return {"ok": True, "unknown_plan": plan_slug}
        plan, scans, llm = PLAN_MAP[plan_slug]

    db.execute("""
        UPDATE tenants SET plan = ?, plan_source = 'marketplace',
               scan_limit_month = ?, llm_budget_month = ?
        WHERE id = ?
    """, (plan, scans, llm, tid))
    audit.record(db, tid, "marketplace", "billing.plan_changed",
                 "tenant", str(tid),
                 {"plan": plan, "action": action})
    db.commit()
    return {"ok": True, "tenant_id": tid, "plan": plan}