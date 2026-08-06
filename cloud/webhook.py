"""GitHub webhook receiver (S2).

Безопасность:
  - подпись проверяется по СЫРОМУ телу (не по распарсенному JSON);
  - защита от replay через X-GitHub-Delivery + Redis SETNX;
  - постоянный тенант резолвится только после проверки подписи.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

from fastapi import APIRouter, HTTPException, Request

from cloud import onboarding, pr_commands, scanjobs
from cloud.dedup import DeliveryDedup

router = APIRouter()
dedup = DeliveryDedup()


def verify_signature(raw_body: bytes, sig_header: str, secret: str) -> bool:
    if not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


@router.post("/api/v2/webhook/github")
async def github_webhook(request: Request):
    secret = os.environ.get("GSC_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(500, "webhook secret not configured")
    raw = await request.body()
    if not verify_signature(raw,
                            request.headers.get("X-Hub-Signature-256", ""),
                            secret):
        raise HTTPException(401, "invalid signature")

    delivery = request.headers.get("X-GitHub-Delivery", "")
    if delivery and not dedup.once(f"gsc:delivery:{delivery}", ttl=86400):
        return {"ok": True, "deduplicated": True}

    event = request.headers.get("X-GitHub-Event", "")
    payload = json.loads(raw)
    if event == "ping":
        return {"ok": True, "zen": payload.get("zen")}
    if event == "pull_request":
        return scanjobs.handle_pull_request(payload)
    if event == "issue_comment":
        return pr_commands.handle_issue_comment(payload)
    return {"ok": True, "ignored_event": event}