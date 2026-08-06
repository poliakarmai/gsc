"""Agent API: активация, ingest, политики (S5)."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from fastapi import APIRouter, HTTPException, Header

from cloud import audit
from cloud.store import control_plane

router = APIRouter(prefix="/api/v2/agent")


def _store_session(token: str, tenant_id: int, agent_id: int,
                   ttl: int = 86400):
    """Хранит session token в Redis с TTL."""
    try:
        from cloud.dedup import DeliveryDedup
        dd = DeliveryDedup()
        dd.once_raw(f"gsc:agent:session:{token}", ttl,
                     value=json.dumps({"tenant_id": tenant_id,
                                       "agent_id": agent_id}))
    except Exception:
        pass  # Redis недоступен — in-memory fallback не реализован


def _resolve_session(authorization: str) -> tuple[int, int]:
    """Извлекает (tenant_id, agent_id) из session token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing authorization")
    token = authorization.split(" ", 1)[1]
    try:
        from cloud.dedup import DeliveryDedup
        dd = DeliveryDedup()
        val = dd.r.get(f"gsc:agent:session:{token}")
        if not val:
            raise HTTPException(401, "invalid session")
        data = json.loads(val)
        return data["tenant_id"], data["agent_id"]
    except Exception:
        raise HTTPException(401, "invalid session")


@router.post("/activate")
def activate_agent(body: dict):
    key = body.get("activation_key", "")
    agent_uuid = body.get("agent_uuid", "")
    if not key or not agent_uuid:
        raise HTTPException(400, "activation_key and agent_uuid required")

    db = control_plane()
    prefix = key[:12]
    row = db.fetchone("""
        SELECT k.tenant_id, k.key_hash, k.agent_id, a.agent_uuid
        FROM agent_keys k
        LEFT JOIN agents a ON a.id = k.agent_id
        WHERE k.prefix = ? AND k.revoked_at IS NULL
    """, (prefix,))
    if not row:
        raise HTTPException(401, "invalid activation key")

    expected_hash = hashlib.sha256(key.encode()).hexdigest()
    if not hmac.compare_digest(row["key_hash"], expected_hash):
        raise HTTPException(401, "invalid activation key")

    tenant_id = row["tenant_id"]

    if row["agent_id"] is None:
        db.execute("""
            INSERT INTO agents (tenant_id, agent_uuid, version)
            VALUES (?, ?, ?)
        """, (tenant_id, agent_uuid, body.get("version", "0.31")))
        agent_id = db.fetchone(
            "SELECT currval(pg_get_serial_sequence('agents','id')) "
            "AS id")["id"]
        db.execute("""
            UPDATE agent_keys SET agent_id = ? WHERE prefix = ?
        """, (agent_id, prefix))
    else:
        agent_id = row["agent_id"]
        if row["agent_uuid"] != agent_uuid:
            raise HTTPException(403, "agent_uuid mismatch")

    session_token = secrets.token_urlsafe(48)
    _store_session(session_token, tenant_id, agent_id, ttl=86400)
    db.execute("""
        UPDATE agents SET last_seen_at = now(), version = ?
        WHERE id = ?
    """, (body.get("version", "0.31"), agent_id))
    db.commit()

    return {"agent_id": str(agent_id), "session_token": session_token}


@router.get("/policy")
def get_policy(authorization: str = Header(...)):
    """Политика для агента: profile, детекторы, пороги."""
    tenant_id, agent_id = _resolve_session(authorization)
    db = control_plane(tenant_id)
    tenant = db.fetchone(
        "SELECT plan FROM tenants WHERE id = ?", (tenant_id,))
    plan = tenant["plan"] if tenant else "free"

    return {
        "profile": "audit",
        "with_poc": plan in ("business", "enterprise"),
        "with_chains": plan in ("business", "enterprise"),
        "detectors_enabled": None,
        "blocking_thresholds": {
            "critical": 0.90,
            "high": 0.85,
        },
    }