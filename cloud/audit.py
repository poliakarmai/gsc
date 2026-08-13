# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Append-only audit log с hash chain.

event_hash = sha256(prev_hash | canonical(tenant, actor, action,
resource, detail, created_at)) — подделка/удаление середины цепи
обнаруживается верификацией.
"""
from __future__ import annotations

import hashlib
import json


def _canonical(tenant_id, actor, action, rtype, rid, detail,
               created_at) -> str:
    return json.dumps([tenant_id, actor, action, rtype, rid,
                       detail, created_at], sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))


def last_hash(db, tenant_id: int) -> str:
    row = db.fetchone(
        "SELECT event_hash FROM audit_events WHERE tenant_id = ? "
        "ORDER BY id DESC LIMIT 1", (tenant_id,))
    return row["event_hash"] if row else "0" * 64


def record(db, tenant_id: int, actor: str, action: str,
           resource_type: str = None, resource_id: str = None,
           detail: dict = None) -> None:
    prev = last_hash(db, tenant_id)
    created = db.fetchone("SELECT now() AS t")["t"].isoformat()
    event_hash = hashlib.sha256(
        (prev + _canonical(tenant_id, actor, action, resource_type,
                           resource_id, detail, created)).encode()
    ).hexdigest()
    db.execute("""
        INSERT INTO audit_events
            (tenant_id, actor, action, resource_type, resource_id,
             detail, prev_hash, event_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::timestamptz)
    """, (tenant_id, actor, action, resource_type, resource_id,
          json.dumps(detail or {}, ensure_ascii=False), prev,
          event_hash, created))


def verify_chain(db, tenant_id: int) -> dict:
    """Полный проход цепи: подделка любой записи ломает хвост."""
    rows = db.query("SELECT * FROM audit_events WHERE tenant_id = ? "
                    "ORDER BY id", (tenant_id,))
    prev = "0" * 64
    for row in rows:
        detail = row["detail"]
        if isinstance(detail, str):
            detail = json.loads(detail)
        expected = hashlib.sha256(
            (prev + _canonical(
                row["tenant_id"], row["actor"], row["action"],
                row["resource_type"], row["resource_id"], detail,
                row["created_at"].isoformat())).encode()
        ).hexdigest()
        if row["prev_hash"] != prev or row["event_hash"] != expected:
            return {"ok": False, "broken_at": row["id"]}
        prev = row["event_hash"]
    return {"ok": True, "events": len(rows)}