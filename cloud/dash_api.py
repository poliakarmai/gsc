"""BFF-эндпоинты для дашборда. Каждый запрос:
сессия → user → membership → tenant-scoped данные."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from cloud.session import parse
from cloud.store import control_plane

router = APIRouter(prefix="/api/v2/dash")


def _ctx(request: Request) -> tuple[int, int]:
    """Возвращает (user_id, tenant_id) или 401/403."""
    cookie = request.cookies.get("gsc_session", "")
    payload = parse(cookie)
    if not payload:
        raise HTTPException(401, "unauthenticated")
    tenant_id = payload.get("tid")
    if not tenant_id:
        raise HTTPException(400, "tenant not selected")
    db = control_plane()
    row = db.fetchone("""
        SELECT role FROM memberships
        WHERE user_id = ? AND tenant_id = ?
    """, (payload["uid"], tenant_id))
    if not row:
        raise HTTPException(403, "not a member of this tenant")
    return payload["uid"], tenant_id


@router.get("/repos")
def list_repos(request: Request):
    _, tid = _ctx(request)
    db = control_plane(tid)
    return {"repos": db.query(
        "SELECT id, name, gh_repo_id FROM repos "
        "WHERE tenant_id = ? ORDER BY name", (tid,))}


@router.get("/findings")
def list_findings(request: Request, repo_id: int | None = None,
                  severity: str | None = None, limit: int = 100):
    _, tid = _ctx(request)
    db = control_plane(tid)
    sql = ("SELECT finding_key, rule_id, severity, confidence, file, "
           "line, snippet, poc, metadata, scan_id "
           "FROM findings WHERE tenant_id = ?")
    params: list = [tid]
    if repo_id:
        sql += " AND scan_id IN (SELECT id FROM scans WHERE repo_id = ?)"
        params.append(repo_id)
    if severity:
        sql += " AND severity = ?"
        params.append(severity.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(limit, 500))
    return {"findings": db.query(sql, tuple(params))}


@router.get("/chains")
def list_chains(request: Request):
    _, tid = _ctx(request)
    db = control_plane(tid)
    return {"chains": db.query(
        "SELECT chain_key, finding_keys, composed_severity, confidence, "
        "narrative, status FROM chains WHERE tenant_id = ? "
        "ORDER BY id DESC LIMIT 100", (tid,))}


@router.get("/mutations")
def list_mutations(request: Request):
    _, tid = _ctx(request)
    db = control_plane(tid)
    return {"alerts": db.query(
        "SELECT finding_key, parent_key, kind, similarity, detected_at "
        "FROM mutation_alerts WHERE tenant_id = ? "
        "ORDER BY detected_at DESC LIMIT 100", (tid,))}


@router.get("/usage")
def usage_summary(request: Request):
    _, tid = _ctx(request)
    db = control_plane(tid)
    tenant = db.fetchone(
        "SELECT plan, seat_count, scan_limit_month FROM tenants WHERE id = ?",
        (tid,))
    month = db.fetchone("""
        SELECT scans, llm_calls FROM usage
        WHERE tenant_id = ? AND period = date_trunc('month', now())::date
    """, (tid,))
    return {
        "plan": tenant["plan"],
        "seats": tenant["seat_count"],
        "scan_limit": tenant["scan_limit_month"],
        "scans_this_month": month["scans"] if month else 0,
        "llm_calls_this_month": month["llm_calls"] if month else 0,
    }


# ── Helpers ─────────────────────────────────────────────

def _plan_of(tid: int) -> str:
    db = control_plane()
    row = db.fetchone("SELECT plan FROM tenants WHERE id = ?", (tid,))
    return row["plan"] if row else "free"


# ── Audit log (Business+) ───────────────────────────────

import json as _json
from cloud import audit


@router.get("/audit")
def audit_log(request: Request, limit: int = 200,
              action: str | None = None):
    _, tid = _ctx(request)
    if _plan_of(tid) not in ("business", "enterprise"):
        raise HTTPException(402, "audit log requires Business plan")
    db = control_plane(tid)
    sql = ("SELECT id, actor, action, resource_type, resource_id, "
           "detail, created_at FROM audit_events WHERE tenant_id = ?")
    params: list = [tid]
    if action:
        sql += " AND action = ?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(limit, 1000))
    rows = db.query(sql, tuple(params))
    return {"events": [_redact_event(r) for r in rows]}


@router.get("/audit/export")
def audit_export(request: Request):
    _, tid = _ctx(request)
    if _plan_of(tid) not in ("business", "enterprise"):
        raise HTTPException(402, "audit log requires Business plan")
    db = control_plane(tid)
    rows = db.query("SELECT * FROM audit_events WHERE tenant_id = ? "
                    "ORDER BY id", (tid,))
    events = [_redact_event(r) for r in rows]
    return {"events": events,
            "chain": audit.verify_chain(db, tid)}


def _redact_event(row: dict) -> dict:
    """Redaction поверх detail — секреты не покидают контур."""
    out = dict(row)
    detail = out.get("detail")
    if isinstance(detail, str):
        detail = _json.loads(detail)
    # Strip anything looking like a token/key from detail
    if isinstance(detail, dict):
        out["detail"] = {
            k: v for k, v in detail.items()
            if not any(secret_marker in k.lower()
                       for secret_marker in ("key", "secret", "token",
                                              "password", "credential"))
        }
    else:
        out["detail"] = detail
    return out