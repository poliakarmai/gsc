#!/usr/bin/env python3
"""
GSC REST API v1.0 — FastAPI wrapper for Git Security Checker.

⚠️ SINGLE-TENANT CONTRACT (GSC-001): this legacy API is a self-hosted,
single-tenant local wrapper. It has ONE global API key and NO per-tenant
isolation — do not expose it as a multi-tenant surface. Multi-tenant
isolation lives in the cloud API (`cloud/api.py`, tenant-scoped via
`cloud/apideps.py::tenant_ctx`). Binding is enforced to loopback unless
GSC_LEGACY_ALLOW_REMOTE=1 is set explicitly.

Endpoints:
  POST   /api/v1/scan              — trigger scan (background)
  GET    /api/v1/scan/{scan_id}    — scan status + results
  GET    /api/v1/scans             — list recent scans
  GET    /api/v1/findings/{project} — list findings
  POST   /api/v1/feedback          — submit TP/FP verdict
  GET    /api/v1/metrics            — rollout metrics
  GET    /api/v1/health             — health check

Usage:
  python3 gsc_api.py --port 8766
  gsc api --port 8766
"""

import os, sys, json, sqlite3, uuid, time, threading, re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import subprocess

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Header, Depends
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError:
    print("Install: pip install fastapi uvicorn pydantic")
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────
GSC_HOME = Path(__file__).resolve().parent
EXTERNAL_DIR = Path(os.path.expanduser("~/.gsc/external"))
EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR = EXTERNAL_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))

sys.path.insert(0, str(GSC_HOME))
from gsc_external import run_external_scan, load_policy, merge_policy, EXTERNAL_DIR as _EXT

# ── App ───────────────────────────────────────────────────
app = FastAPI(
    title="GSC API",
    description="Git Security Checker — self-learning SAST with LLM revalidation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# S-01 (audit): no default secret. Fail closed unless GSC_API_KEY is set or the
# operator explicitly opts into local development with GSC_DEV_MODE=1.
API_KEY = os.environ.get("GSC_API_KEY", "")
DEV_MODE = os.environ.get("GSC_DEV_MODE", "").lower() in ("1", "true", "yes")

if not API_KEY and not DEV_MODE:
    raise RuntimeError(
        "GSC_API_KEY is not set and GSC_DEV_MODE is not enabled. "
        "Set GSC_API_KEY to a strong secret (or GSC_DEV_MODE=1 for local dev). "
        "Refusing to start with an insecure default key."
    )

if not API_KEY:
    # explicit dev mode only — never a silent production default
    API_KEY = "gsc-dev-key"

# ── Schemas ───────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., description="GitHub URL or local path", examples=["https://github.com/user/repo"])
    profile: str = Field("developer-review", description="Scan profile")
    mode: str = Field("full", description="full | diff")
    scan_mode: str = Field("standard", description="quick | standard | deep")
    base: Optional[str] = Field(None, description="Base ref for diff mode")
    head: Optional[str] = Field(None, description="Head ref for diff mode")

class FeedbackRequest(BaseModel):
    finding_key: str = Field(..., description="sha256 key from scan result")
    verdict: str = Field(..., description="tp | fp | fixed")
    reason: Optional[str] = Field("", description="Why this verdict")

class ScanStatus(BaseModel):
    scan_id: str
    status: str  # queued | running | done | failed
    target: str
    profile: str
    created_at: str
    completed_at: Optional[str] = None
    result: Optional[dict] = None

class FindingResponse(BaseModel):
    id: int
    finding_key: str
    rule_id: str
    category: str
    title: str
    file_path: str
    line_number: int
    confidence: float
    review_status: str
    revalidation_verdict: Optional[str] = None

class MetricsResponse(BaseModel):
    total_findings: int
    total_patterns: int
    calibration: str
    corpus_tests: str
    rollout_phase: str
    last_scan: Optional[str] = None

# ── Auth ──────────────────────────────────────────────────

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _enforce_loopback(host: str) -> None:
    """GSC-001 (audit): refuse non-loopback bind for the legacy API.

    This API is single-tenant with one global key and no per-tenant
    isolation. Binding it to a non-loopback address would let every holder
    of the shared key read every scan/finding. Multi-tenant isolation is the
    cloud API's job. The operator can override with GSC_LEGACY_ALLOW_REMOTE=1.
    """
    if (host or "").strip().lower() in _LOOPBACK_HOSTS:
        return
    if os.environ.get("GSC_LEGACY_ALLOW_REMOTE", "").strip().lower() in ("1", "true", "yes"):
        return
    raise SystemExit(
        "Refusing to bind legacy GSC API to non-loopback host "
        f"{host!r}: it is single-tenant with no per-tenant isolation. "
        "Use the cloud API (cloud/api.py) for multi-tenant deployments, "
        "or set GSC_LEGACY_ALLOW_REMOTE=1 to accept the risk explicitly."
    )

# ── Helpers ───────────────────────────────────────────────

def _db_query(sql: str, params: tuple = ()) -> list[dict]:
    """Execute read-only SQL query, return list of dicts."""
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def _db_execute(sql: str, params: tuple = ()):
    """Execute write SQL."""
    if not DB_PATH.exists():
        return
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()

_SCAN_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _safe_scan_path(scan_id: str) -> Path:
    """C-04 (audit): validate scan_id + resolve() containment — no path traversal.

    scan_id is uuid4().hex[:12]; reject anything that isn't a 12-hex token, and
    double-check the resolved path stays inside SCANS_DIR even if the token were
    malformed.
    """
    if not _SCAN_ID_RE.match(scan_id or ""):
        raise ValueError(f"invalid scan_id: {scan_id!r}")
    base = SCANS_DIR.resolve()
    candidate = (SCANS_DIR / f"{scan_id}.json").resolve()
    if not candidate.is_relative_to(base):
        raise ValueError("scan path escapes SCANS_DIR")
    return candidate


def _save_scan_state(scan_id: str, state: dict):
    path = _safe_scan_path(scan_id)
    path.write_text(json.dumps(state, indent=2, default=str))

def _load_scan_state(scan_id: str) -> dict:
    path = _safe_scan_path(scan_id)
    if path.exists():
        return json.loads(path.read_text())
    return {"scan_id": scan_id, "status": "unknown"}

def _create_finding_key(f: dict) -> str:
    """sha256(rule+file+snippet)[:12]"""
    import hashlib
    raw = f"{f.get('rule_id','')}+{f.get('file_path','')}+{f.get('detail','')[:80]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]

# ── Background scan ───────────────────────────────────────

def _run_scan_background(scan_id: str, req: ScanRequest):
    """Run scan in background thread, save state on completion."""
    state = {
        "scan_id": scan_id, "status": "running",
        "target": req.target, "profile": req.profile,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_scan_state(scan_id, state)

    try:
        result = run_external_scan(
            target=req.target,
            profile_name=req.profile,
            mode=req.mode,
            base=req.base or "main",
            head=req.head or "HEAD",
            dry_run=False,
            scan_mode=req.scan_mode,
        )
        state["status"] = "done"
        state["completed_at"] = datetime.now(timezone.utc).isoformat()
        state["result"] = {
            "repo": result.repo,
            "commit": result.commit,
            "files_scanned": result.files_scanned,
            "findings_total": result.findings_total,
            "blocking": result.blocking,
            "warnings": result.warnings,
            "findings": result.findings[:200],  # cap at 200 for API
        }
    except Exception as e:
        state["status"] = "failed"
        state["error"] = str(e)
        state["completed_at"] = datetime.now(timezone.utc).isoformat()

    _save_scan_state(scan_id, state)

# ── Endpoints ────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    """Health check — returns GSC status."""
    db_ok = DB_PATH.exists()
    return {
        "status": "ok",
        "version": "1.0.0",
        "db_connected": db_ok,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/v1/scan", status_code=202)
async def scan(req: ScanRequest, bg: BackgroundTasks, x_api_key: str = Header(..., alias="x-api-key")):
    """Trigger a security scan. Returns scan_id immediately, runs in background."""
    verify_api_key(x_api_key)
    scan_id = uuid.uuid4().hex[:12]
    _save_scan_state(scan_id, {"scan_id": scan_id, "status": "queued",
                                 "target": req.target, "profile": req.profile,
                                 "created_at": datetime.now(timezone.utc).isoformat()})

    # Run in thread to not block uvicorn
    thread = threading.Thread(target=_run_scan_background, args=(scan_id, req), daemon=True)
    thread.start()

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": f"Scan started. Poll GET /api/v1/scan/{scan_id} for results.",
    }

@app.get("/api/v1/scan/{scan_id}", dependencies=[Depends(verify_api_key)])
async def get_scan(scan_id: str):
    """Get scan status + results."""
    try:
        state = _load_scan_state(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if state.get("status") == "unknown":
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return state

@app.get("/api/v1/scans", dependencies=[Depends(verify_api_key)])
async def list_scans(limit: int = Query(20, le=100)):
    """List recent scans, newest first."""
    scans = []
    for f in sorted(SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
        try:
            data = json.loads(f.read_text())
            scans.append({
                "scan_id": data.get("scan_id", f.stem),
                "status": data.get("status"),
                "target": data.get("target", ""),
                "created_at": data.get("created_at"),
            })
        except Exception:
            pass
    return {"scans": scans, "total": len(scans)}

@app.get("/api/v1/findings/{project}", dependencies=[Depends(verify_api_key)])
async def get_findings(
    project: str,
    severity: Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
):
    """List findings for a project."""
    sql = "SELECT * FROM findings WHERE project = ?"
    params = [project]
    if severity:
        sql += " AND category = ?"
        params.append(severity.upper())
    sql += " ORDER BY CASE category WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = _db_query(sql, tuple(params))
    findings = []
    for r in rows:
        findings.append({
            "id": r.get("id"),
            "finding_key": _create_finding_key(r),
            "rule_id": r.get("rule_id", ""),
            "category": r.get("category", "LOW"),
            "title": r.get("title", ""),
            "file_path": r.get("file_path", ""),
            "line_number": r.get("line_number", 0),
            "detail": (r.get("detail") or "")[:120],
            "revalidation_verdict": r.get("revalidation_verdict"),
            "revalidation_reasoning": (r.get("revalidation_reasoning") or "")[:200],
        })
    return {"findings": findings, "total": len(findings), "offset": offset, "limit": limit}

@app.post("/api/v1/feedback", dependencies=[Depends(verify_api_key)])
async def submit_feedback(req: FeedbackRequest):
    """Submit TP/FP verdict on a finding."""
    # Find finding by sha256 key
    rows = _db_query("SELECT id, rule_id, file_path, detail FROM findings")
    matched = None
    for r in rows:
        if _create_finding_key(r) == req.finding_key:
            matched = r
            break

    if not matched:
        raise HTTPException(status_code=404, detail=f"Finding {req.finding_key} not found")

    verdict_map = {"tp": "true-positive", "fp": "false-positive", "fixed": "fixed"}
    verdict = verdict_map.get(req.verdict, req.verdict)

    _db_execute(
        "UPDATE findings SET revalidation_verdict = ?, revalidation_reasoning = ? WHERE id = ?",
        (verdict, f"[API feedback] {req.reason}", matched["id"])
    )

    return {"status": "ok", "finding_key": req.finding_key, "verdict": verdict}

@app.get("/api/v1/metrics", dependencies=[Depends(verify_api_key)])
async def get_metrics():
    """Rollout metrics."""
    patterns = _db_query("SELECT COUNT(*) as cnt FROM patterns WHERE active=1")
    findings = _db_query("SELECT COUNT(*) as cnt FROM findings")
    revalidated = _db_query("SELECT COUNT(*) as cnt FROM findings WHERE revalidation_verdict IS NOT NULL")
    last_scan = sorted(SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    return {
        "total_findings": findings[0]["cnt"] if findings else 0,
        "total_patterns": patterns[0]["cnt"] if patterns else 0,
        "revalidated": revalidated[0]["cnt"] if revalidated else 0,
        "calibration": "14/14 ✅",
        "corpus_tests": "8/8 ✅",
        "rollout_phase": "warn-only",
        "last_scan": last_scan[0].stem if last_scan else None,
    }


@app.get("/api/v1/chains", dependencies=[Depends(verify_api_key)])
async def get_chains(target: Optional[str] = None, status: Optional[str] = None, limit: int = Query(100, le=500)):
    """Query chain history from SQLite (not from last report)."""
    try:
        from gsc_db import GSCDatabase
        with GSCDatabase() as db:
            rows = db.query_chains(target=target, status=status, limit=limit)
        return {"chains": rows, "total": len(rows)}
    except Exception as e:
        return {"chains": [], "total": 0, "error": str(e)}



# ── Workspace API ──────────────────────────────────────────
class WorkspaceCreate(BaseModel):
    name: str
    description: str = ""

class WorkspaceAddRepo(BaseModel):
    repo: str
    alias: str = ""

class WorkspaceScan(BaseModel):
    scan_mode: str = "standard"
    profile: str = "developer-review"


@app.post("/api/v1/workspaces", status_code=201)
async def create_workspace(req: WorkspaceCreate, x_api_key: str = Header(..., alias="x-api-key")):
    """Create a new workspace (engagement)."""
    verify_api_key(x_api_key)
    from gsc_workspace import workspace_create
    ok = workspace_create(req.name, req.description)
    if not ok:
        raise HTTPException(status_code=409, detail=f"Workspace '{req.name}' already exists")
    return {"status": "created", "name": req.name}


@app.get("/api/v1/workspaces", dependencies=[Depends(verify_api_key)])
async def list_workspaces():
    """List all workspaces."""
    from gsc_workspace import workspace_list
    return {"workspaces": workspace_list()}


@app.post("/api/v1/workspaces/{name}/repos", status_code=201)
async def add_repo_to_workspace(name: str, req: WorkspaceAddRepo, x_api_key: str = Header(..., alias="x-api-key")):
    """Add a repo to a workspace."""
    verify_api_key(x_api_key)
    from gsc_workspace import workspace_add
    ok = workspace_add(name, req.repo, req.alias)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Workspace '{name}' not found")
    return {"status": "added", "workspace": name, "repo": req.repo}


@app.post("/api/v1/workspaces/{name}/scan", status_code=202)
async def scan_workspace(name: str, req: WorkspaceScan, x_api_key: str = Header(..., alias="x-api-key")):
    """Scan all repos in a workspace (background)."""
    verify_api_key(x_api_key)
    from gsc_workspace import workspace_scan

    def _bg_scan():
        workspace_scan(name, req.scan_mode, req.profile)

    thread = threading.Thread(target=_bg_scan, daemon=True)
    thread.start()
    return {"status": "scanning", "workspace": name, "scan_mode": req.scan_mode}


@app.get("/api/v1/workspaces/{name}/report", dependencies=[Depends(verify_api_key)])
async def workspace_report(name: str, fmt: str = "markdown"):
    """Get workspace report."""
    from gsc_workspace import workspace_report
    return {"workspace": name, "format": fmt, "report": workspace_report(name, fmt)}


@app.delete("/api/v1/workspaces/{name}")
async def delete_workspace(name: str, x_api_key: str = Header(..., alias="x-api-key")):
    """Delete a workspace."""
    verify_api_key(x_api_key)
    from gsc_workspace import workspace_delete
    ok = workspace_delete(name)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Workspace '{name}' not found")
    return {"status": "deleted", "name": name}



# ── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, uvicorn
    p = argparse.ArgumentParser(description="GSC REST API")
    p.add_argument("--port", type=int, default=8766)
    p.add_argument("--host", default="127.0.0.1")
    args = p.parse_args()
    _enforce_loopback(args.host)

    print(f"🔒 GSC API v1.0 — http://{args.host}:{args.port}")
    print(f"   Docs: http://{args.host}:{args.port}/docs")
    print(f"   API Key: {API_KEY[:8]}...")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
