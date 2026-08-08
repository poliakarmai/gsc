#!/usr/bin/env python3
"""GSC Cloud — Public API Server.

SaaS MVP: scan, findings, billing, GitHub auth.
Deploy: docker build -t gsc-api . && docker run -d -p 8081:8000 gsc-api
"""

import os, sys, json, uuid, hashlib, secrets, subprocess, tempfile, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from jose import jwt, JWTError

# ── GSC paths ──
GSC_DIR = Path(os.environ.get("GSC_DIR", "/app"))
sys.path.insert(0, str(GSC_DIR))

import sqlite3
from gsc_db import DB_PATH as GSC_DB_PATH  # just for reference

DB_PATH = Path(os.environ.get("GSC_DB", "/data/gsc_cloud.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
conn.row_factory = sqlite3.Row
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA busy_timeout=5000")

# ── GitHub OAuth config ──
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "http://localhost:8081/api/v2/auth/github/callback")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
SESSION_TTL_HOURS = 24

# ═══════════════════════════════════════════════════════════
# App
# ═══════════════════════════════════════════════════════════

app = FastAPI(title="GSC Cloud API", version="1.3.0", docs_url="/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ═══════════════════════════════════════════════════════════
# Schema init
# ═══════════════════════════════════════════════════════════

def ensure_cloud_schema():
    """Ensure api_keys and scan_jobs tables exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            github_user TEXT,
            plan TEXT DEFAULT 'free',
            scans_used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            profile TEXT DEFAULT 'audit',
            status TEXT DEFAULT 'queued',
            findings_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            finding_key TEXT PRIMARY KEY,
            rule_id TEXT,
            title TEXT,
            severity TEXT DEFAULT 'UNKNOWN',
            confidence REAL DEFAULT 0.85,
            file TEXT,
            line INTEGER,
            snippet TEXT,
            tenant_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            tenant_id INTEGER NOT NULL,
            github_user TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()

ensure_cloud_schema()

# ═══════════════════════════════════════════════════════════
# Auth
# ═══════════════════════════════════════════════════════════

def create_tenant(name: str, plan: str = "free") -> tuple[str, int]:
    """Create tenant + API key. Returns (api_key, tenant_id)."""
    cur = conn.execute("INSERT INTO tenants (name, plan) VALUES (?, ?)", (name, plan))
    tid = cur.lastrowid
    raw_key = "gsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    conn.execute(
        "INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)",
        (tid, key_hash, raw_key[:8])
    )
    conn.commit()
    return raw_key, tid

def verify_api_key(raw_key: str) -> Optional[int]:
    """Return tenant_id or None."""
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (h,)
    ).fetchone()
    return row["tenant_id"] if row else None

def create_session(tenant_id: int, github_user: str) -> str:
    """Create JWT session token. Returns token string."""
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
    token = jwt.encode(
        {"tenant_id": tenant_id, "github_user": github_user, "exp": expires},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    conn.execute(
        "INSERT INTO sessions (token, tenant_id, github_user, expires_at) VALUES (?,?,?,?)",
        (token, tenant_id, github_user, expires.isoformat())
    )
    conn.commit()
    return token

def verify_session(token: str) -> Optional[int]:
    """Return tenant_id from session token or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Also verify in DB (revocation support)
        row = conn.execute(
            "SELECT tenant_id FROM sessions WHERE token=? AND expires_at > datetime('now')",
            (token,)
        ).fetchone()
        return row["tenant_id"] if row else None
    except JWTError:
        return None

# ═══════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    profile: str = "audit"
    api_key: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    findings_count: int
    severity_breakdown: dict = {}

# ═══════════════════════════════════════════════════════════
# Health
# ═══════════════════════════════════════════════════════════

@app.get("/health")
def health():
    db_path = Path(os.environ.get("GSC_DB", "/data/gsc_cloud.db"))
    size = db_path.stat().st_size if db_path.exists() else 0
    return {
        "status": "ok",
        "version": "1.3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_size_kb": round(size / 1024, 1),
        "detectors": 36,
    }

# ═══════════════════════════════════════════════════════════
# Scan
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    tid = verify_api_key(req.api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    scan_id = str(uuid.uuid4())[:12]

    # Check plan limits
    tenant = conn.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
    limits = {"free": 10, "pro": 100, "team": 500, "enterprise": 99999}
    max_scans = limits.get(tenant["plan"], 10)
    if tenant["scans_used"] >= max_scans:
        raise HTTPException(429, f"Monthly scan limit ({max_scans}) reached. Upgrade to Pro.")

    conn.execute(
        "INSERT INTO scan_jobs (id, tenant_id, target, profile, status) VALUES (?,?,?,?,'running')",
        (scan_id, tid, req.target, req.profile)
    )
    conn.commit()

    # Run GSC scan in temp dir
    findings = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            # Clone shallow
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", "--filter=blob:none", req.target, tmp],
                capture_output=True, timeout=60
            )
            if clone.returncode != 0:
                raise RuntimeError(f"Clone failed: {clone.stderr.decode()[:100]}")

            # Scan
            result = subprocess.run(
                ["python3", str(GSC_DIR / "gsc.py"), "scan", tmp, "--ci", "--json"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                # Strip any leading non-JSON lines (warnings, etc.)
                stdout_clean = result.stdout.strip()
                # Find the first '[' — JSON array starts there
                json_start = stdout_clean.find('[')
                if json_start > 0:
                    stdout_clean = stdout_clean[json_start:]
                findings = json.loads(stdout_clean) if stdout_clean else []
                if not isinstance(findings, list):
                    findings = []

        # Store findings
        breakdown = {}
        for f in findings[:500]:  # cap at 500
            sev = f.get("severity", "UNKNOWN")
            breakdown[sev] = breakdown.get(sev, 0) + 1
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (f.get("finding_key", ""), f.get("rule_id", ""), f.get("title", ""),
                 sev, f.get("confidence", 0.85), f.get("file", ""),
                 f.get("line", 0), f.get("snippet", ""), tid)
            )

        conn.execute(
            "UPDATE scan_jobs SET status='done', findings_count=?, completed_at=datetime('now') WHERE id=?",
            (len(findings), scan_id)
        )
        conn.execute("UPDATE tenants SET scans_used = scans_used + 1 WHERE id=?", (tid,))
        conn.commit()

        return ScanResponse(scan_id=scan_id, status="done", findings_count=len(findings), severity_breakdown=breakdown)

    except Exception as e:
        conn.execute("UPDATE scan_jobs SET status='failed' WHERE id=?", (scan_id,))
        conn.commit()
        raise HTTPException(500, str(e))

# ═══════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/findings")
def findings(
    api_key: str = Query(...),
    severity: str = Query(None),
    rule_id: str = Query(None),
    limit: int = Query(50, le=500),
):
    tid = verify_api_key(api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    sql = "SELECT * FROM findings WHERE tenant_id = ?"
    params: list = [tid]

    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if rule_id:
        sql += " AND rule_id = ?"
        params.append(rule_id)

    sql += " ORDER BY severity DESC, created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    return {"findings": [dict(r) for r in rows], "count": len(rows)}

# ═══════════════════════════════════════════════════════════
# Scans list
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/scans")
def scans(api_key: str = Query(...)):
    tid = verify_api_key(api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    rows = conn.execute(
        "SELECT * FROM scan_jobs WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50", (tid,)
    ).fetchall()
    return {"scans": [dict(r) for r in rows]}

# ═══════════════════════════════════════════════════════════
# Billing
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/billing/plans")
def billing_plans():
    return {"plans": [
        {"id": "free", "name": "Free", "price": 0, "scans_per_month": 10, "repos": 1},
        {"id": "pro", "name": "Pro", "price": 49, "scans_per_month": 100, "repos": 10},
        {"id": "team", "name": "Team", "price": 199, "scans_per_month": 500, "repos": 50},
        {"id": "enterprise", "name": "Enterprise", "price": 999, "scans_per_month": 99999, "repos": 999},
    ]}

# ═══════════════════════════════════════════════════════════
# Tenant onboarding
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/auth/signup")
def signup(github_user: str = Query(...), plan: str = Query("free")):
    """Quick signup with GitHub username. Returns API key."""
    api_key, tid = create_tenant(github_user, plan)
    return {"api_key": api_key, "tenant_id": tid, "plan": plan, "message": "Save this key — it won't be shown again."}

# ═══════════════════════════════════════════════════════════
# GitHub OAuth
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/auth/github")
def github_login(redirect: str = Query("/")):
    """Redirect user to GitHub OAuth."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(500, "GitHub OAuth not configured — set GITHUB_CLIENT_ID")
    state = secrets.token_urlsafe(16)
    # Store state temporarily for CSRF protection
    conn.execute(
        "INSERT OR REPLACE INTO sessions (token, tenant_id, github_user, expires_at) VALUES (?,0,?,datetime('now','+10 minutes'))",
        (f"state:{state}", f"redirect:{redirect}")
    )
    conn.commit()
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&state={state}"
        f"&scope=user:email"
    )
    return RedirectResponse(url)

@app.get("/api/v2/auth/github/callback")
async def github_callback(code: str = Query(...), state: str = Query("")):
    """Handle GitHub OAuth callback. Exchange code → access token → user info."""
    if not GITHUB_CLIENT_SECRET:
        raise HTTPException(500, "GitHub OAuth not configured — set GITHUB_CLIENT_SECRET")

    # Verify state
    state_row = conn.execute(
        "SELECT github_user FROM sessions WHERE token=? AND expires_at > datetime('now')",
        (f"state:{state}",)
    ).fetchone()
    redirect_url = "/"
    if state_row and state_row["github_user"] and state_row["github_user"].startswith("redirect:"):
        redirect_url = state_row["github_user"].split(":", 1)[1]

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_resp.json()

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(400, f"GitHub auth failed: {token_data.get('error_description', 'unknown error')}")

    # Get user info
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        )
        user_data = user_resp.json()

    github_user = user_data.get("login", "unknown")
    github_id = user_data.get("id", 0)

    # Find or create tenant
    existing = conn.execute(
        "SELECT id FROM tenants WHERE github_user=?", (github_user,)
    ).fetchone()
    if existing:
        tid = existing["id"]
    else:
        cur = conn.execute(
            "INSERT INTO tenants (name, github_user, plan) VALUES (?,?,'free')",
            (github_user, github_user)
        )
        tid = cur.lastrowid
        conn.commit()

    # Create session
    session_token = create_session(tid, github_user)

    # Redirect to frontend with token
    return RedirectResponse(f"{redirect_url}?token={session_token}&github_user={github_user}")

@app.get("/api/v2/auth/session")
def session_info(token: str = Query(...)):
    """Validate session token and return tenant info."""
    tid = verify_session(token)
    if tid is None:
        raise HTTPException(401, "Invalid or expired session")
    tenant = conn.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
    return {"tenant": dict(tenant), "valid": True}

# ═══════════════════════════════════════════════════════════
# Stats / dashboard
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/stats")
def stats(api_key: str = Query(...)):
    tid = verify_api_key(api_key)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    tenant = conn.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
    total_findings = conn.execute(
        "SELECT COUNT(*) as c FROM findings WHERE tenant_id=?", (tid,)
    ).fetchone()["c"]
    scans_done = conn.execute(
        "SELECT COUNT(*) as c FROM scan_jobs WHERE tenant_id=? AND status='done'", (tid,)
    ).fetchone()["c"]

    return {
        "tenant": dict(tenant),
        "total_findings": total_findings,
        "scans_completed": scans_done,
        "scans_remaining": {"free": 10, "pro": 100, "team": 500, "enterprise": 99999}[tenant["plan"]] - tenant["scans_used"],
    }

# ── Static files (catch-all for frontend) ──
STATIC_DIR = GSC_DIR

@app.get("/")
def index():
    """Serve landing page."""
    from fastapi.responses import FileResponse
    return FileResponse(str(STATIC_DIR / "index.html"))

# ═══════════════════════════════════════════════════════════
# Entrypoint
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"GSC Cloud API v1.3.0 starting on :{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
