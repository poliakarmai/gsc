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

# ── Dashboard ──
@app.get("/dashboard")
def dashboard():
    """Security dashboard with trend charts and PR feedback."""
    db = conn  # global sqlite3 connection (cloud DB)

    # Stats for charts
    stats = {
        "total_scans": 0, "scans_today": 0, "total_findings": 0,
        "by_severity": {}, "by_rule": {}, "pr_feedback": [],
        "prs_created": 0, "prs_accepted": 0, "last_scan": None,
    }

    try:
        # Scan stats (from audit DB if available, else cloud DB)
        src = _audit_conn or db
        stats["total_scans"] = src.execute("SELECT COUNT(*) FROM audit_runs").fetchone()[0]
        try:
            stats["scans_today"] = src.execute(
                "SELECT COUNT(*) FROM audit_runs WHERE date(started_at) = date('now')"
            ).fetchone()[0]
        except Exception:
            stats["scans_today"] = 0
        last = src.execute(
            "SELECT project, started_at, total_findings FROM audit_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if last:
            stats["last_scan"] = {"project": last["project"], "at": last["started_at"],
                                 "findings": last["total_findings"]}

        # PR stats
        try:
            stats["prs_created"] = db.execute("SELECT COUNT(*) FROM published_comments").fetchone()[0]
        except Exception:
            stats["prs_created"] = 0
        # Findings stats (from audit DB if available)
        src = _audit_conn or db
        stats["total_findings"] = src.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        try:
            # Audit DB uses 'category' not 'severity'
            rows = src.execute(
                "SELECT COALESCE(category, 'UNKNOWN') as sev, COUNT(*) as cnt "
                "FROM findings GROUP BY sev ORDER BY cnt DESC"
            ).fetchall()
            stats["by_severity"] = {r["sev"]: r["cnt"] for r in rows}
        except Exception:
            stats["by_severity"] = {}
        try:
            rows = src.execute(
                "SELECT COALESCE(category, 'unknown') as rule_id, COUNT(*) as cnt "
                "FROM findings GROUP BY rule_id ORDER BY cnt DESC LIMIT 8"
            ).fetchall()
            stats["by_rule"] = {r["rule_id"]: r["cnt"] for r in rows}
        except Exception:
            stats["by_rule"] = {}

        # PR feedback
        try:
            rows = db.execute("""
                SELECT repo, pr_number, pr_state, author_response, comment_count,
                       reactions_json, merged, checked_at
                FROM pr_feedback ORDER BY checked_at DESC LIMIT 10
            """).fetchall()
            stats["pr_feedback"] = [dict(r) for r in rows]
        except Exception:
            stats["pr_feedback"] = []

    except Exception:
        pass  # Generic fallback for scan/finding queries

    # Build HTML with Chart.js
    severity_json = json.dumps(stats["by_severity"])
    rule_json = json.dumps(stats["by_rule"])
    pr_json = json.dumps(stats["pr_feedback"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GSC Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }}
header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }}
h1 {{ font-size: 20px; color: #58a6ff; }}
.version {{ font-size: 12px; color: #8b949e; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px; padding: 24px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
.card h2 {{ font-size: 16px; margin-bottom: 16px; color: #8b949e; }}
.big-number {{ font-size: 48px; font-weight: bold; color: #58a6ff; }}
.stats-row {{ display: flex; gap: 20px; flex-wrap: wrap; }}
.stat {{ flex: 1; min-width: 100px; text-align: center; }}
.stat .value {{ font-size: 28px; font-weight: bold; }}
.stat .label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
.crit {{ color: #f85149; }} .high {{ color: #f0883e; }} .med {{ color: #d29922; }} .low {{ color: #58a6ff; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ color: #8b949e; font-weight: 600; }}
.merged {{ color: #3fb950; }} .open {{ color: #58a6ff; }} .closed {{ color: #8b949e; }}
canvas {{ max-height: 250px; }}
.last-scan {{ font-size: 13px; color: #8b949e; margin-top: 12px; }}
</style>
</head>
<body>
<header><h1>🔒 GSC Security Dashboard</h1><span class="version">v1.4.0</span></header>
<div class="grid">
    <div class="card">
        <h2>📊 Overview</h2>
        <div class="stats-row">
            <div class="stat"><div class="value" id="scans">{stats['total_scans']}</div><div class="label">Total Scans</div></div>
            <div class="stat"><div class="value" id="scansToday">{stats['scans_today']}</div><div class="label">Today</div></div>
            <div class="stat"><div class="value" id="prs">{stats['prs_created']}</div><div class="label">PRs Created</div></div>
        </div>
        <div class="last-scan" id="lastScan">{f"Last: {stats['last_scan']['project']} ({stats['last_scan']['findings']} findings)" if stats.get('last_scan') else ""}</div>
    </div>
    <div class="card">
        <h2>🔍 Findings</h2>
        <div class="big-number" id="total">{stats['total_findings']:,}</div>
        <div class="stats-row" style="margin-top:12px">
            <div class="stat"><div class="value crit" id="crit">0</div><div class="label">Critical</div></div>
            <div class="stat"><div class="value high" id="hi">0</div><div class="label">High</div></div>
            <div class="stat"><div class="value med" id="med">0</div><div class="label">Medium</div></div>
            <div class="stat"><div class="value low" id="lo">0</div><div class="label">Low</div></div>
        </div>
    </div>
    <div class="card">
        <h2>🥧 Severity Distribution</h2>
        <canvas id="pieChart"></canvas>
    </div>
    <div class="card">
        <h2>🔝 Top Detectors</h2>
        <canvas id="barChart"></canvas>
    </div>
    <div class="card">
        <h2>🔄 PR Feedback</h2>
        <table id="prTable"><tr><td colspan="5" style="color:#8b949e">Loading...</td></tr></table>
    </div>
</div>
<script>
const sevData = {severity_json};
const ruleData = {rule_json};
const prData = {pr_json};

// Overview
const total = {stats['total_findings']};
document.getElementById('total').textContent = total || 0;
if (sevData) {{
    document.getElementById('crit').textContent = sevData.CRITICAL || 0;
    document.getElementById('hi').textContent = sevData.HIGH || 0;
    document.getElementById('med').textContent = sevData.MEDIUM || 0;
    document.getElementById('lo').textContent = sevData.LOW || 0;
}}

// Pie chart
if (sevData && Object.keys(sevData).length > 0) {{
    new Chart(document.getElementById('pieChart'), {{
        type: 'doughnut',
        data: {{
            labels: Object.keys(sevData),
            datasets: [{{
                data: Object.values(sevData),
                backgroundColor: ['#f85149', '#f0883e', '#d29922', '#58a6ff', '#8b949e']
            }}]
        }},
        options: {{ plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }} }}
    }});
}}

// Bar chart
if (ruleData && Object.keys(ruleData).length > 0) {{
    new Chart(document.getElementById('barChart'), {{
        type: 'bar',
        data: {{
            labels: Object.keys(ruleData),
            datasets: [{{
                label: 'Findings',
                data: Object.values(ruleData),
                backgroundColor: '#58a6ff'
            }}]
        }},
        options: {{
            indexAxis: 'y',
            plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
        }}
    }});
}}

// PR table
const prTable = document.getElementById('prTable');
if (prData && prData.length > 0) {{
    prTable.innerHTML = '<tr><th>Repo</th><th>PR</th><th>Status</th><th>Response</th><th>Comments</th></tr>' +
        prData.map(p => {{
            const stateClass = p.merged ? 'merged' : (p.pr_state || 'open');
            const icon = p.merged ? '🟣' : (p.pr_state === 'closed' ? '🔴' : '🟢');
            const responseIcon = p.author_response === 'accepted' ? '✅' : (p.author_response === 'dismissed' ? '❌' : '');
            return `<tr>
                <td>${{p.repo}}</td>
                <td><a href="https://github.com/${{p.repo}}/pull/${{p.pr_number}}" style="color:#58a6ff">#${{p.pr_number}}</a></td>
                <td class="${{stateClass}}">${{icon}} ${{p.merged ? 'merged' : p.pr_state}}</td>
                <td>${{responseIcon}} ${{p.author_response}}</td>
                <td>${{p.comment_count}}</td>
            </tr>`;
        }}).join('');
}} else {{
    prTable.innerHTML = '<tr><td colspan="5" style="color:#8b949e;text-align:center">No PRs tracked yet. Scan a repo and create a PR to see feedback here.</td></tr>';
}}
</script>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)

# ── Import audit DB at startup ──
AUDIT_DB = os.environ.get("GSC_AUDIT_DB", "")
_audit_conn = None
if AUDIT_DB and Path(AUDIT_DB).exists():
    _audit_conn = sqlite3.connect(
        f"file://{AUDIT_DB}?immutable=1", uri=True,
        check_same_thread=False)
    _audit_conn.row_factory = sqlite3.Row
    print(f"✅ Audit DB loaded: {_audit_conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]} findings", flush=True)

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
