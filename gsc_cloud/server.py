#!/usr/bin/env python3
"""GSC Cloud — Public API Server.

SaaS MVP: scan, findings, billing, GitHub auth.
Deploy: docker build -t gsc-api . && docker run -d -p 8081:8000 gsc-api
"""

import os, sys, json, uuid, hashlib, hmac, secrets, subprocess, tempfile, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Query, Body, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import jwt

# ── GSC paths ──
GSC_DIR = Path(os.environ.get("GSC_DIR", "/app"))
sys.path.insert(0, str(GSC_DIR))

import sqlite3
from gsc_db import DB_PATH as GSC_DB_PATH  # just for reference
from gsc_cloud.gsc_db_backend import SqliteBackend, PgBackend

# GSC-008: default to a writable user path so `import server` doesn't fail
# creating /data (which only exists in the container). Production sets
# GSC_DB=/data/gsc_cloud.db explicitly (see cloud/docker-compose.yml).
# GSC roadmap 5.2: GSC_DATA_DIR переопределяет data-корень (cloud/ под ним).
_DATA_DIR = os.environ.get("GSC_DATA_DIR")
_DEFAULT_DB_PATH = (
    str(Path(_DATA_DIR) / "cloud" / "gsc_cloud.db") if _DATA_DIR
    else str(Path(os.path.expanduser("~/.gsc")) / "gsc_cloud.db")
)
DB_PATH = Path(os.environ.get("GSC_DB", _DEFAULT_DB_PATH))
try:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
except OSError:
    pass  # GSC-008: non-fatal on import — DB init happens at runtime


def get_backend(tenant_id: Optional[int] = None):
    """Backend-фабрика (S1): SQLite по умолчанию, PostgreSQL при GSC_DATABASE_URL.

    SQLite = dev/локальный контур. PostgreSQL = multi-tenant production (RLS).
    PgBackend требует tenant_id — по умолчанию 0 (control-plane).
    """
    dsn = os.environ.get("GSC_DATABASE_URL")
    if dsn:
        return PgBackend(dsn, tenant_id if tenant_id is not None else 0)
    return SqliteBackend(str(DB_PATH))


# GSC roadmap 4.7: этот global backend используется ТОЛЬКО для startup/init
# (ensure_cloud_schema, миграции) и как fallback в helper'ах вне request context
# (db=None). Все request-пути получают свой backend через get_db() — per-request,
# tenant-scoped (PgBackend при GSC_DATABASE_URL). SQLite — не concurrent
# multi-writer store, поэтому global conn для request-путей убран.
conn = get_backend()

# ── GitHub OAuth config ──
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "http://localhost:8081/api/v2/auth/github/callback")


def _load_or_create_jwt_secret() -> str:
    """JWT_SECRET: env > (dev-only: persist-файл > generate).

    GSC roadmap 3.8: в production (GSC_DEV_MODE != 1) отсутствие JWT_SECRET env —
    fail-closed: процесс завершается с ошибкой, а не молча генерирует secret
    (иначе multi-replica/restart дают разные secrets и инвалидируют сессии).
    В dev-mode допустим persist-файл (~/.gsc/.jwt_secret) для удобства локальной
    разработки.
    """
    env_secret = os.environ.get("JWT_SECRET")
    if env_secret:
        return env_secret

    dev_mode = os.environ.get("GSC_DEV_MODE", "0").lower() in ("1", "true", "yes")
    if not dev_mode:
        sys.exit(
            "GSC: JWT_SECRET is required in production. "
            "Set JWT_SECRET env (or GSC_DEV_MODE=1 for local development)."
        )

    # DD-08: surface dev-mode auto-gen explicitly — ops must know the secret is
    # a local, auto-generated value (not a production JWT_SECRET).
    print(
        "[gsc] WARNING: GSC_DEV_MODE=1 — JWT secret is auto-generated/persisted "
        "locally (~/.gsc/.jwt_secret). Do NOT use in production.",
        file=sys.stderr,
    )

    # dev-mode: persist, чтобы сессии переживали restart локально
    secret_file = DB_PATH.parent / ".jwt_secret"
    try:
        if secret_file.exists():
            return secret_file.read_text().strip()
        secret = secrets.token_urlsafe(32)
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        # Атомарная запись (temp + rename), чтобы частичная запись при падении
        # процесса не оставила битый secret-файл.
        tmp = secret_file.with_suffix(".tmp")
        tmp.write_text(secret)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, secret_file)
        return secret
    except OSError:
        # read-only FS → ephemeral (сессии не переживут restart, но не падаем)
        return secrets.token_urlsafe(32)


_jwt_secret: str | None = None
JWT_ALGORITHM = "HS256"


def _get_jwt_secret() -> str:
    """Lazy JWT secret (GSC roadmap 5.1): не создаём файл и не exit при import.

    Реальный load происходит при первом запросе, которому нужен JWT
    (create_session / verify_session), а не в момент импорта модуля.
    """
    global _jwt_secret
    if _jwt_secret is None:
        _jwt_secret = _load_or_create_jwt_secret()
    return _jwt_secret
SESSION_TTL_HOURS = 24

# ═══════════════════════════════════════════════════════════
# App
# ═══════════════════════════════════════════════════════════

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app):
    """GSC roadmap 5.1: DDL/миграции при старте, не при import (uvicorn server:app)."""
    init_cloud_db()
    yield


app = FastAPI(title="GSC Cloud API", version="1.3.0", docs_url="/docs", lifespan=lifespan)

# CORS: explicit allowlist from env (audit S-04). No wildcard — a wildcard
# combined with a cookie/API-key auth model enables cross-origin abuse.
CORS_ORIGINS = [
    o.strip() for o in os.environ.get(
        "GSC_CORS_ORIGINS",
        "http://localhost:8081,http://localhost:3000"
    ).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

# ═══════════════════════════════════════════════════════════
# Schema init
# ═══════════════════════════════════════════════════════════

def ensure_cloud_schema():
    """Ensure api_keys and scan_jobs tables exist (SQLite dev).

    PostgreSQL prod использует cloud/schema_s3.sql (S1, трек 1.3 миграции).
    """
    if not isinstance(conn, SqliteBackend):
        return
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
            finding_key TEXT,
            rule_id TEXT,
            title TEXT,
            severity TEXT DEFAULT 'UNKNOWN',
            confidence REAL DEFAULT 0.85,
            file TEXT,
            line INTEGER,
            snippet TEXT,
            tenant_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (tenant_id, finding_key)
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


def _migrate_findings_composite_key():
    """C-02 (audit): findings.finding_key was a global PRIMARY KEY, so INSERT OR
    REPLACE could delete another tenant's row and reassign it to the new tenant.
    Rebuild the table with composite PRIMARY KEY (tenant_id, finding_key)."""
    if not isinstance(conn, SqliteBackend):
        return  # PostgreSQL использует schema_s3.sql, не sqlite_master
    try:
        row = conn.fetchone(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'"
        )
        if not row:
            return
        ddl = row["sql"] if isinstance(row, sqlite3.Row) else (row[0] if row else "")
        if "PRIMARY KEY (tenant_id, finding_key)" in ddl:
            return  # already migrated
        conn.executescript("""
            ALTER TABLE findings RENAME TO findings_old;
            CREATE TABLE findings (
                finding_key TEXT,
                rule_id TEXT,
                title TEXT,
                severity TEXT DEFAULT 'UNKNOWN',
                confidence REAL DEFAULT 0.85,
                file TEXT,
                line INTEGER,
                snippet TEXT,
                tenant_id INTEGER NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (tenant_id, finding_key)
            );
            INSERT OR REPLACE INTO findings
                (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id,created_at)
            SELECT finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id,created_at
            FROM findings_old;
            DROP TABLE findings_old;
        """)
        conn.commit()
    except Exception as e:
        print(f"[migrate findings] {e}", flush=True)


def init_cloud_db() -> None:
    """Startup-инициализация (GSC roadmap 5.1): DDL + миграции — НЕ при import.

    Вызывается из entrypoint (if __name__ == '__main__') и/или FastAPI lifespan,
    чтобы импорт модуля (тесты, worker, внешние импортеры) не имел побочных
    эффектов на файловую систему / схему БД.
    """
    ensure_cloud_schema()
    _migrate_findings_composite_key()

# ═══════════════════════════════════════════════════════════
# Auth
# ═══════════════════════════════════════════════════════════

def create_tenant(name: str, plan: str = "free", db=None) -> tuple[str, int]:
    """Create tenant + API key. Returns (api_key, tenant_id).

    GSC roadmap 4.7: db — request-scoped backend (get_db); fallback на bootstrap
    conn только для startup/init путей.
    """
    db = db or conn
    tid = db.insert_id(
        "INSERT INTO tenants (name, plan) VALUES (?, ?) RETURNING id",
        (name, plan)
    )
    raw_key = "gsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)",
        (tid, key_hash, raw_key[:8])
    )
    return raw_key, tid

def verify_api_key(raw_key: str, db=None) -> Optional[int]:
    """Return tenant_id or None (constant-time hash comparison, audit S-10)."""
    db = db or conn
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:8] if len(raw_key) >= 8 else raw_key
    rows = db.query(
        "SELECT tenant_id, key_hash FROM api_keys WHERE key_prefix=? AND revoked_at IS NULL",
        (prefix,)
    )
    for r in rows:
        if hmac.compare_digest(r["key_hash"], h):
            return r["tenant_id"]
    return None


def get_db():
    """Per-request backend (audit A-07).

    Each request gets its own backend (SQLite dev / PostgreSQL prod), isolated
    from the module-global ``conn``. SQLite default; GSC_DATABASE_URL switches
    to PostgreSQL (S1).
    """
    db = get_backend()
    try:
        yield db
    finally:
        db.close()


def get_tenant_from_key(
    authorization: str = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db=Depends(get_db),
) -> int:
    """Resolve tenant id from Authorization: Bearer <key> or X-API-Key header.

    GSC roadmap 3.9: query-param API key удалён — он попадает в access logs /
    browser history (audit S-10). Только header.
    """
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    elif x_api_key:
        raw = x_api_key.strip()
    if not raw:
        raise HTTPException(401, "Missing API key (use Authorization: Bearer <key> or X-API-Key header)")
    tid = verify_api_key(raw, db)
    if tid is None:
        raise HTTPException(401, "Invalid API key")
    return tid

def create_session(tenant_id: int, github_user: str, db=None) -> str:
    """Create JWT session token. Returns token string."""
    db = db or conn
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
    token = jwt.encode(
        {"tenant_id": tenant_id, "github_user": github_user, "exp": expires},
        _get_jwt_secret(), algorithm=JWT_ALGORITHM
    )
    db.execute(
        "INSERT INTO sessions (token, tenant_id, github_user, expires_at) VALUES (?,?,?,?)",
        (token, tenant_id, github_user, expires.isoformat())
    )
    return token

def verify_session(token: str, db=None) -> Optional[int]:
    """Return tenant_id from session token or None."""
    db = db or conn
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        # Also verify in DB (revocation support) — portable timestamp compare
        now = datetime.now(timezone.utc).isoformat()
        row = db.fetchone(
            "SELECT tenant_id FROM sessions WHERE token=? AND expires_at > ?",
            (token, now)
        )
        return row["tenant_id"] if row else None
    except jwt.PyJWTError:
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


def _normalize_finding(f: dict) -> dict:
    """Normalize a scanner finding (category/file_path/line_number/detail)
    to the cloud API schema (severity/file/line/snippet). Audit C-05.

    The core scanner emits category/file_path/line_number/detail; the cloud
    findings table expects severity/file/line/snippet. Without this, every
    row lands as UNKNOWN / empty path / line 0.
    """
    return {
        "finding_key": f.get("finding_key") or f.get("pattern_fingerprint") or "",
        "rule_id": f.get("rule_id") or f.get("pattern_title") or f.get("pattern_id") or "",
        "title": f.get("title", ""),
        "severity": f.get("severity") or f.get("category") or "UNKNOWN",
        "confidence": f.get("confidence") or f.get("confidence_score") or 0.85,
        "file": f.get("file") or f.get("file_path") or "",
        "line": f.get("line") or f.get("line_number") or 0,
        "snippet": f.get("snippet") or f.get("detail") or "",
    }


ALLOWED_GIT_HOSTS = {
    h.strip().lower() for h in os.environ.get(
        "GSC_ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org"
    ).split(",") if h.strip()
}


def _validate_target(target: str) -> None:
    """Reject non-HTTPS, non-allowlisted, or SSRF-prone git targets (audit S-09).

    Only https:// to a known public host is accepted; credentials-in-URL,
    file://, ssh://, git:// and private/link-local hosts are rejected up front
    so an arbitrary target can't be used as an SSRF/egress primitive.
    """
    parsed = urlparse(target)
    if parsed.scheme != "https":
        raise HTTPException(400, "Only https:// git targets are allowed")
    host = (parsed.hostname or "").lower()
    if not host or host not in ALLOWED_GIT_HOSTS:
        raise HTTPException(400, "Target host is not in the allowlist")
    if parsed.username or parsed.password:
        raise HTTPException(400, "Credentials in the target URL are not allowed")
    if not parsed.path or parsed.path == "/":
        raise HTTPException(400, "Repository path is required")

# ═══════════════════════════════════════════════════════════
# Health
# ═══════════════════════════════════════════════════════════

def _detector_count() -> int:
    """GSC-006: detector count comes from the registry (single source of truth),
    not a hardcoded number that drifts from README/CLI/server."""
    try:
        from gsc_meta import get_meta
        # GSC-011: detectors_total может быть None (registry import failed) —
        # не подставлять молчаливый fallback 41, честно отдаём 0/unknown.
        return int(get_meta().get("detectors_total") or 0)
    except Exception:
        return 0  # GSC-011: честный "unknown", а не hardcoded 41


@app.get("/health")
def health():
    db_path = Path(os.environ.get("GSC_DB", "/data/gsc_cloud.db"))
    size = db_path.stat().st_size if db_path.exists() else 0
    return {
        "status": "ok",
        "version": "1.3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_size_kb": round(size / 1024, 1),
        "detectors": _detector_count(),
    }


@app.get("/ready")
def ready(db=Depends(get_db)):
    """Readiness probe: проверяет реальную DB connectivity (не stat файла).

    GSC roadmap 4.9: Kubernetes/Docker readiness gate — если БД недоступна,
    под возвращает 503 и не получает трафик (в отличие от /health, который
    показывает liveness без проверки БД).
    """
    try:
        db.fetchone("SELECT 1")
        return {"status": "ready", "db": "ok"}
    except Exception as e:
        raise HTTPException(503, f"database not reachable: {e}")

# ═══════════════════════════════════════════════════════════
# Scan
# ═══════════════════════════════════════════════════════════

@app.post("/api/v2/scan", status_code=202)
async def scan(req: ScanRequest, background_tasks: BackgroundTasks, db=Depends(get_db)):
    tid = verify_api_key(req.api_key, db)
    if tid is None:
        raise HTTPException(401, "Invalid API key")

    # SSRF guard: reject arbitrary/non-allowlisted git targets (audit S-09)
    _validate_target(req.target)

    scan_id = str(uuid.uuid4())[:12]

    # Atomic quota reservation (audit C-06): claim a slot only if under limit.
    # UPDATE ... WHERE scans_used < limit closes the check-then-act race.
    tenant = db.fetchone("SELECT plan FROM tenants WHERE id=?", (tid,))
    if not tenant:
        raise HTTPException(404, "Tenant not found")
    limits = {"free": 10, "pro": 100, "team": 500, "enterprise": 99999}
    max_scans = limits.get(tenant["plan"], 10)
    # Atomic quota reservation (audit C-06): execute returns rowcount
    if db.execute(
        "UPDATE tenants SET scans_used = scans_used + 1 WHERE id=? AND scans_used < ?",
        (tid, max_scans)
    ) == 0:
        raise HTTPException(429, f"Monthly scan limit ({max_scans}) reached. Upgrade to Pro.")

    db.execute(
        "INSERT INTO scan_jobs (id, tenant_id, target, profile, status) VALUES (?,?,?,?,'queued')",
        (scan_id, tid, req.target, req.profile)
    )

    # Run clone/scan off the HTTP worker (audit C-06) — no blocking, no DoS.
    background_tasks.add_task(_run_scan, scan_id, tid, req.target, req.profile)
    return {"scan_id": scan_id, "status": "queued", "message": "Scan queued; poll /api/v2/scans"}


def _run_scan(scan_id: str, tid: int, target: str, profile: str):
    """Spawn out-of-process scan worker (GSC roadmap 4.8).

    Долгий clone+scan+store выполняется в отдельном процессе (gsc_scan_worker.py),
    а не в FastAPI background task — чтобы не блокировать HTTP worker и не тянуть
    его память. Fallback на in-process при недоступности worker-скрипта.
    """
    worker = Path(__file__).parent / "gsc_scan_worker.py"
    if worker.exists():
        try:
            subprocess.Popen(
                [sys.executable, str(worker), scan_id],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,  # detach from the web process
            )
            return
        except Exception as e:
            print(f"[scan {scan_id}] worker spawn failed, in-process fallback: {e}", flush=True)
    _run_scan_in_process(scan_id, tid, target, profile)


def _run_scan_in_process(scan_id: str, tid: int, target: str, profile: str):
    """In-process fallback (dev без worker). clone + scan + store, никогда не бросает."""
    db = get_backend(tid)
    try:
        db.execute("UPDATE scan_jobs SET status='running' WHERE id=? AND tenant_id=?", (scan_id, tid))
        findings = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # Clone shallow
                clone = subprocess.run(
                    ["git", "clone", "--depth", "1", "--filter=blob:none", target, tmp],
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
                    stdout_clean = result.stdout.strip()
                    json_start = stdout_clean.find('[')
                    if json_start > 0:
                        stdout_clean = stdout_clean[json_start:]
                    findings = json.loads(stdout_clean) if stdout_clean else []
                    if not isinstance(findings, list):
                        findings = []

            # Store findings
            for f in findings[:500]:  # cap at 500
                nf = _normalize_finding(f)
                db.execute(
                    """INSERT INTO findings
                       (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id)
                       VALUES (?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(tenant_id, finding_key) DO UPDATE SET
                         rule_id=excluded.rule_id, title=excluded.title,
                         severity=excluded.severity, confidence=excluded.confidence,
                         file=excluded.file, line=excluded.line, snippet=excluded.snippet""",
                    (nf["finding_key"], nf["rule_id"], nf["title"],
                     nf["severity"], nf["confidence"], nf["file"],
                     nf["line"], nf["snippet"], tid)
                )

            db.execute(
                "UPDATE scan_jobs SET status='done', findings_count=?, completed_at=? WHERE id=? AND tenant_id=?",
                (len(findings), datetime.now(timezone.utc).isoformat(), scan_id, tid)
            )
        except Exception as e:
            db.execute("UPDATE scan_jobs SET status='failed' WHERE id=? AND tenant_id=?", (scan_id, tid))
            print(f"[scan {scan_id}] failed: {e}", flush=True)
    finally:
        db.close()

# ═══════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/findings")
def findings(
    severity: str = Query(None),
    rule_id: str = Query(None),
    limit: int = Query(50, le=500),
    tid: int = Depends(get_tenant_from_key),
    db=Depends(get_db),
):
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

    rows = db.query(sql, params)
    return {"findings": [dict(r) for r in rows], "count": len(rows)}

# ═══════════════════════════════════════════════════════════
# Scans list
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/scans")
def scans(tid: int = Depends(get_tenant_from_key), db=Depends(get_db)):
    rows = db.query(
        "SELECT * FROM scan_jobs WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50", (tid,)
    )
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
def signup(github_user: str = Query(...), db=Depends(get_db)):
    """Quick signup with GitHub username. Returns API key.

    Plan is assigned server-side only (default 'free'); billing/webhook may
    upgrade it later. Clients must not self-select a plan (audit S-01).

    GSC-007 / S-08: при GSC_INVITE_ONLY=1 open signup отклоняется (fail-closed).
    server.py runtime-схема не хранит invites (это enterprise schema_s3.sql),
    поэтому в invite-only режиме выдачу ключей берёт на себя admin-issued
    invite (cloud/user_auth.py) — оператор больше не получает «скрытый» open
    signup, противоречащий заявленному invite-only onboarding.
    """
    if os.environ.get("GSC_INVITE_ONLY", "0").lower() in ("1", "true", "yes"):
        raise HTTPException(403, "This instance is invite-only. Ask an admin to invite you.")
    api_key, tid = create_tenant(github_user, "free", db)
    return {"api_key": api_key, "tenant_id": tid, "plan": "free", "message": "Save this key — it won't be shown again."}

# ═══════════════════════════════════════════════════════════
# GitHub OAuth
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/auth/github")
def github_login(redirect: str = Query("/"), db=Depends(get_db)):
    """Redirect user to GitHub OAuth."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(500, "GitHub OAuth not configured — set GITHUB_CLIENT_ID")
    # Validate redirect: only same-origin relative paths (prevents open redirect, S-05)
    if not redirect.startswith("/") or redirect.startswith("//"):
        redirect = "/"
    state = secrets.token_urlsafe(16)
    # Store state temporarily for CSRF protection
    state_expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    db.execute(
        "INSERT INTO sessions (token, tenant_id, github_user, expires_at) VALUES (?,0,?,?) "
        "ON CONFLICT(token) DO UPDATE SET tenant_id=excluded.tenant_id, "
        "github_user=excluded.github_user, expires_at=excluded.expires_at",
        (f"state:{state}", f"redirect:{redirect}", state_expires)
    )
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&state={state}"
        f"&scope=user:email"
    )
    return RedirectResponse(url)

@app.get("/api/v2/auth/github/callback")
async def github_callback(code: str = Query(...), state: str = Query(""), db=Depends(get_db)):
    """Handle GitHub OAuth callback. Exchange code → access token → user info."""
    if not GITHUB_CLIENT_SECRET:
        raise HTTPException(500, "GitHub OAuth not configured — set GITHUB_CLIENT_SECRET")

    # Verify state (one-time: consume atomically, reject replay — audit S-02)
    state_key = f"state:{state}"
    now = datetime.now(timezone.utc).isoformat()
    state_row = db.fetchone(
        "SELECT github_user FROM sessions WHERE token=? AND expires_at > ?",
        (state_key, now)
    )
    if not state_row:
        raise HTTPException(400, "Invalid or expired OAuth state")
    db.execute("DELETE FROM sessions WHERE token=?", (state_key,))

    redirect_url = "/"
    if state_row["github_user"] and state_row["github_user"].startswith("redirect:"):
        candidate = state_row["github_user"].split(":", 1)[1]
        if candidate.startswith("/") and not candidate.startswith("//"):
            redirect_url = candidate

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
    existing = db.fetchone(
        "SELECT id FROM tenants WHERE github_user=?", (github_user,)
    )
    if existing:
        tid = existing["id"]
    else:
        tid = db.insert_id(
            "INSERT INTO tenants (name, github_user, plan) VALUES (?,?,'free') RETURNING id",
            (github_user, github_user)
        )

    # Issue a one-time, short-lived authorization code (audit S-03). The real
    # JWT session is created at /api/v2/auth/exchange — never placed in a URL.
    auth_code = secrets.token_urlsafe(32)
    code_expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    db.execute(
        "INSERT INTO sessions (token, tenant_id, github_user, expires_at) VALUES (?,?,?,?)",
        (f"code:{auth_code}", tid, github_user, code_expires)
    )

    return RedirectResponse(f"{redirect_url}?code={auth_code}")

@app.post("/api/v2/auth/exchange")
def exchange_code(payload: dict = Body(...), db=Depends(get_db)):
    """Exchange a one-time auth code for a session token (POST body, not URL)."""
    code = payload.get("code", "")
    if not code:
        raise HTTPException(400, "Missing code")
    key = f"code:{code}"
    now = datetime.now(timezone.utc).isoformat()
    row = db.fetchone(
        "SELECT tenant_id, github_user FROM sessions WHERE token=? AND expires_at > ?",
        (key, now)
    )
    if not row:
        raise HTTPException(401, "Invalid or expired code")
    # One-time: consume the code atomically before issuing a session
    db.execute("DELETE FROM sessions WHERE token=?", (key,))
    session_token = create_session(row["tenant_id"], row["github_user"], db)
    return {"token": session_token, "github_user": row["github_user"]}

@app.get("/api/v2/auth/session")
def session_info(
    authorization: str = Header(None),
    token: Optional[str] = Query(None),
    db=Depends(get_db),
):
    """Validate session token and return tenant info (token via header preferred)."""
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    elif token:
        raw = token  # legacy query fallback
    if not raw:
        raise HTTPException(401, "Missing session token")
    tid = verify_session(raw, db)
    if tid is None:
        raise HTTPException(401, "Invalid or expired session")
    tenant = db.fetchone("SELECT * FROM tenants WHERE id=?", (tid,))
    return {"tenant": dict(tenant), "valid": True}

# ═══════════════════════════════════════════════════════════
# Stats / dashboard
# ═══════════════════════════════════════════════════════════

@app.get("/api/v2/stats")
def stats(tid: int = Depends(get_tenant_from_key), db=Depends(get_db)):
    tenant = db.fetchone("SELECT * FROM tenants WHERE id=?", (tid,))
    total_findings = db.fetchone(
        "SELECT COUNT(*) as c FROM findings WHERE tenant_id=?", (tid,)
    )["c"]
    scans_done = db.fetchone(
        "SELECT COUNT(*) as c FROM scan_jobs WHERE tenant_id=? AND status='done'", (tid,)
    )["c"]

    return {
        "tenant": dict(tenant),
        "total_findings": total_findings,
        "scans_completed": scans_done,
        "scans_remaining": {"free": 10, "pro": 100, "team": 500, "enterprise": 99999}[tenant["plan"]] - tenant["scans_used"],
    }

# ── Dashboard ──
@app.get("/dashboard")
def dashboard(tid: int = Depends(get_tenant_from_key), db=Depends(get_db)):
    """Security dashboard with trend charts and PR feedback.

    GSC-004: authenticated (API key) — not public. Findings are scoped to the
    calling tenant; local audit aggregates are admin-only self-hosted data.
    """

    # Stats for charts
    stats = {
        "total_scans": 0, "scans_today": 0, "total_findings": 0,
        "by_severity": {}, "by_rule": {}, "pr_feedback": [],
        "prs_created": 0, "prs_accepted": 0, "last_scan": None,
        "trend": [], "fixed_count": 0,
    }

    try:
        # Scan stats (from audit DB if available, else cloud DB)
        src = _audit_conn or db
        stats["total_scans"] = src.fetchone("SELECT COUNT(*) FROM audit_runs")[0]
        try:
            stats["scans_today"] = src.fetchone(
                f"SELECT COUNT(*) FROM audit_runs "
                f"WHERE {src.date_expr('started_at')} = {src.now_expr()}"
            )[0]
        except Exception:
            stats["scans_today"] = 0
        last = src.fetchone(
            "SELECT project, started_at, total_findings FROM audit_runs ORDER BY id DESC LIMIT 1"
        )
        if last:
            stats["last_scan"] = {"project": last["project"], "at": last["started_at"],
                                 "findings": last["total_findings"]}

        # PR stats
        try:
            stats["prs_created"] = db.fetchone("SELECT COUNT(*) FROM published_comments")[0]
        except Exception:
            stats["prs_created"] = 0
        # Findings stats — GSC-004: tenant-scoped via the cloud DB (which has
        # tenant_id), never the shared local audit DB.
        stats["total_findings"] = db.fetchone(
            "SELECT COUNT(*) FROM findings WHERE tenant_id = ?", (tid,)
        )[0]
        try:
            # Cloud DB uses 'severity' not 'category'
            rows = db.query(
                "SELECT COALESCE(severity, 'UNKNOWN') as sev, COUNT(*) as cnt "
                "FROM findings WHERE tenant_id = ? GROUP BY sev ORDER BY cnt DESC",
                (tid,),
            )
            stats["by_severity"] = {r["sev"]: r["cnt"] for r in rows}
        except Exception:
            stats["by_severity"] = {}
        try:
            rows = db.query(
                "SELECT COALESCE(rule_id, 'unknown') as rule_id, COUNT(*) as cnt "
                "FROM findings WHERE tenant_id = ? GROUP BY rule_id "
                "ORDER BY cnt DESC LIMIT 8",
                (tid,),
            )
            stats["by_rule"] = {r["rule_id"]: r["cnt"] for r in rows}
        except Exception:
            stats["by_rule"] = {}

        # Trend (temporal): findings over the last 30 days (line chart)
        stats["trend"] = []
        try:
            since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            de = db.date_expr("created_at")
            rows = db.query(
                f"SELECT {de} as d, COUNT(*) as cnt FROM findings "
                "WHERE tenant_id = ? AND created_at >= ? "
                f"GROUP BY {de} ORDER BY d",
                (tid, since),
            )
            stats["trend"] = [{"date": r["d"], "count": r["cnt"]} for r in rows]
        except Exception:
            stats["trend"] = []

        # Fixed count (audit DB — revalidation_verdict='fixed')
        stats["fixed_count"] = 0
        try:
            if _audit_conn is not None:
                stats["fixed_count"] = _audit_conn.fetchone(
                    "SELECT COUNT(*) FROM findings WHERE revalidation_verdict = 'fixed'"
                )[0]
        except Exception:
            stats["fixed_count"] = 0

        # PR feedback
        try:
            rows = db.query("""
                SELECT repo, pr_number, pr_state, author_response, comment_count,
                       reactions_json, merged, checked_at
                FROM pr_feedback ORDER BY checked_at DESC LIMIT 10
            """)
            stats["pr_feedback"] = [dict(r) for r in rows]
        except Exception:
            stats["pr_feedback"] = []

    except Exception:
        pass  # Generic fallback for scan/finding queries

    # Build HTML with Chart.js
    # Audit S-08: escape "</" so external data can't break out of the <script>
    # tag; JS side additionally uses textContent/escaping for the PR table.
    def _json_safe(obj) -> str:
        return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")

    severity_json = _json_safe(stats["by_severity"])
    rule_json = _json_safe(stats["by_rule"])
    pr_json = _json_safe(stats["pr_feedback"])
    trend_json = _json_safe(stats["trend"])

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
            <div class="stat"><div class="value" style="color:#3fb950" id="fixed">{stats['fixed_count']}</div><div class="label">Fixed</div></div>
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
        <h2>📈 Trend (30 days)</h2>
        <canvas id="trendChart"></canvas>
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

// Trend line chart
const trendData = {trend_json};
if (trendData && trendData.length > 0) {{
    new Chart(document.getElementById('trendChart'), {{
        type: 'line',
        data: {{
            labels: trendData.map(d => d.date),
            datasets: [{{
                label: 'Findings',
                data: trendData.map(d => d.count),
                borderColor: '#3fb950',
                backgroundColor: 'rgba(63,185,80,0.1)',
                fill: true,
                tension: 0.3
            }}]
        }},
        options: {{ plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }} }}
    }});
}}

// PR table
const prTable = document.getElementById('prTable');
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const safeRepo = (s) => /^[A-Za-z0-9._/-]+$/.test(String(s ?? '')) ? String(s) : '';
if (prData && prData.length > 0) {{
    const rows = prData.map(p => {{
        const stateClass = p.merged ? 'merged' : (p.pr_state || 'open');
        const icon = p.merged ? '🟣' : (p.pr_state === 'closed' ? '🔴' : '🟢');
        const responseIcon = p.author_response === 'accepted' ? '✅' : (p.author_response === 'dismissed' ? '❌' : '');
        const repo = safeRepo(p.repo);
        const repoLink = repo ? `<a href="https://github.com/${{repo}}/pull/${{p.pr_number}}" style="color:#58a6ff">#${{p.pr_number}}</a>` : `#${{p.pr_number}}`;
        return `<tr>
            <td>${{escapeHtml(repo || p.repo)}}</td>
            <td>${{repoLink}}</td>
            <td class="${{escapeHtml(stateClass)}}">${{icon}} ${{escapeHtml(p.merged ? 'merged' : p.pr_state)}}</td>
            <td>${{responseIcon}} ${{escapeHtml(p.author_response)}}</td>
            <td>${{escapeHtml(p.comment_count)}}</td>
        </tr>`;
    }}).join('');
    prTable.innerHTML = '<tr><th>Repo</th><th>PR</th><th>Status</th><th>Response</th><th>Comments</th></tr>' + rows;
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
    _audit_conn = SqliteBackend(AUDIT_DB, read_only=True)
    print(f"✅ Audit DB loaded: {_audit_conn.fetchone('SELECT COUNT(*) FROM findings')[0]} findings", flush=True)

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
    init_cloud_db()
    port = int(os.environ.get("PORT", 8000))
    print(f"GSC Cloud API v1.3.0 starting on :{port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
