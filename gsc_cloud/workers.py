"""cloud/workers.py — ⚠️ LEGACY для runtime-слоя (S1 Трек 2).

Использует таблицу gsc_jobs из enterprise-схемы schema_s2.sql (S2-слой,
пока не реализован — см. GSC_AUDIT_GUIDE.md «SaaS S2–S3 не реализованы»).
Runtime-слой server.py работает на schema_runtime.sql (таблица scan_jobs),
его канонический out-of-process worker — gsc_scan_worker.py (--loop, без Redis).

Файл НЕ удалять: это задел enterprise S2, алиасится через cloud/__init__.py.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import Dict, List, Optional

from gsc_cloud.gsc_db_backend import PgBackend

DB_DSN = os.environ.get("GSC_DATABASE_URL", "postgresql://gsc_app:***@localhost:5432/gsc")

# ── Job queue ───────────────────────────────────────────────────────

@dataclass
class ScanJob:
    job_id: str
    tenant_id: int
    repo_path: str
    profile: str = "audit"
    status: str = "queued"


def _db(tenant_id: int = 0) -> PgBackend:
    """Get DB connection. tenant_id=0 for admin queries (no RLS filter)."""
    return PgBackend(DB_DSN, tenant_id)


def enqueue_scan(tenant_id: int, repo_path: str, profile: str = "audit") -> str:
    """Submit a scan job. Returns job_id."""
    db = _db(tenant_id)
    job_id = uuid.uuid4().hex[:12]
    db.execute(
        "INSERT INTO gsc_jobs (job_id, tenant_id, repo_path, profile, status) "
        "VALUES (?, ?, ?, ?, 'queued')",
        (job_id, tenant_id, repo_path, profile),
    )
    db.commit()
    return job_id


def get_next_job() -> Optional[ScanJob]:
    """Pull next queued job (admin query, reads all tenants). Returns None if queue empty."""
    db = _db(0)  # admin context: read across tenants
    row = db.fetchone(
        "SELECT job_id, tenant_id, repo_path, profile FROM gsc_jobs "
        "WHERE status = 'queued' ORDER BY created_at LIMIT 1"
    )
    if not row:
        return None
    job_id = row["job_id"]
    db.execute(
        "UPDATE gsc_jobs SET status = 'running', started_at = now() WHERE job_id = ?",
        (job_id,),
    )
    db.commit()
    return ScanJob(
        job_id=job_id,
        tenant_id=row["tenant_id"],
        repo_path=row["repo_path"],
        profile=row["profile"] or "audit",
    )


def complete_job(job_id: str, findings: List[Dict], error: str = ""):
    db = _db(0)
    status = "done" if not error else "failed"
    db.execute(
        "UPDATE gsc_jobs SET status = ?, findings_json = ?, error = ?, completed_at = now() "
        "WHERE job_id = ?",
        (status, json.dumps(findings), error, job_id),
    )
    db.commit()


def get_job_status(job_id: str) -> Optional[Dict]:
    db = _db(0)
    row = db.fetchone(
        "SELECT job_id, tenant_id, repo_path, status, created_at, "
        "started_at, completed_at, error FROM gsc_jobs WHERE job_id = ?",
        (job_id,),
    )
    if not row:
        return None
    return dict(row)


def get_tenant_jobs(tenant_id: int, limit: int = 20) -> List[Dict]:
    db = _db(tenant_id)
    rows = db.query(
        "SELECT job_id, status, repo_path, created_at FROM gsc_jobs "
        "WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
        (tenant_id, limit),
    )
    return [dict(r) for r in rows]


# ── Worker ──────────────────────────────────────────────────────────

def scan_repo(repo_path: str, profile: str = "audit") -> tuple[List[Dict], str]:
    """Execute gsc scan on a repo. Returns (findings, error)."""
    gsc_dir = Path(__file__).parent.parent
    try:
        r = subprocess.run(
            [sys.executable, str(gsc_dir / "gsc.py"), "scan", repo_path,
             "--ci", "--json"],
            capture_output=True, text=True, timeout=120, cwd=str(gsc_dir),
        )
        if r.returncode != 0:
            return [], f"scan exit {r.returncode}: {r.stderr[:500]}"
        return json.loads(r.stdout), ""
    except subprocess.TimeoutExpired:
        return [], "scan timed out (>120s)"
    except Exception as e:
        return [], str(e)


def worker_loop(poll_interval: float = 5.0, max_jobs: int = 0):
    """Run worker loop: pull jobs, scan, repeat.
    max_jobs=0 → infinite loop. Set to N for testing (exit after N jobs).
    """
    completed = 0
    while max_jobs == 0 or completed < max_jobs:
        job = get_next_job()
        if not job:
            time.sleep(poll_interval)
            continue
        findings, error = scan_repo(job.repo_path, job.profile)
        complete_job(job.job_id, findings, error)
        completed += 1


def start_worker(daemon: bool = True) -> Thread:
    """Start worker in background thread."""
    t = Thread(target=worker_loop, daemon=daemon)
    t.start()
    return t


# ── Self-test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    db = _db(0)
    try:
        db.execute("SELECT 1 FROM gsc_jobs LIMIT 0")
        print("✅ gsc_jobs table accessible via PostgreSQL")
    except Exception as e:
        print(f"❌ DB error: {e}")
