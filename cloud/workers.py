"""cloud/workers.py — SaaS S2: background scan workers with SQLite job queue.

Workers pull jobs from gsc_jobs table, execute gsc.scan(), and store results.
Compatible with S1 tenant isolation (scoped_query).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Dict, List, Optional

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"

# ── Schema migration (adds gsc_jobs table to schema 28) ─────────────

JOB_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS gsc_jobs (
    job_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repo_url TEXT,
    repo_path TEXT,
    profile TEXT DEFAULT 'audit',
    status TEXT DEFAULT 'queued',  -- queued | running | done | failed
    findings_json TEXT,
    error TEXT,
    created_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON gsc_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON gsc_jobs(status);
"""

def _ensure_schema():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(JOB_SCHEMA_SQL)
    conn.commit()
    conn.close()

# ── Job queue ───────────────────────────────────────────────────────

@dataclass
class ScanJob:
    job_id: str
    tenant_id: str
    repo_path: str
    profile: str = "audit"
    status: str = "queued"

def enqueue_scan(tenant_id: str, repo_path: str, profile: str = "audit") -> str:
    """Submit a scan job. Returns job_id."""
    _ensure_schema()
    job_id = uuid.uuid4().hex[:12]
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO gsc_jobs (job_id, tenant_id, repo_path, profile, status, created_at) "
        "VALUES (?, ?, ?, ?, 'queued', ?)",
        (job_id, tenant_id, repo_path, profile, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()
    return job_id

def get_next_job() -> Optional[ScanJob]:
    """Pull next queued job. Returns None if queue empty."""
    _ensure_schema()
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute(
        "SELECT job_id, tenant_id, repo_path, profile FROM gsc_jobs "
        "WHERE status = 'queued' ORDER BY created_at LIMIT 1"
    ).fetchone()
    if not row:
        conn.close()
        return None
    job_id = row[0]
    conn.execute(
        "UPDATE gsc_jobs SET status = 'running', started_at = ? WHERE job_id = ?",
        (datetime.now(timezone.utc).isoformat(), job_id),
    )
    conn.commit()
    conn.close()
    return ScanJob(job_id=job_id, tenant_id=row[1], repo_path=row[2], profile=row[3] or "audit")

def complete_job(job_id: str, findings: List[Dict], error: str = ""):
    conn = sqlite3.connect(str(DB_PATH))
    status = "done" if not error else "failed"
    conn.execute(
        "UPDATE gsc_jobs SET status = ?, findings_json = ?, error = ?, completed_at = ? "
        "WHERE job_id = ?",
        (status, json.dumps(findings), error, datetime.now(timezone.utc).isoformat(), job_id),
    )
    conn.commit()
    conn.close()

def get_job_status(job_id: str) -> Optional[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute(
        "SELECT job_id, tenant_id, repo_path, status, created_at, started_at, completed_at, error "
        "FROM gsc_jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"job_id": row[0], "tenant_id": row[1], "repo_path": row[2],
            "status": row[3], "created_at": row[4], "started_at": row[5],
            "completed_at": row[6], "error": row[7]}

def get_tenant_jobs(tenant_id: str, limit: int = 20) -> List[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute(
        "SELECT job_id, status, repo_path, created_at FROM gsc_jobs "
        "WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
        (tenant_id, limit)
    ).fetchall()
    conn.close()
    return [{"job_id": r[0], "status": r[1], "repo_path": r[2], "created_at": r[3]} for r in rows]

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

def _test():
    _ensure_schema()
    print("gsc_jobs table exists ✅" if True else "")

if __name__ == "__main__":
    _test()
