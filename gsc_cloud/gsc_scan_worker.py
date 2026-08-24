"""gsc_scan_worker.py — out-of-process scan worker (GSC roadmap 4.8).

Обрабатывает один scan_job из очереди: clone → gsc external-scan → store
findings → update status. Запускается как ОТДЕЛЬНЫЙ процесс (не FastAPI
background task), чтобы долгие/блокирующие сканы не висели на HTTP worker
и не тянули его память.

Использование:
    python3 -m gsc_scan_worker <scan_id>            # обработать один job
    python3 -m gsc_scan_worker --loop [interval]     # поллить очередь (daemon)

Самодостаточен: не импортирует server.py (избегает его module-level state),
reuses get_backend/_normalize_finding логику.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent          # gsc_cloud/
_REPO_ROOT = _ROOT.parent                         # корень репо (здесь лежит gsc.py)
for _p in (_REPO_ROOT, _ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from gsc_cloud.gsc_db_backend import PgBackend, SqliteBackend  # noqa: E402
from gsc_cloud.target_policy import validate_target  # noqa: E402

SCAN_TIMEOUT_SEC = 300


def _get_backend(tenant_id: int | None = None):
    """Тот же backend-фабрика, что server.get_backend (S1 1.2)."""
    dsn = os.environ.get("GSC_DATABASE_URL")
    if dsn:
        return PgBackend(dsn, tenant_id if tenant_id is not None else 0)
    db_path = os.environ.get("GSC_DB", str(Path.home() / ".gsc" / "gsc_cloud.db"))
    return SqliteBackend(db_path)


def _normalize_finding(f: dict) -> dict:
    """Порт server._normalize_finding (audit C-05): category/file_path → severity/file."""
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


def process_scan_job(scan_id: str) -> int:
    """Обработать один scan_job. Возвращает 0=done, 1=blocking, 2=error."""
    db = _get_backend()
    try:
        job = db.fetchone(
            "SELECT tenant_id, target, profile FROM scan_jobs WHERE id=?", (scan_id,)
        )
        if not job:
            print(f"[worker] scan {scan_id} not found", flush=True)
            return 2
        tid, target, profile = job["tenant_id"], job["target"], job["profile"]

        # GSC-01: shared target policy (SSRF/allowlist guard) before any network I/O
        try:
            validate_target(target)
        except ValueError as e:
            db.execute("UPDATE scan_jobs SET status='failed' WHERE id=?", (scan_id,))
            print(f"[worker] scan {scan_id} rejected: {e}", flush=True)
            return 2

        db.execute("UPDATE scan_jobs SET status='running' WHERE id=?", (scan_id,))
        findings: list = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                clone = subprocess.run(
                    ["git", "clone", "--depth", "1", "--filter=blob:none", target, tmp],
                    capture_output=True, timeout=60,
                )
                if clone.returncode != 0:
                    raise RuntimeError(f"Clone failed: {clone.stderr.decode()[:100]}")

                result = subprocess.run(
                    ["python3", str(_REPO_ROOT / "gsc.py"), "scan", tmp, "--ci", "--json"],
                    capture_output=True, text=True, timeout=SCAN_TIMEOUT_SEC,
                )
                if result.returncode == 0 and result.stdout.strip():
                    out = result.stdout.strip()
                    start = out.find("[")
                    if start > 0:
                        out = out[start:]
                    findings = json.loads(out) if out else []
                    if not isinstance(findings, list):
                        findings = []
        except Exception as e:
            db.execute("UPDATE scan_jobs SET status='failed' WHERE id=?", (scan_id,))
            print(f"[worker] scan {scan_id} failed: {e}", flush=True)
            return 2

        for f in findings[:500]:
            nf = _normalize_finding(f)
            db.execute(
                """INSERT INTO findings
                   (finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(tenant_id, finding_key) DO UPDATE SET
                     rule_id=excluded.rule_id, title=excluded.title,
                     severity=excluded.severity, confidence=excluded.confidence,
                     file=excluded.file, line=excluded.line, snippet=excluded.snippet""",
                (nf["finding_key"], nf["rule_id"], nf["title"], nf["severity"],
                 nf["confidence"], nf["file"], nf["line"], nf["snippet"], tid),
            )

        db.execute(
            "UPDATE scan_jobs SET status='done', findings_count=?, completed_at=? WHERE id=?",
            (len(findings), datetime.now(timezone.utc).isoformat(), scan_id),
        )
        print(f"[worker] scan {scan_id} done: {len(findings)} findings", flush=True)
        return 0
    finally:
        db.close()


def loop(interval: float = 5.0) -> None:
    """Poll scan_jobs queue (status='queued') and process one at a time."""
    import time
    while True:
        db = _get_backend()
        try:
            job = db.fetchone(
                "SELECT id FROM scan_jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
            )
            if job:
                process_scan_job(job["id"])
        finally:
            db.close()
        time.sleep(interval)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--loop":
        interval = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
        loop(interval)
    elif len(sys.argv) >= 2:
        sys.exit(process_scan_job(sys.argv[1]))
    else:
        print("usage: python3 -m gsc_scan_worker <scan_id> | --loop [interval]")
        sys.exit(2)
