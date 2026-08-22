# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Cloud worker (S1).

Тянет задачу → валидирует цель → запускает gsc external-scan как
subprocess с эфемерным HOME → ингестит report в PG → пишет metering.
Код тенанта живёт только во временном каталоге и удаляется после скана.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from gsc_cloud.gsc_db_backend import PgBackend
from gsc_cloud import store          # CRUD по scans/findings/usage
from gsc_cloud.scan_queue import ScanQueue
from gsc_cloud.target_policy import validate_target

SCAN_TIMEOUT_SEC = 900


def run_scanner(job: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="gsc_scan_") as tmp:
        report_path = os.path.join(tmp, "report.json")
        cmd = ["gsc", "external-scan", job["target"],
               "--profile", job["profile"], "-o", report_path]
        if job.get("with_poc"):
            cmd.append("--with-poc")
        if job.get("with_chains"):
            cmd.append("--with-chains")
        env = {**os.environ,
               "GSC_DB_PATH": os.path.join(tmp, "worker.db"),
               "HOME": tmp}
        proc = subprocess.run(cmd, env=env, timeout=SCAN_TIMEOUT_SEC,
                              capture_output=True, text=True)
        # 0 = pass, 1 = blocking (нормальный исход), 2 = error
        if proc.returncode not in (0, 1):
            raise RuntimeError(proc.stderr[-500:] or "scanner failed")
        with open(report_path, encoding="utf-8") as f:
            return json.load(f)


def ingest(db: PgBackend, scan_id: int, report: dict) -> None:
    findings = report.get("findings", [])
    for f in findings:
        db.execute("""
            INSERT INTO findings
                (tenant_id, scan_id, finding_key, rule_id, severity,
                 confidence, file, line, snippet, poc, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (db.tenant_id, scan_id, f["finding_key"], f["rule_id"],
              f.get("severity"), f.get("confidence"), f.get("file"),
              f.get("line"), f.get("snippet", ""),
              (f.get("metadata") or {}).get("poc", ""),
              json.dumps(f.get("metadata") or {})))
    blocking = sum(1 for f in findings if f.get("blocking"))
    usage = report.get("usage", {})
    db.execute("""
        UPDATE scans SET status='done', findings_total=?, blocking_count=?,
               llm_calls=?, duration_sec=?, finished_at=now()
        WHERE id=? AND tenant_id=?
    """, (len(findings), blocking, usage.get("llm_calls", 0),
          report.get("duration_sec"), scan_id, db.tenant_id))


def main() -> None:
    q = ScanQueue()
    dsn = os.environ["GSC_DATABASE_URL"]
    print("worker: ready", flush=True)
    while True:
        job = q.dequeue(timeout=10)
        if not job:
            continue
        scan_id, tenant_id = job["scan_id"], job["tenant_id"]
        db = PgBackend(dsn, tenant_id)
        try:
            validate_target(job["target"])
            store.set_scan_status(db, scan_id, "running")
            t0 = time.time()
            report = run_scanner(job)
            report.setdefault("usage", {})["duration_sec"] = time.time() - t0
            ingest(db, scan_id, report)
            store.meter(db, tenant_id, report)
            db.commit()
        except Exception as e:
            db.execute(
                "UPDATE scans SET status='error', error=?, finished_at=now() "
                "WHERE id=? AND tenant_id=?",
                (str(e)[:500], scan_id, tenant_id))
            db.commit()
            print(f"scan {scan_id} failed: {e}", flush=True)


if __name__ == "__main__":
    main()