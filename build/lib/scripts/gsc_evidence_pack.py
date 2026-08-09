"""Собирает пакет доказательств для аудита одним прогоном."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def build_pack(db_admin, out_dir: str) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. Audit chain verification
    from cloud import audit
    from cloud.store import control_plane
    db = control_plane()
    tenants = [r["id"] for r in db.query("SELECT id FROM tenants")]
    chain_results = {str(tid): audit.verify_chain(db_admin, tid)
                     for tid in tenants}
    _save(out / "audit_chain_verify.json", chain_results)

    # 2. Calibration report
    proc = subprocess.run(
        [sys.executable, "-m", "gsc", "calibration", "run",
         "--fail-on-regression"],
        capture_output=True, text=True, timeout=300)
    _save(out / "calibration_report.txt", proc.stdout or proc.stderr)

    # 3. Test suite results
    proc2 = subprocess.run(
        [sys.executable, "tests/test_corpus.py"],
        capture_output=True, text=True, timeout=300)
    _save(out / "tests_report.txt", proc2.stdout or proc2.stderr)

    # 4. Access review
    members = db_admin.query("""
        SELECT t.name AS tenant, u.login, m.role, m.created_at
        FROM memberships m JOIN tenants t ON m.tenant_id = t.id
        JOIN users u ON m.user_id = u.id ORDER BY t.name, u.login
    """)
    _save(out / "access_review.json", members)

    return {"pack_dir": str(out), "tenants": len(tenants),
            "audit_chains_ok": all(r.get("ok") for r in chain_results.values())}


def _save(path: Path, data):
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str)
        if isinstance(data, (dict, list)) else str(data))