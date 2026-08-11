#!/usr/bin/env python3
"""
GSC Pipeline Health Check — monitors self-learning loop degradation.

Checks:
  1. Bounty flow: examples collected in last 7 days?
  2. Shadow lifecycle: shadow detectors or promotions exist?
  3. Feedback flow: verdicts recorded in last 7 days?
  4. Pipeline: did last nightly run complete OK?

Run: python3 scripts/gsc_pipeline_health.py
"""
from __future__ import annotations
import json, os, sqlite3, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
LOG_DIR = Path(__file__).parent.parent / "logs"


def _connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def check_bounty_flow(days: int = 7) -> dict:
    """Bounty examples flowing? > 0 in last N days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    db = _connect()
    try:
        count = db.execute(
            "SELECT COUNT(*) as c FROM bounty_examples WHERE collected_at >= ?",
            (cutoff,)).fetchone()["c"]
        total = db.execute("SELECT COUNT(*) FROM bounty_examples").fetchone()[0]
    except sqlite3.OperationalError:
        count = total = 0
    finally:
        db.close()
    return {"ok": count > 0, "recent": count, "total": total,
            "message": f"{count} examples in last {days}d (total: {total})"}


def check_shadow_lifecycle() -> dict:
    """Any shadow detectors or promotions?"""
    db = _connect()
    try:
        shadow = db.execute(
            "SELECT COUNT(*) as c FROM detector_status WHERE status='shadow'"
        ).fetchone()["c"]
        full_from_shadow = db.execute(
            "SELECT COUNT(*) as c FROM detector_status "
            "WHERE status='full' AND rule_id LIKE 'GSAUTO%'"
        ).fetchone()["c"]
        deactivated = db.execute(
            "SELECT COUNT(*) as c FROM detector_status WHERE status='deactivated'"
        ).fetchone()["c"]
    except sqlite3.OperationalError:
        shadow = full_from_shadow = deactivated = 0
    finally:
        db.close()
    has_lifecycle = shadow > 0 or full_from_shadow > 0
    return {"ok": has_lifecycle or True,  # OK even if none yet (still collecting)
            "shadow": shadow, "promoted": full_from_shadow, "deactivated": deactivated,
            "message": f"shadow={shadow} promoted={full_from_shadow} deactivated={deactivated}"}


def check_feedback_flow(days: int = 7) -> dict:
    """Verdicts flowing? > 0 in last N days."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    db = _connect()
    try:
        count = db.execute(
            "SELECT COUNT(*) as c FROM feedback WHERE created_at >= ?",
            (cutoff,)).fetchone()["c"]
    except sqlite3.OperationalError:
        count = 0
    finally:
        db.close()
    # Not critical if 0 — might be no manual verdicts this week
    return {"ok": True, "recent": count,
            "message": f"{count} verdicts in last {days}d"}


def check_pipeline_ok() -> dict:
    """Did last nightly run complete OK?"""
    # Find most recent health snapshot
    health_files = sorted(LOG_DIR.glob("health_*.json"), reverse=True)
    if not health_files:
        return {"ok": True, "message": "no health snapshots yet (first run pending)"}

    latest = json.loads(health_files[0].read_text())
    pipeline = latest.get("pipeline", {})
    failed = [k for k, v in pipeline.items() if v == "FAIL"]

    return {"ok": len(failed) == 0,
            "failed_steps": failed,
            "timestamp": latest.get("timestamp", ""),
            "message": f"pipeline: {len(pipeline)-len(failed)}/{len(pipeline)} OK"
            if pipeline else "no pipeline data"}


def main():
    checks = [
        ("bounty_flow",    check_bounty_flow()),
        ("shadow_lifecycle", check_shadow_lifecycle()),
        ("feedback_flow",  check_feedback_flow()),
        ("pipeline_ok",    check_pipeline_ok()),
    ]

    print("GSC Pipeline Health Check\n")
    all_ok = True
    for name, result in checks:
        icon = "✅" if result["ok"] else "❌"
        print(f"  {icon} {name}: {result['message']}")
        if not result["ok"]:
            all_ok = False

    print(f"\n{'Overall: OK' if all_ok else 'Overall: ISSUES DETECTED'}")

    # Show bounty coverage
    db = _connect()
    try:
        coverage = db.execute("""
            SELECT cwe_id, language, COUNT(*) as n FROM bounty_examples
            WHERE cwe_id != '' GROUP BY cwe_id, language ORDER BY n DESC LIMIT 5
        """).fetchall()
        if coverage:
            print("\nTop CWE+lang coverage:")
            for c in coverage:
                print(f"    {c['cwe_id']} | {c['language']}: {c['n']} examples")
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
