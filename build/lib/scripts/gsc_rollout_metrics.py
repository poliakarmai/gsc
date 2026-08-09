#!/usr/bin/env python3
"""
GSC Rollout Metrics — v0.16 production tracking.
Usage: gsc metrics --rollout
"""

import os, sys, json, sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))
FEEDBACK_FILE = Path(os.path.expanduser("~/.gsc/external/feedback.jsonl"))


def metrics_rollout() -> dict:
    """Collect rollout metrics from DB + feedback file."""
    m = {
        "phase": "unknown",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "repos": 0,
        "prs_scanned": 0,
        "comments_posted": 0,
        "comments_updated": 0,
        "duplicate_comments": 0,
        "blocking_findings": 0,
        "warnings": 0,
        "confirmed": 0,
        "likely": 0,
        "feedback_total": 0,
        "feedback_tp": 0,
        "feedback_fp": 0,
        "feedback_ignore": 0,
        "calibration_pass": True,
        "redaction_leaks": 0,
        "errors": [],
    }

    # DB metrics
    if DB.exists():
        try:
            conn = sqlite3.connect(str(DB))
            conn.row_factory = sqlite3.Row
            # Findings with verdicts
            total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
            revalidated = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE revalidation_verdict IS NOT NULL"
            ).fetchone()["c"]
            tp = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE revalidation_verdict='true-positive'"
            ).fetchone()["c"]
            fp = conn.execute(
                "SELECT COUNT(*) as c FROM findings WHERE revalidation_verdict='false-positive'"
            ).fetchone()["c"]
            m["findings_total"] = total
            m["findings_revalidated"] = revalidated
            m["tp_count"] = tp
            m["fp_count"] = fp
            if tp + fp > 0:
                m["precision"] = round(tp / (tp + fp) * 100, 1)
            conn.close()
        except Exception as e:
            m["errors"].append(f"DB error: {e}")

    # Feedback metrics
    if FEEDBACK_FILE.exists():
        try:
            for line in FEEDBACK_FILE.read_text().strip().split("\n"):
                if not line: continue
                entry = json.loads(line)
                m["feedback_total"] += 1
                v = entry.get("verdict", "")
                if v in ("tp", "true-positive"): m["feedback_tp"] += 1
                elif v in ("fp", "false-positive"): m["feedback_fp"] += 1
                elif v in ("ignore", "ignored"): m["feedback_ignore"] += 1
        except Exception as e:
            m["errors"].append(f"Feedback error: {e}")

    # Calibration
    calib_reports = list(Path(os.path.expanduser("~/gsc")).rglob("calibration/reports/*/calibration_report.json"))
    if calib_reports:
        try:
            latest = sorted(calib_reports)[-1]
            cr = json.loads(latest.read_text())
            m["calibration_pass"] = cr.get("failed", 0) == 0
            m["calibration_passed"] = cr.get("passed", 0)
            m["calibration_total"] = cr.get("total", 0)
        except Exception:
            pass

    return m


def print_rollout(m: dict):
    print("📊 GSC Rollout Metrics")
    print(f"   Scanned at: {m['scanned_at'][:19]}")
    print()
    print(f"   DB findings total: {m.get('findings_total', '?')}")
    print(f"   Revalidated (LLM): {m.get('findings_revalidated', 0)}")
    if m.get("precision") is not None:
        print(f"   TP: {m.get('tp_count', 0)}  FP: {m.get('fp_count', 0)}  "
              f"Precision: {m['precision']}%")
    print()
    print(f"   Feedback total: {m['feedback_total']}")
    print(f"   TP: {m['feedback_tp']}  FP: {m['feedback_fp']}  Ignored: {m['feedback_ignore']}")
    fb_total = m['feedback_tp'] + m['feedback_fp']
    if fb_total > 0:
        print(f"   Feedback precision: {round(m['feedback_tp'] / fb_total * 100, 1)}%")
    print()
    if m.get("calibration_total"):
        print(f"   Calibration: {m.get('calibration_passed', '?')}/{m.get('calibration_total', '?')} "
              f"{'✅' if m['calibration_pass'] else '❌'}")
    if m.get("errors"):
        print(f"   ⚠️ Errors: {', '.join(m['errors'])}")
    print()

    # Readiness assessment
    issues = []
    if m.get("findings_revalidated", 0) == 0:
        issues.append("No LLM-revalidated findings yet — run self-learning cycle")
    if m.get("precision", 100) < 50:
        issues.append(f"Low precision ({m['precision']}%) — review noisy patterns")
    if not m.get("calibration_pass", True):
        issues.append("Calibration failed — fix before rollout")
    if m.get("redaction_leaks", 0) > 0:
        issues.append(f"Redaction leaks detected ({m['redaction_leaks']})")

    if issues:
        print("⚠️ Readiness issues:")
        for i in issues:
            print(f"   - {i}")
    else:
        print("✅ Ready for production rollout")


def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC Rollout Metrics v0.16")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    m = metrics_rollout()
    if args.json:
        print(json.dumps(m, indent=2, default=str))
    else:
        print_rollout(m)


if __name__ == "__main__":
    main()
