#!/usr/bin/env python3
"""GSC PR Feedback — check PR outcomes and feed back to DB.

Merged PR → mark findings as fixed + TP
Closed (not merged) PR → mark findings as FP

Run: python3 gsc_pr_feedback.py
Designed to be called from gsc_pr_tracker.py or cron.
"""
import os, sys, json, sqlite3, subprocess
from datetime import datetime, timezone

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

# Our open PRs to track
TRACKED_PRS = [
    {"repo": "aio-libs/aiohttp-security", "pr": 1005, "project": "aio-libs/aiohttp-security"},
    {"repo": "mathiasertl/django-ca", "pr": 202, "project": "mathiasertl/django-ca"},
    {"repo": "stanfrbd/cyberbro", "pr": 212, "project": "stanfrbd/cyberbro"},
    {"repo": "deep-learning-indaba/Baobab", "pr": 1401, "project": "deep-learning-indaba/Baobab"},
    {"repo": "manjurulhoque/doccure", "pr": 14, "project": "manjurulhoque/doccure"},
]


def check_pr(repo: str, pr_num: int) -> dict:
    """Check PR state via gh CLI."""
    try:
        result = subprocess.run(
            ["gh", "pr", "view", str(pr_num), "--repo", repo,
             "--json", "state,mergedAt,closedAt,updatedAt"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


def update_db(db, project: str, verdict: str, pr_info: dict):
    """Mark findings for this project with feedback from PR outcome."""
    now = datetime.now(timezone.utc).isoformat()
    reason = f"PR {'merged' if verdict == 'TP' else 'closed'} — auto-feedback"

    # Find findings for this project
    updated = db.execute("""
        UPDATE findings 
        SET status = ?, 
            revalidation_verdict = ?,
            revalidation_checked_at = ?,
            revalidation_reasoning = ?
        WHERE project = ?
          AND revalidation_verdict IS NULL
    """, (
        "fixed" if verdict == "TP" else "false_positive",
        verdict, now, reason, project
    )).rowcount

    return updated


def main():
    db = sqlite3.connect(DB)
    now = datetime.now(timezone.utc).isoformat()

    for pr in TRACKED_PRS:
        result = check_pr(pr["repo"], pr["pr"])
        if "error" in result:
            print(f"  ⚠️ {pr['repo']}#{pr['pr']}: {result['error']}")
            continue

        state = result.get("state", "").lower()
        merged = result.get("mergedAt")

        if state == "merged" or merged:
            updated = update_db(db, pr["project"], "TP", result)
            print(f"  ✅ {pr['repo']}#{pr['pr']} MERGED → {updated} findings marked TP")
        elif state == "closed":
            updated = update_db(db, pr["project"], "FP", result)
            print(f"  ❌ {pr['repo']}#{pr['pr']} CLOSED → {updated} findings marked FP")
        else:
            print(f"  ⏳ {pr['repo']}#{pr['pr']} still OPEN — waiting")

    # Show current stats
    tp = db.execute("SELECT COUNT(*) FROM findings WHERE revalidation_verdict='TP'").fetchone()[0]
    fp = db.execute("SELECT COUNT(*) FROM findings WHERE revalidation_verdict='FP'").fetchone()[0]
    print(f"\nTotal: TP={tp}, FP={fp}")

    db.commit()
    db.close()


if __name__ == "__main__":
    main()
