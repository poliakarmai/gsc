#!/usr/bin/env python3
"""
GSC Batch Revalidator v3 — agent-assisted mode.
Agent fetches findings, classifies them with LLM, then updates DB.
"""

import os, sys, json, sqlite3
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
BATCH_SIZE = 200


def fetch_findings(limit=BATCH_SIZE):
    """Output findings as JSON for agent to classify — prioritized by uncertainty."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    
    # Priority 1: findings with confidence_score in uncertainty band (40-70%)
    # Priority 2: findings with highest confidence_score (most likely TP)
    # Priority 3: remaining unverified
    rows = db.execute("""
        SELECT f.id, f.category, f.title, f.project, f.file_path, 
               f.line_number, f.detail, f.echelon, f.confidence_score, f.pattern_id
        FROM findings f
        WHERE f.revalidation_verdict IS NULL
          AND f.detail IS NOT NULL AND f.detail != ''
        ORDER BY 
            CASE WHEN f.confidence_score BETWEEN 40 AND 70 THEN 0 ELSE 1 END,
            f.confidence_score DESC NULLS LAST,
            f.id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    
    db.close()
    
    findings = []
    for r in rows:
        findings.append({
            "id": r["id"],
            "category": r["category"],
            "title": r["title"] or "",
            "project": r["project"] or "",
            "file_path": f"{r['file_path']}:{r['line_number']}" if r['file_path'] and r['line_number'] else (r["file_path"] or "?"),
            "detail": (r["detail"] or "")[:200],
        })
    
    print(json.dumps({"count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
    return len(findings)


def update_db(results_json):
    """Update DB with agent classifications. Input: {"0": "TP", "1": "FP", ...}"""
    results = json.loads(results_json)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    now = datetime.now().isoformat()
    
    stats = {"TP": 0, "FP": 0, "FIX": 0, "updated": 0}
    
    for idx_str, verdict in results.items():
        fid = int(idx_str)
        verdict = verdict.upper()
        if verdict not in ("TP", "FP", "FIX"):
            continue
        
        stats[verdict] = stats.get(verdict, 0) + 1
        stats["updated"] += 1
        
        db.execute("""
            UPDATE findings 
            SET revalidation_verdict = ?, revalidation_checked_at = ?
            WHERE id = ?
        """, (verdict, now, fid))
    
    db.commit()
    
    # Check for auto-deactivation — now per pattern_id
    rules = db.execute("""
        SELECT COALESCE(pattern_id, category) as rule_key,
               COUNT(*) as total,
               SUM(CASE WHEN revalidation_verdict = 'TP' THEN 1 ELSE 0 END) as tp
        FROM findings 
        WHERE revalidation_verdict IS NOT NULL
        GROUP BY rule_key
        HAVING total >= 10
    """).fetchall()
    
    for r in rules:
        tp_rate = r['tp'] / r['total'] if r['total'] > 0 else 0
        if tp_rate < 0.30:
            reason = f"global_tp_rate={tp_rate:.2f}@{r['total']}verdicts"
            existing = db.execute(
                "SELECT 1 FROM federated_deactivated WHERE rule_id = ?", (r['rule_key'],)
            ).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO federated_deactivated (rule_id, reason, deactivated_at) VALUES (?, ?, ?)",
                    (r['rule_key'], reason, now)
                )
                stats[f"DEACTIVATED_{r['rule_key']}"] = 1
                print(f"  🛑 AUTO-DEACTIVATED: {r['rule_key']} (TP={tp_rate:.2f} at {r['total']} verdicts)")
    
    db.commit()
    db.close()
    
    print(json.dumps(stats, indent=2))
    return stats["updated"]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: batch_revalidate.py --fetch | --update '<json>'")
        sys.exit(1)
    
    if sys.argv[1] == "--fetch":
        fetch_findings(int(sys.argv[2]) if len(sys.argv) > 2 else BATCH_SIZE)
    elif sys.argv[1] == "--update":
        update_db(sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read())
    else:
        print("Unknown command")
        sys.exit(1)
