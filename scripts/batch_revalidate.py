#!/usr/bin/env python3
"""
GSC Batch Revalidator v3 — agent-assisted mode.
Agent fetches findings, classifies them with LLM, then updates DB.
"""

import os, sys, json, sqlite3
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
BATCH_SIZE = 500


def fetch_findings(limit=BATCH_SIZE, with_context=False):
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
          AND f.project IS NOT NULL
          AND f.project != '.'
          AND f.project NOT LIKE '/home/%'
          AND f.project NOT LIKE '/opt/%'
          AND f.project NOT LIKE '/tmp/tmp%'
          AND f.project NOT LIKE '%benchmark%'
          AND f.project NOT LIKE '%pof_corpus%'
          AND COALESCE(f.file_path, '') NOT LIKE '/home/%'
          AND COALESCE(f.file_path, '') NOT LIKE '/opt/%'
          AND COALESCE(f.file_path, '') NOT LIKE '/tmp/tmp%'
          AND COALESCE(f.file_path, '') NOT LIKE '%benchmark%'
          AND COALESCE(f.file_path, '') NOT LIKE '%pof_corpus%'
        ORDER BY 
            CASE WHEN f.confidence_score BETWEEN 40 AND 70 THEN 0 ELSE 1 END,
            f.confidence_score DESC NULLS LAST,
            f.id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    
    # Preload bounty context if requested
    bounty_map = {}
    if with_context:
        bounty_map = _load_bounty_map(db)
    
    db.close()
    
    findings = []
    for r in rows:
        fdata = {
            "id": r["id"],
            "category": r["category"],
            "title": r["title"] or "",
            "project": r["project"] or "",
            "file_path": f"{r['file_path']}:{r['line_number']}" if r['file_path'] and r['line_number'] else (r["file_path"] or "?"),
            "detail": (r["detail"] or "")[:200],
        }
        # Attach bounty context if available
        if with_context:
            lang = _guess_lang(r["file_path"] or "")
            detail_text = (r["detail"] or "").lower()
            fdata["bounty_context"] = _find_relevant_examples(bounty_map, lang, detail_text)
        findings.append(fdata)
    
    print(json.dumps({"count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
    return len(findings)


def _load_bounty_map(db):
    """Load all bounty examples grouped by language."""
    try:
        examples = db.execute(
            "SELECT language, cwe_id, summary, severity, vulnerable_code, fixed_code FROM bounty_examples"
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    
    bmap = {}
    for ex in examples:
        lang = ex["language"] or "other"
        bmap.setdefault(lang, []).append({
            "cwe_id": ex["cwe_id"], "summary": ex["summary"][:120],
            "severity": ex["severity"],
            "vulnerable_code": (ex["vulnerable_code"] or "")[:400],
            "fixed_code": (ex["fixed_code"] or "")[:400],
        })
    return bmap


def _guess_lang(file_path: str) -> str:
    ext = os.path.splitext(file_path or "")[1].lower()
    return {
        '.py': 'python', '.js': 'javascript', '.ts': 'javascript',
        '.tsx': 'javascript', '.jsx': 'javascript', '.go': 'go',
        '.rs': 'rust', '.rb': 'ruby', '.php': 'php',
        '.java': 'java', '.cs': 'csharp', '.swift': 'swift',
    }.get(ext, 'other')


def _find_relevant_examples(bounty_map: dict, lang: str, detail: str) -> list:
    """Find 2 most relevant bounty examples for a finding."""
    candidates = bounty_map.get(lang, []) + bounty_map.get("other", [])
    if not candidates:
        return []
    
    # Score: CWE match in detail > severity match > random
    scored = []
    for ex in candidates:
        score = 0
        if ex["cwe_id"] and ex["cwe_id"].lower() in detail:
            score += 10
        if ex["severity"] in ("CRITICAL", "HIGH"):
            score += 2
        if any(kw in detail for kw in ex["summary"].lower().split()[:5]):
            score += 3
        scored.append((score, ex))
    
    scored.sort(key=lambda x: -x[0])
    return [{"cwe_id": e["cwe_id"], "summary": e["summary"],
             "severity": e["severity"],
             "vulnerable_code": e["vulnerable_code"][:300],
             "fixed_code": e["fixed_code"][:300]}
            for _, e in scored[:2]]


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
        print("Usage: batch_revalidate.py --fetch [N] [--context] | --update '<json>'")
        sys.exit(1)
    
    if sys.argv[1] == "--fetch":
        with_context = "--context" in sys.argv
        # Extract limit: --fetch N or --fetch --context N
        limit = BATCH_SIZE
        for i, a in enumerate(sys.argv):
            if a == "--fetch" and i+1 < len(sys.argv) and sys.argv[i+1].isdigit():
                limit = int(sys.argv[i+1])
        fetch_findings(limit, with_context=with_context)
    elif sys.argv[1] == "--update":
        update_db(sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read())
    else:
        print("Unknown command")
        sys.exit(1)
