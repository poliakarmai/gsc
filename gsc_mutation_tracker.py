#!/usr/bin/env python3
"""
GSC Temporal Mutation Tracker v1.0.

Detects resurgence of 'fixed' vulnerability patterns in mutated form.
"If you fixed it once, it shouldn't come back in a copy-pasted variant."

Uses normalized fingerprinting: strip identifiers, keep structure.
Compares against DB of previously-fixed findings.
Alerts when similarity is in [0.5, 0.95] range (mutation, not duplicate).

Usage:
  python3 gsc_mutation_tracker.py check <finding_id>
  python3 gsc_mutation_tracker.py --project gsc --scan
  python3 gsc_mutation_tracker.py migrate   # run DB migration
"""

import hashlib, os, sys, sqlite3, json
from pathlib import Path
from difflib import SequenceMatcher
from datetime import datetime, timezone, timedelta

DB_PATH = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))
MUTATION_SIM_MIN = 0.50
MUTATION_SIM_MAX = 0.95
LOOKBACK_DAYS = 90


def fingerprint(snippet: str) -> str:
    """Normalize snippet: strip identifiers, keep structure."""
    import re
    norm = re.sub(r'"[^"]*"', '"STR"', snippet)
    norm = re.sub(r"'[^']*'", "'STR'", norm)
    norm = re.sub(r'\b[a-z_]\w*(?=\s*=)', "VAR", norm)
    norm = re.sub(r'\b\d+\b', "N", norm)
    norm = re.sub(r'\s+', " ", norm).strip().lower()
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


def run_migration():
    """Add mutation tracking columns to findings table."""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN pattern_fingerprint TEXT")
    except sqlite3.OperationalError:
        pass  # already exists
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN resolved_at TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN mutation_parent TEXT")
    except sqlite3.OperationalError:
        pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS mutation_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mutated_finding_key TEXT NOT NULL,
            parent_finding_key TEXT NOT NULL,
            similarity REAL NOT NULL,
            detected_at TEXT DEFAULT (datetime('now')),
            UNIQUE(mutated_finding_key, parent_finding_key)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(pattern_fingerprint)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_resolved ON findings(resolved_at)")
    conn.commit()
    conn.close()
    print("✅ Migration complete — mutation tracking ready")


def check_finding(finding: dict) -> dict | None:
    """Check if a finding is a mutation of a previously-fixed one."""
    snippet = finding.get("detail", finding.get("snippet", ""))
    if not snippet:
        snippet = f"{finding.get('title','')} {finding.get('file_path','')}"

    fp = fingerprint(snippet)
    finding["pattern_fingerprint"] = fp

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    cutoff = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).isoformat()
    rows = conn.execute("""
        SELECT id, title, file_path, line_number, detail, resolved_at, pattern_fingerprint
        FROM findings
        WHERE pattern_fingerprint IS NOT NULL
          AND substr(pattern_fingerprint, 1, 8) = ?
          AND resolved_at IS NOT NULL
          AND resolved_at > ?
        ORDER BY resolved_at DESC
        LIMIT 10
    """, (fp[:8], cutoff)).fetchall()
    conn.close()

    for row in rows:
        old_snippet = row["detail"] or ""
        if not old_snippet:
            continue

        sim = SequenceMatcher(None, snippet.lower(), old_snippet.lower()).ratio()
        if MUTATION_SIM_MIN < sim < MUTATION_SIM_MAX:
            conn2 = sqlite3.connect(str(DB_PATH))
            finding_key = hashlib.sha256(
                f"{finding.get('file_path','')}+{finding.get('line_number',0)}+{snippet[:40]}".encode()
            ).hexdigest()[:12]
            parent_key = hashlib.sha256(
                f"{row['file_path']}+{row['line_number']}+{old_snippet[:40]}".encode()
            ).hexdigest()[:12]

            try:
                conn2.execute(
                    "INSERT OR IGNORE INTO mutation_alerts "
                    "(mutated_finding_key, parent_finding_key, similarity) VALUES (?,?,?)",
                    (finding_key, parent_key, round(sim, 2))
                )
                conn2.commit()
            except Exception:
                pass
            conn2.close()

            return {
                "mutation_detected": True,
                "parent_file": row["file_path"],
                "parent_line": row["line_number"],
                "resolved_at": row["resolved_at"] or "unknown",
                "similarity": round(sim, 2),
                "mutated_key": finding_key,
                "parent_key": parent_key,
            }

    return None


def scan_project(project: str, limit: int = 100):
    """Batch-check all findings in a project for mutations."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM findings
        WHERE project = ? AND status = 'open'
        ORDER BY CASE category WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END
        LIMIT ?
    """, (project, limit)).fetchall()
    conn.close()

    alerts = []
    for r in rows:
        finding = dict(r)
        result = check_finding(finding)
        if result:
            alerts.append({
                "finding_id": r["id"],
                "title": r["title"],
                "file": r["file_path"],
                "line": r["line_number"],
                **result,
            })

    return alerts


# ── CLI ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GSC Temporal Mutation Tracker")
    sub = p.add_subparsers(dest="command")

    migrate = sub.add_parser("migrate", help="Run DB migration for mutation tracking")
    check = sub.add_parser("check", help="Check if finding is a mutation")
    check.add_argument("finding_id", type=int)
    scan = sub.add_parser("scan", help="Batch scan project for mutations")
    scan.add_argument("--project", required=True)
    scan.add_argument("--limit", type=int, default=100)
    list_cmd = sub.add_parser("list", help="List recent mutation alerts")
    list_cmd.add_argument("--days", type=int, default=30)
    show = sub.add_parser("show", help="Show mutation details")
    show.add_argument("finding_key")

    args = p.parse_args()

    if args.command == "migrate":
        run_migration()

    elif args.command == "check":
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        r = conn.execute("SELECT * FROM findings WHERE id=?", (args.finding_id,)).fetchone()
        conn.close()
        if not r:
            print(f"Finding {args.finding_id} not found")
            sys.exit(1)
        result = check_finding(dict(r))
        if result:
            print(f"🔴 MUTATION DETECTED (similarity: {result['similarity']:.0%})")
            print(f"   Original: {result['parent_file']}:{result['parent_line']}")
            print(f"   Fixed at: {result['resolved_at']}")
        else:
            print("✅ No mutation detected")

    elif args.command == "scan":
        alerts = scan_project(args.project, args.limit)
        if not alerts:
            print(f"No mutations found in {args.project}")
        for a in alerts:
            print(f"🔴 [{a['finding_id']}] {a['title'][:60]}")
            print(f"   Similarity: {a['similarity']:.0%} — originally fixed at {a['resolved_at']}")
            print(f"   Parent: {a['parent_file']}:{a['parent_line']}")
        print(f"\n📊 {len(alerts)} mutations found")

    elif args.command == "list":
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
        rows = conn.execute(
            "SELECT * FROM mutation_alerts WHERE detected_at > ? ORDER BY detected_at DESC LIMIT 50",
            (cutoff,)
        ).fetchall()
        conn.close()
        if not rows:
            print(f"No mutation alerts in last {args.days} days")
        for r in rows:
            print(f"  {r['mutated_finding_key']} ← {r['parent_finding_key']} "
                  f"({r['similarity']:.0%} sim) {r['detected_at']}")

    elif args.command == "show":
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        r = conn.execute(
            "SELECT * FROM mutation_alerts WHERE mutated_finding_key=? OR parent_finding_key=?",
            (args.finding_key, args.finding_key)
        ).fetchone()
        conn.close()
        if r:
            print(json.dumps(dict(r), indent=2, default=str))
        else:
            print(f"No mutation data for {args.finding_key}")

    else:
        p.print_help()
