#!/usr/bin/env python3
"""
GSC Pattern Marketplace — export/import patterns as YAML.
Community-sharing ready: export your best patterns, import from others.
"""
import sys, os, json, sqlite3, yaml
from pathlib import Path

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

def export_patterns(output: str, min_effectiveness: float = 0.5, language: str = None):
    """Export high-quality patterns to YAML file."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    where = "WHERE (true_positive_count + false_positive_count) > 0"
    if min_effectiveness > 0:
        where += f" AND CAST(true_positive_count AS REAL) / NULLIF(true_positive_count + false_positive_count, 0) >= {min_effectiveness}"
    if language:
        where += f" AND language = '{language}'"

    rows = conn.execute("SELECT * FROM patterns " + where + " ORDER BY effectiveness DESC"  # gsc:ignore — where is internal var).fetchall()
    conn.close()

    patterns = []
    for r in rows:
        p = {
            "title": r['title'],
            "category": r.get('category', 'MEDIUM'),
            "echelon": r.get('echelon', 1),
            "pattern_type": r.get('pattern_type', 'regex'),
            "search_pattern": r.get('search_pattern', ''),
            "description": r.get('description', ''),
            "language": r.get('language', ''),
            "effectiveness": r.get('effectiveness', 0),
            "tp_count": r.get('true_positive_count', 0),
            "fp_count": r.get('false_positive_count', 0),
            "source": "gsc-marketplace",
            "exported_at": __import__('datetime').datetime.utcnow().isoformat(),
        }
        patterns.append(p)

    with open(output, 'w') as f:
        yaml.dump({"gsc_patterns": patterns, "meta": {"version": 1, "count": len(patterns), "min_effectiveness": min_effectiveness}}, f, allow_unicode=True, sort_keys=False)

    print(f"✅ Exported {len(patterns)} patterns → {output}")


def import_patterns(input_file: str, force: bool = False):
    """Import patterns from YAML file."""
    with open(input_file) as f:
        data = yaml.safe_load(f)

    patterns = data.get("gsc_patterns", [])
    if not patterns:
        print("No patterns found in file"); return

    conn = sqlite3.connect(DB)
    imported = 0
    for p in patterns:
        # Check if already exists
        existing = conn.execute("SELECT id FROM patterns WHERE title=?", (p['title'],)).fetchone()
        if existing and not force:
            continue

        conn.execute("""
            INSERT OR REPLACE INTO patterns
            (project, echelon, category, title, pattern_type, search_pattern, description, language, effectiveness, true_positive_count, false_positive_count, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            '*', p.get('echelon', 1), p.get('category', 'MEDIUM'), p['title'],
            p.get('pattern_type', 'regex'), p.get('search_pattern', ''),
            p.get('description', ''), p.get('language', ''),
            p.get('effectiveness', 0), p.get('tp_count', 0), p.get('fp_count', 0),
        ))
        imported += 1

    conn.commit()
    conn.close()
    print(f"✅ Imported {imported} patterns from {input_file}")


def list_marketplace():
    """Show all exportable patterns with stats."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT language, COUNT(*) as cnt,
               ROUND(AVG(effectiveness)*100,1) as avg_eff,
               SUM(true_positive_count) as tp, SUM(false_positive_count) as fp
        FROM patterns WHERE (true_positive_count + false_positive_count) > 0 AND language IS NOT NULL
        GROUP BY language ORDER BY cnt DESC
    """).fetchall()
    conn.close()

    print("Pattern Marketplace — exportable patterns:\n")
    print(f"  {'Language':<12} {'Count':>5} {'Avg Eff':>8} {'TP':>5} {'FP':>5}")
    print(f"  {'-'*40}")
    for r in rows:
        print(f"  {r['language']:<12} {r['cnt']:>5} {r['avg_eff']:>7}% {r['tp']:>5} {r['fp']:>5}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_marketplace()
    elif sys.argv[1] == "export" and len(sys.argv) >= 3:
        lang = sys.argv[3] if len(sys.argv) > 3 else None
        export_patterns(sys.argv[2], language=lang)
    elif sys.argv[1] == "import" and len(sys.argv) >= 3:
        force = "--force" in sys.argv
        import_patterns(sys.argv[2], force)
    else:
        print("Usage:")
        print("  gsc marketplace              — list exportable patterns")
        print("  gsc marketplace export <file> [language]  — export to YAML")
        print("  gsc marketplace import <file> [--force]   — import from YAML")
