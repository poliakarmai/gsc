#!/usr/bin/env python3
"""GSC Metrics — precision/recall/effectiveness dashboard."""
import sys, os, sqlite3

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

def calc_metrics(project: str = None):
    if not os.path.exists(DB):
        print("No database"); return

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    where = f"WHERE project = '{project}'" if project else "WHERE 1=1"
    where_p = ""

    # Overall stats
    total = conn.execute(f"SELECT COUNT(*) FROM findings {where}").fetchone()[0]
    tp = conn.execute(f"SELECT COUNT(*) FROM findings {where} AND status='confirmed'").fetchone()[0]
    fp = conn.execute(f"SELECT COUNT(*) FROM findings {where} AND status='false_positive'").fetchone()[0]
    open_f = conn.execute(f"SELECT COUNT(*) FROM findings {where} AND status='open'").fetchone()[0]
    baseline = conn.execute(f"SELECT COUNT(*) FROM findings {where} AND status='baseline'").fetchone()[0]

    print("=" * 55)
    print(f"GSC Precision/Recall {'— ' + project if project else ''}")
    print("=" * 55)
    print(f"\n📊 Findings:")
    print(f"  Total:       {total}")
    print(f"  Triaged:     {tp + fp} ({100*(tp+fp)//max(1,total)}%)")
    print(f"  Confirmed:   {tp}")
    print(f"  False pos:   {fp}")
    print(f"  Still open:  {open_f}")
    print(f"  Baseline:    {baseline}")
    if tp + fp > 0:
        print(f"  Precision:   {tp/(tp+fp)*100:.1f}%")

    # Per-pattern stats (top performers + worst)
    print(f"\n🔝 Top patterns (by precision):")
    rows = conn.execute(f"""
        SELECT p.title, p.true_positive_count as tp, p.false_positive_count as fp,
               p.effectiveness, p.active, p.language
        FROM patterns p
        WHERE p.false_positive_count + p.true_positive_count > 0
        ORDER BY p.effectiveness DESC LIMIT 5
    """).fetchall()
    for r in rows:
        lang = f" [{r['language']}]" if r['language'] else ""
        status = "🟢" if r['active'] else "🔴"
        print(f"  {status} {r['tp']}/{r['tp']+r['fp']} ({r['effectiveness']*100:.0f}%) {r['title'][:50]}{lang}")

    print(f"\n⚠️  Patterns at risk (FP-heavy):")
    rows = conn.execute(f"""
        SELECT p.title, p.true_positive_count as tp, p.false_positive_count as fp,
               p.effectiveness, p.active, p.language
        FROM patterns p
        WHERE p.false_positive_count > 0 AND p.active = 1
        ORDER BY p.effectiveness ASC LIMIT 5
    """).fetchall()
    for r in rows:
        lang = f" [{r['language']}]" if r['language'] else ""
        deact = " 🔜 DEACTIVATE" if r['effectiveness'] and r['effectiveness'] < 0.3 and r['tp']+r['fp'] >= 10 else ""
        print(f"  {r['tp']}/{r['tp']+r['fp']} ({r['effectiveness']*100:.0f}%) {r['title'][:50]}{lang}{deact}")

    # Per-language stats
    print(f"\n🌐 Per-language:")
    rows = conn.execute(f"""
        SELECT p.language, COUNT(*) as patterns,
               SUM(p.true_positive_count) as tp, SUM(p.false_positive_count) as fp
        FROM patterns p
        WHERE p.language IS NOT NULL
        GROUP BY p.language
        ORDER BY SUM(p.true_positive_count) + SUM(p.false_positive_count) DESC
    """).fetchall()
    for r in rows:
        prec = r['tp']/(r['tp']+r['fp'])*100 if r['tp']+r['fp'] > 0 else 0
        print(f"  {r['language']:<12} {r['patterns']:>3} patterns  {r['tp']}TP/{r['fp']}FP  {prec:.0f}%")

    # Deactivated patterns
    dead = conn.execute("SELECT COUNT(*) FROM patterns WHERE active=0").fetchone()[0]
    if dead:
        print(f"\n💀 Deactivated: {dead} patterns")
        rows = conn.execute("SELECT title, effectiveness FROM patterns WHERE active=0 ORDER BY effectiveness LIMIT 3").fetchall()
        for r in rows:
            print(f"  ❌ {r['title'][:60]} ({r['effectiveness']*100:.0f}%)")

    conn.close()


if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else None
    calc_metrics(project)
