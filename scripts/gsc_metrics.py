#!/usr/bin/env python3
"""
GSC Metrics v2.0 — точные метрики precision/recall/effectiveness.
Использует revalidation_verdict для подсчёта TP/FP.

Исправления v2.0:
- effectiveness = TP/(TP+FP) только если есть данные, иначе NULL
- precision по revalidation_verdict, не по status
- статистика по детекторам (rule_id)
- тренд precision за последние N дней
"""
import sys, os, sqlite3, json
from datetime import datetime, timedelta

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")


def calc_metrics(project: str = None):
    if not os.path.exists(DB):
        print("No database"); return

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    where_f = "WHERE 1=1"
    where_p = ""
    if project:
        where_f = f"WHERE f.project = '{project}'"

    # ── Overall stats ──
    total = conn.execute(f"SELECT COUNT(*) FROM findings f {where_f}").fetchone()[0]

    # TP = revalidation_verdict 'true-positive' OR status 'confirmed'/'fixed'
    tp = conn.execute(f"""
        SELECT COUNT(*) FROM findings f {where_f}
        AND (f.revalidation_verdict = 'true-positive'
             OR f.status IN ('confirmed', 'fixed'))
    """).fetchone()[0]

    fp = conn.execute(f"""
        SELECT COUNT(*) FROM findings f {where_f}
        AND (f.revalidation_verdict = 'false-positive'
             OR f.status = 'false_positive')
    """).fetchone()[0]

    open_f = conn.execute(f"""
        SELECT COUNT(*) FROM findings f {where_f}
        AND f.status = 'open'
        AND f.revalidation_verdict IS NULL
    """).fetchone()[0]

    reval_total = conn.execute(f"""
        SELECT COUNT(*) FROM findings f {where_f}
        AND f.revalidation_verdict IS NOT NULL
    """).fetchone()[0]

    print("=" * 60)
    print(f"GSC Precision/Recall v2.0{' — ' + project if project else ''}")
    print("=" * 60)
    print(f"\n📊 Findings:")
    print(f"  Total:         {total}")
    print(f"  Revalidated:   {reval_total} ({100*reval_total//max(1,total)}%)")
    print(f"  Confirmed TP:  {tp}")
    print(f"  False pos:     {fp}")
    print(f"  Still open:    {open_f}")
    if tp + fp > 0:
        prec = tp / (tp + fp) * 100
        print(f"  Precision:     {prec:.1f}% ({tp} TP / {tp+fp} rated)")
    else:
        print(f"  Precision:     N/A (no revalidated findings)")

    # ── Per-detector stats ──
    print(f"\n🔬 Per Detector (revalidation-based):")
    det_rows = conn.execute(f"""
        SELECT 
            COALESCE(f.pattern_title, 'unknown') as detector,
            f.category,
            COUNT(*) as total_finds,
            SUM(CASE WHEN f.revalidation_verdict='true-positive'
                      OR f.status IN ('confirmed','fixed') THEN 1 ELSE 0 END) as tp,
            SUM(CASE WHEN f.revalidation_verdict='false-positive'
                      OR f.status='false_positive' THEN 1 ELSE 0 END) as fp,
            SUM(CASE WHEN f.revalidation_verdict IS NULL
                      AND f.status='open' THEN 1 ELSE 0 END) as unrated
        FROM findings f {where_f}
        GROUP BY f.pattern_title
        HAVING total_finds >= 5
        ORDER BY total_finds DESC
        LIMIT 15
    """).fetchall()

    for r in det_rows:
        rated = r['tp'] + r['fp']
        prec = f"{r['tp']/rated*100:.0f}%" if rated > 0 else "N/A"
        bar = _bar(r['tp'], rated, 10) if rated > 0 else "─" * 10
        print(f"  [{r['category'][:4]:4s}] {prec:>5s} {bar} {r['detector'][:45]:45s} "
              f"({r['total_finds']} total, {r['unrated']} unrated)")

    # ── Worst patterns (FP-heavy, candidates for deactivation) ──
    print(f"\n⚠️  Patterns at risk (FP-heavy, active, ≥10 rated):")
    worst = conn.execute(f"""
        SELECT p.title, p.category,
               SUM(CASE WHEN f.revalidation_verdict='true-positive'
                         OR f.status IN ('confirmed','fixed') THEN 1 ELSE 0 END) as tp,
               SUM(CASE WHEN f.revalidation_verdict='false-positive'
                         OR f.status='false_positive' THEN 1 ELSE 0 END) as fp
        FROM patterns p
        LEFT JOIN findings f ON f.pattern_title = p.title
        WHERE p.active = 1
        GROUP BY p.id
        HAVING (tp + fp) >= 10
        ORDER BY CAST(tp AS REAL) / MAX(tp + fp, 1) ASC
        LIMIT 10
    """).fetchall()

    if worst:
        for r in worst:
            tp_v, fp_v = r['tp'] or 0, r['fp'] or 0
            eff = tp_v / (tp_v + fp_v) * 100 if (tp_v + fp_v) > 0 else 0
            deact = " 🔜 DEACTIVATE" if eff < 30 else ""
            print(f"  [{r['category']}] {eff:.0f}% TP — {r['title'][:55]}{deact}")
    else:
        print("  (none — need ≥10 revalidated findings per pattern)")

    # ── Auto-deactivation log ──
    log_file = os.path.expanduser("~/.hermes/state/gsc_deactivation_log.json")
    if os.path.exists(log_file):
        try:
            log = json.loads(open(log_file).read())
            recent = [e for e in log if e.get("action") == "deactivated"]
            if recent:
                print(f"\n💀 Recent deactivations ({len(recent)}):")
                for e in recent[-5:]:
                    print(f"  ❌ {e['title'][:55]} — eff={e['efficiency']*100:.0f}% "
                          f"({e['tp']}TP/{e['fp']}FP)")
        except Exception:
            pass

    # ── Precision trend ──
    stats_file = os.path.expanduser("~/.hermes/state/gsc_self_learn_stats.json")
    if os.path.exists(stats_file):
        try:
            stats = json.loads(open(stats_file).read())
            runs = stats.get("runs", [])
            if runs:
                print(f"\n📈 Precision trend (last {min(10, len(runs))} cycles):")
                for run in runs[-10:]:
                    rv = run.get("revalidated", 0)
                    tp_r = run.get("tp", 0)
                    fp_r = run.get("fp_llm", 0)
                    prec_str = f"{tp_r/(tp_r+fp_r)*100:.0f}%" if (tp_r + fp_r) > 0 else "N/A"
                    print(f"  {run['date']}: {run['findings']} finds, "
                          f"rv={rv}, prec={prec_str}")
        except Exception:
            pass

    # ── Active/deactivated pattern counts ──
    active = conn.execute("SELECT COUNT(*) FROM patterns WHERE active=1").fetchone()[0]
    dead = conn.execute("SELECT COUNT(*) FROM patterns WHERE active=0").fetchone()[0]
    null_eff = conn.execute(
        "SELECT COUNT(*) FROM patterns WHERE active=1 AND effectiveness IS NULL"
    ).fetchone()[0]
    print(f"\n📋 Patterns: {active} active ({null_eff} unrated), {dead} deactivated")

    conn.close()


def _bar(tp: int, total: int, width: int = 10) -> str:
    """Mini bar chart for precision."""
    if total == 0:
        return "─" * width
    ratio = tp / total
    filled = round(ratio * width)
    return "█" * filled + "░" * (width - filled)


if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else None
    calc_metrics(project)
