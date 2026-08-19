# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""scripts/gsc_metrics_dashboard.py — live precision/noise dashboard.

Прозрачные метрики качества SAST (Precision / FP-rate / TP-rate по детекторам)
из единого источника правды — SQLite. Заменяет разовый PRECISION_REPORT.md
живой, пересчитываемой сводкой. Запуск::

    python3 scripts/gsc_metrics_dashboard.py          # human table
    python3 scripts/gsc_metrics_dashboard.py --json   # machine-readable
    python3 scripts/gsc_metrics_dashboard.py --days 14

Источники:
  - feedback (verdict tp/fp/fixed)       → precision per detector
  - fp_log (v33, structured FP events)   → noise ranking + actions
  - findings (status)                    → объём и доля revalidated
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gsc_db import GSCDatabase, TARGET_VERSION  # noqa: E402


def _precision(tp: int, fp: int) -> float | None:
    denom = tp + fp
    return round(tp / denom, 3) if denom else None


def collect(db: GSCDatabase, days: int | None) -> dict:
    """Собрать все метрики в один dict (для human и --json рендеров)."""
    # Общий объём
    total = db.count_findings()
    revalidated = db.count_revalidated()

    # Precision из feedback (verdict tp/fp/fixed)
    feedback_rows = db.query("""
        SELECT verdict, COUNT(*) AS n FROM feedback GROUP BY verdict
    """).fetchall()
    fb = {r["verdict"]: r["n"] for r in feedback_rows}
    tp = fb.get("tp", 0)
    fp = fb.get("fp", 0)
    fixed = fb.get("fixed", 0)

    # Fallback: findings.status (confirmed/fixed = TP, false_positive = FP).
    # Исторические вердикты, накопленные до появления feedback-таблицы.
    status_rows = db.query("""
        SELECT status, COUNT(*) AS n FROM findings
        WHERE status IN ('confirmed','fixed','false_positive')
        GROUP BY status
    """).fetchall()
    st = {r["status"]: r["n"] for r in status_rows}
    st_tp = st.get("confirmed", 0) + st.get("fixed", 0)
    st_fp = st.get("false_positive", 0)
    use_status = (tp + fp + fixed) == 0
    eff_tp = (tp + fixed) if not use_status else st_tp
    eff_fp = fp if not use_status else st_fp

    # TP-rate / blocking-ready по детекторам
    detector_rates = db.detector_tp_rates()

    # Noise ranking из fp_log
    noise = db.fp_stats(days=days)

    return {
        "schema_version": db._schema_version(),
        "target_version": TARGET_VERSION,
        "totals": {
            "findings": total,
            "revalidated": revalidated,
            "feedback_verdicts": tp + fp + fixed,
            "tp": tp,
            "fp": fp,
            "fixed": fixed,
            "precision": _precision(eff_tp, eff_fp),
            "precision_source": "status" if use_status else "feedback",
            "fp_events_logged": sum(r["fp_count"] for r in noise),
        },
        "detectors": detector_rates,
        "noise": noise,
    }


def render_human(d: dict) -> str:
    t = d["totals"]
    lines = []
    lines.append("═" * 72)
    lines.append("  GSC — Precision / Noise Dashboard")
    lines.append(f"  schema v{d['schema_version']} (target v{d['target_version']})")
    lines.append("═" * 72)
    lines.append(
        f"  Findings: {t['findings']}  |  revalidated: {t['revalidated']}"
        f"  |  feedback: {t['feedback_verdicts']} (tp={t['tp']} fp={t['fp']} fixed={t['fixed']})"
    )
    lines.append(
        f"  Precision ({t['precision_source']}): {t['precision'] if t['precision'] is not None else '—'}"
        f"  |  FP-events in fp_log: {t['fp_events_logged']}"
    )
    lines.append("─" * 72)

    lines.append("  Detector TP-rate (feedback):")
    lines.append(f"  {'rule':<10} {'verdicts':>8} {'tp':>5} {'fp':>5} {'fixed':>6} {'tp_rate':>8}  block")
    if not d["detectors"]:
        lines.append("    (no feedback verdicts yet)")
    for det in d["detectors"]:
        rate = f"{det['tp_rate']:.2f}" if det["tp_rate"] is not None else "  —"
        block = "READY" if det["blocking_ready"] else "·"
        lines.append(
            f"  {det['detector']:<10} {det['verdicts']:>8} {det['tp']:>5} "
            f"{det['fp']:>5} {det['fixed']:>6} {rate:>8}  {block}"
        )

    lines.append("─" * 72)
    lines.append("  Noise ranking (fp_log, noisiest first):")
    lines.append(f"  {'rule':<18} {'fp':>4}  reasons / actions")
    if not d["noise"]:
        lines.append("    (fp_log is empty — run triage to populate)")
    for n in d["noise"]:
        lines.append(
            f"  {str(n['rule_id']):<18} {n['fp_count']:>4}  "
            f"{n['reasons']} / {n['actions']}"
        )
    lines.append("═" * 72)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="GSC precision/noise dashboard")
    ap.add_argument("--days", type=int, default=None,
                    help="restrict fp_log noise to trailing window")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    args = ap.parse_args()

    db = GSCDatabase()
    try:
        d = collect(db, args.days)
    finally:
        db.close()

    if args.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print(render_human(d))


if __name__ == "__main__":
    main()
