#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""GSC Ground-Truth Trainer — бесплатное обучение детекторов (0 LLM).

Считает per-detector precision на ground-truth источниках:
  - calibration (13 проектов: 9 clean + 4 vuln) — calibration/calibration_dataset.json
  - benchmark   (100 проектов: 90 clean + 10 recall/vuln) — benchmark/precision_report_batch*.json
  clean-проекты: находки = FP (чистый, протестированный код — vuln не ожидаются)
  vuln-проекты:  находки = TP-сигнал (заведомо уязвимый код)

Правило FP-генератора (консервативное, чтобы не уронить recall):
  fp_clean >= MIN_FP  AND  tp_vuln == 0
  → детектор шумит в чистом коде и не ловит ни одну заведомую уязвимость.

Детерминированная замена LLM-revalidate: источник вердикта — размеченный
ground-truth, не платный LLM.

Использование:
  python3 scripts/gsc_ground_truth_train.py              # отчёт (calibration + benchmark)
  python3 scripts/gsc_ground_truth_train.py --apply       # деактивировать FP-генераторы
  python3 scripts/gsc_ground_truth_train.py --json        # machine-readable
  python3 scripts/gsc_ground_truth_train.py --source calibration   # только calibration
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

GSC_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"
DATASET_PATH = GSC_ROOT / "calibration" / "calibration_dataset.json"

# Движковые детекторы (rule_id формируется как "<ID>-<subtype>", паттерны не в patterns).
# Для них деактивация = правка severity/regex в gsc_core/gsc_detectors/gs037_python.py.
ENGINE_PREFIXES = ("GS037-", "YAML-", "GS0")

MIN_FP_DEFAULT = 20

# Язык по префиксу rule_id. Нужен, чтобы отличать «0 TP из-за отсутствия vuln-проектов
# этого языка» от «0 TP из-за плохого детектора».
LANG_BY_PREFIX = {
    "GS037-": "python", "GS038-": "go", "GS036-": "javascript",
    "GS035-": "php", "GS039-": "ruby", "GS032-": "ai",
    "GS034-": "supply_chain", "YAML-": "yaml",
}

# Языки, у которых в benchmark recall-сете есть заведомо уязвимые проекты.
# Только для них tp_vuln==0 является информативным сигналом FP.
COVERED_LANGS = {"python", "javascript", "php"}


def rule_lang(rule_id: str) -> str:
    for prefix, lang in LANG_BY_PREFIX.items():
        if rule_id.startswith(prefix):
            return lang
    return "unknown"


def load_calibration() -> dict[str, str]:
    """name -> category (clean|vulnerable) из calibration_dataset.json."""
    if not DATASET_PATH.exists():
        return {}
    data = json.loads(DATASET_PATH.read_text())
    return {p["name"]: p.get("category", "clean") for p in data.get("projects", [])}


def load_benchmark() -> dict[str, str]:
    """name -> clean|vulnerable из precision_report_batch*.json (recall=True → vuln)."""
    out: dict[str, str] = {}
    for f in sorted(GSC_ROOT.glob("benchmark/precision_report_batch*.json")):
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue
        for p in data.get("projects", []):
            n = p.get("name")
            if n:
                out[n] = "vulnerable" if p.get("recall") else "clean"
    return out


def load_ground_truth(source: str) -> dict[str, str]:
    """Объединённый ground-truth name -> clean|vulnerable."""
    gt: dict[str, str] = {}
    if source in ("calibration", "all"):
        gt.update(load_calibration())
    if source in ("benchmark", "all"):
        gt.update(load_benchmark())
    return gt


def classify_project(project: str, ground_truth: dict[str, str]) -> str | None:
    """Вернуть 'clean' | 'vuln' | None по имени проекта в ground-truth."""
    plow = (project or "").lower()
    for name, cat in ground_truth.items():
        if name.lower() in plow:
            return "vuln" if cat == "vulnerable" else "clean"
    return None


def compute_precision(db: sqlite3.Connection, ground_truth: dict[str, str]) -> tuple[dict, int]:
    fp = defaultdict(int)
    tp = defaultdict(int)
    seen = 0
    rows = db.execute(
        "SELECT rule_id, project FROM findings "
        "WHERE project LIKE '%gsc-calibration%' OR project LIKE '%real_world_100%'"
    ).fetchall()
    for rid, proj in rows:
        cls = classify_project(proj, ground_truth)
        if cls is None:
            continue
        seen += 1
        if cls == "vuln":
            tp[rid] += 1
        else:
            fp[rid] += 1

    out = {}
    for rid in set(fp) | set(tp):
        f, t = fp[rid], tp[rid]
        total = f + t
        prec = (t / total * 100.0) if total else 0.0
        out[rid] = {
            "fp_clean": f, "tp_vuln": t, "total": total,
            "precision_pct": round(prec, 1),
        }
    return out, seen


def apply_deactivation(db: sqlite3.Connection, results: dict, min_fp: int) -> tuple[list, list]:
    """Деактивировать registry-паттерны для FP-генераторов; движковые — отметить."""
    deactivated: list[str] = []
    engine_flagged: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    for rid, r in results.items():
        if not (r["fp_clean"] >= min_fp and r["tp_vuln"] == 0):
            continue
        if rid.startswith(ENGINE_PREFIXES):
            engine_flagged.append(rid)
            continue
        title_rows = db.execute(
            "SELECT DISTINCT pattern_title FROM findings WHERE rule_id=? AND pattern_title IS NOT NULL LIMIT 1",
            (rid,),
        ).fetchall()
        title = title_rows[0][0] if title_rows else None
        if not title:
            engine_flagged.append(rid)
            continue
        core = title.split("(")[0].strip()
        pat = db.execute(
            "UPDATE patterns SET active=0, deactivated_at=? WHERE title LIKE ? AND active=1",
            (now, f"%{core}%"),
        )
        try:
            db.execute(
                "INSERT INTO fp_log (finding_key, rule_id, reason, action_taken, source, actor, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (f"gt-{rid}", rid,
                 f"ground-truth: {r['fp_clean']} FP clean / 0 TP vuln",
                 "auto-deactivate", "ground_truth_trainer", "system", now),
            )
        except Exception:
            pass
        if pat.rowcount > 0:
            deactivated.append(rid)

    db.commit()
    return deactivated, engine_flagged


def main() -> int:
    ap = argparse.ArgumentParser(description="GSC ground-truth trainer (0 LLM)")
    ap.add_argument("--apply", action="store_true", help="деактивировать FP-генераторы")
    ap.add_argument("--min-fp", type=int, default=MIN_FP_DEFAULT, help=f"порог FP (default {MIN_FP_DEFAULT})")
    ap.add_argument("--source", choices=["calibration", "benchmark", "all"], default="all")
    ap.add_argument("--json", action="store_true", help="вывод JSON")
    args = ap.parse_args()

    ground_truth = load_ground_truth(args.source)
    if not ground_truth:
        print("❌ ground-truth не найден")
        return 2

    db = sqlite3.connect(str(DB_PATH))
    results, seen = compute_precision(db, ground_truth)

    if args.json:
        print(json.dumps({"source": args.source, "projects": len(ground_truth),
                          "scanned_findings": seen, "detectors": results},
                         ensure_ascii=False, indent=2))
        db.close()
        return 0

    print("=" * 72)
    print(f"GSC GROUND-TRUTH TRAINER — 0 LLM | source={args.source} | "
          f"проектов={len(ground_truth)} | findings={seen}")
    print("=" * 72)
    rows = sorted(results.items(), key=lambda kv: -kv[1]["fp_clean"])
    print(f'{"rule_id":<32} {"FP(clean)":>9} {"TP(vuln)":>9} {"prec%":>7}  вердикт')
    for rid, r in rows:
        if r["fp_clean"] == 0 and r["tp_vuln"] == 0:
            continue
        if r["fp_clean"] >= args.min_fp and r["tp_vuln"] == 0:
            v = "🔴 FP-GEN" if rule_lang(rid) in COVERED_LANGS else "🟠 нет покрытия"
        elif r["tp_vuln"] > 0:
            v = "🟢 TP"
        else:
            v = "⚪ шум"
        print(f"{rid:<32} {r['fp_clean']:>9} {r['tp_vuln']:>9} {r['precision_pct']:>7}  {v}")

    fg = [rid for rid, r in results.items()
          if r["fp_clean"] >= args.min_fp and r["tp_vuln"] == 0
          and rule_lang(rid) in COVERED_LANGS]
    uncovered = [rid for rid, r in results.items()
                 if r["fp_clean"] >= args.min_fp and r["tp_vuln"] == 0
                 and rule_lang(rid) not in COVERED_LANGS]
    print()
    print(f"🔴 FP-генераторы НАДЁЖНЫЕ (язык покрыт, fp>={args.min_fp}, tp=0): {len(fg)}")
    for rid in fg:
        print(f"   - {rid}: {results[rid]['fp_clean']} FP в clean, 0 TP в vuln")
    if uncovered:
        print(f"🟠 0 TP, но язык НЕ покрыт vuln-проектами (не деактивируем): {len(uncovered)}")
        for rid in uncovered:
            print(f"   - {rid}: {results[rid]['fp_clean']} FP (lang={rule_lang(rid)}, нет vuln-проектов)")

    if args.apply and fg:
        deactivated, engine_flagged = apply_deactivation(db, results, args.min_fp)
        print()
        print(f"✅ Деактивировано (registry): {len(deactivated)} — {deactivated}")
        if engine_flagged:
            print(f"⚠️  Требуют правки движка (код): {engine_flagged}")
        print("   fp_log записан, commit выполнен.")
    elif args.apply:
        print()
        print("✅ FP-генераторов нет — деактивировать нечего.")

    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
