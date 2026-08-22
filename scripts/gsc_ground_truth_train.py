#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""GSC Ground-Truth Trainer — бесплатное обучение детекторов (0 LLM).

Считает per-detector precision на calibration-сете (calibration/calibration_dataset.json):
  - clean-проекты (9): находки = FP (чистый, хорошо протестированный код — vuln не ожидаются)
  - vuln-проекты (4): находки = TP-сигнал (заведомо уязвимый код)

Правило FP-генератора (консервативное, чтобы не уронить recall):
  fp_clean >= MIN_FP  AND  tp_vuln == 0
  → детектор шумит в чистом коде и не ловит ни одну заведомую уязвимость.

Это детерминированная замена LLM-revalidate: источник вердикта — размеченный
ground-truth, а не платный LLM.

Использование:
  python3 scripts/gsc_ground_truth_train.py            # отчёт по всем детекторам
  python3 scripts/gsc_ground_truth_train.py --apply     # деактивировать FP-генераторы
  python3 scripts/gsc_ground_truth_train.py --json      # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

GSC_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"
DATASET_PATH = GSC_ROOT / "calibration" / "calibration_dataset.json"

# Движковые детекторы (rule_id формируется как "<ID>-<subtype>", паттерны не в patterns).
# Для них деактивация = правка severity в gsc_core/gsc_detectors/gs037_python.py.
ENGINE_PREFIXES = ("GS037-", "YAML-", "GS0")

MIN_FP_DEFAULT = 20


def load_dataset() -> dict[str, str]:
    """name -> category (clean|vulnerable) из calibration_dataset.json."""
    if not DATASET_PATH.exists():
        return {}
    data = json.loads(DATASET_PATH.read_text())
    return {p["name"]: p.get("category", "clean") for p in data.get("projects", [])}


def classify_project(project: str, dataset: dict[str, str]) -> str | None:
    """Вернуть 'clean' | 'vuln' | None для пути проекта из /tmp/gsc-calibration/."""
    if "/tmp/gsc-calibration/" not in project and "gsc-calibration/" not in project:
        return None
    for name, cat in dataset.items():
        if name.lower() in project.lower():
            return "vuln" if cat == "vulnerable" else "clean"
    return None


def compute_precision(db: sqlite3.Connection, dataset: dict[str, str]) -> dict[str, dict]:
    fp = defaultdict(int)
    tp = defaultdict(int)
    seen = 0
    for rid, proj in db.execute(
        "SELECT rule_id, project FROM findings WHERE project LIKE '%gsc-calibration%'"
    ):
        cls = classify_project(proj or "", dataset)
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


def apply_deactivation(db: sqlite3.Connection, results: dict[str, dict]) -> list[str]:
    """Деактивировать registry-паттерны (по pattern_title маппингу) для FP-генераторов.

    Возвращает список rule_id, которые деактивированы (registry) или требуют
    правки движка (GS037-*).
    """
    from datetime import datetime, timezone

    deactivated = []
    engine_flagged = []
    now = datetime.now(timezone.utc).isoformat()

    for rid, r in results.items():
        if not r["is_fp_generator"]:
            continue
        if rid.startswith(ENGINE_PREFIXES):
            engine_flagged.append(rid)
            continue
        # registry-паттерн: ищем в patterns по pattern_title (findings.pattern_title)
        title_rows = db.execute(
            "SELECT DISTINCT pattern_title FROM findings WHERE rule_id=? AND pattern_title IS NOT NULL LIMIT 1",
            (rid,),
        ).fetchall()
        title = title_rows[0][0] if title_rows else None
        if not title:
            engine_flagged.append(rid)
            continue
        # деактивируем pattern(s) по title-совпадению (title содержит имя детектора)
        pat = db.execute(
            "UPDATE patterns SET active=0, deactivated_at=? WHERE title LIKE ? AND active=1",
            (now, f"%{title.split('(')[0].strip()}%"),
        )
        # пишем в fp_log для audit-trail
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
    ap.add_argument("--json", action="store_true", help="вывод JSON")
    args = ap.parse_args()

    dataset = load_dataset()
    if not dataset:
        print("❌ calibration_dataset.json не найден")
        return 2

    db = sqlite3.connect(str(DB_PATH))
    results, seen = compute_precision(db, dataset)

    # пересчёт is_fp_generator с учётом --min-fp
    for r in results.values():
        r["is_fp_generator"] = (r["fp_clean"] >= args.min_fp and r["tp_vuln"] == 0)

    if args.json:
        print(json.dumps({"scanned_findings": seen, "detectors": results}, ensure_ascii=False, indent=2))
        db.close()
        return 0

    # --- отчёт ---
    print("=" * 68)
    print(f"GSC GROUND-TRUTH TRAINER — 0 LLM | calibration findings: {seen}")
    print("=" * 68)
    rows = sorted(results.items(), key=lambda kv: -kv[1]["fp_clean"])
    print(f'{"rule_id":<30} {"FP(clean)":>9} {"TP(vuln)":>9} {"prec%":>7}  вердикт')
    for rid, r in rows:
        if r["fp_clean"] == 0 and r["tp_vuln"] == 0:
            continue
        if r["is_fp_generator"]:
            v = "🔴 FP-GEN"
        elif r["tp_vuln"] > 0:
            v = "🟢 TP"
        else:
            v = "⚪ шум"
        print(f"{rid:<30} {r['fp_clean']:>9} {r['tp_vuln']:>9} {r['precision_pct']:>7}  {v}")

    fg = [rid for rid, r in results.items() if r["is_fp_generator"]]
    print()
    print(f"🔴 FP-генераторы (fp>={args.min_fp}, tp=0): {len(fg)}")
    for rid in fg:
        print(f"   - {rid}: {results[rid]['fp_clean']} FP в clean, 0 TP в vuln")

    if args.apply and fg:
        deactivated, engine_flagged = apply_deactivation(db, results)
        print()
        print(f"✅ Деактивировано (registry): {len(deactivated)} — {deactivated}")
        if engine_flagged:
            print(f"⚠️  Требуют правки движка (код): {engine_flagged}")
        print(f"   fp_log записан, commit выполнен.")
    elif args.apply:
        print()
        print("✅ FP-генераторов нет — деактивировать нечего.")

    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
