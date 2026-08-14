#!/usr/bin/env python3
"""GSC roadmap 2.2 / 2.4 / 2.6 — detector contract, coverage matrix, DETECTORS.md.

Генерирует из registry (SSOT ``gsc_detectors.registry.get_detectors()``):
  - ``detector_contract.json`` — машинный контракт детекторов;
  - ``DETECTORS.md`` — человекочитаемая таблица;
  - coverage matrix (rule_id → covered_by_fixture) — в обоих артефактах.

Покрытие fixture определяется появлением ``GSnnn`` в файлах ``tests/``.

Запуск:  python3 scripts/gsc_detector_matrix.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))

from gsc_detectors.registry import get_detectors  # noqa: E402


def _fixture_rule_ids() -> set[str]:
    """rule_id, встречающиеся в тестах (fixture coverage)."""
    covered: set[str] = set()
    for f in (GSC / "tests").rglob("*.py"):
        txt = f.read_text(errors="ignore")
        for m in re.finditer(r"(?i)\b(gs\d{3})\b", txt):
            covered.add(m.group(1).upper())
    return covered


def main() -> int:
    detectors = get_detectors()
    covered = _fixture_rule_ids()

    contract = []
    for d in detectors:
        contract.append({
            "rule_id": d.rule_id,
            "echelon": d.echelon,
            "noise_tier": d.noise_tier,
            "description": d.description,
            "covered_by_fixture": d.rule_id in covered,
        })

    # detector_contract.json
    (GSC / "detector_contract.json").write_text(
        json.dumps(contract, indent=2, ensure_ascii=False) + "\n"
    )

    # DETECTORS.md
    lines = [
        "# Detectors",
        "",
        "Сгенерировано из registry — `scripts/gsc_detector_matrix.py`. "
        "SSOT по числам: `gsc_meta.py`.",
        "",
        f"Всего registry-детекторов: **{len(detectors)}** "
        f"(+ 4 standalone движка: Secrets/SCA/IaC/Invariants = {len(detectors) + 4}).",
        "",
        "| Rule ID | Echelon | Noise | Fixture | Description |",
        "|---------|---------|-------|---------|-------------|",
    ]
    for d in detectors:
        mark = "✅" if d.rule_id in covered else "⬜"
        lines.append(f"| {d.rule_id} | {d.echelon} | {d.noise_tier} | {mark} | {d.description} |")
    (GSC / "DETECTORS.md").write_text("\n".join(lines) + "\n")

    covered_n = sum(1 for d in detectors if d.rule_id in covered)
    print(f"✅ detector_contract.json + DETECTORS.md: {len(detectors)} detectors, "
          f"{covered_n} covered, {len(detectors) - covered_n} uncovered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
