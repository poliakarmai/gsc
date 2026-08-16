"""Fix Quality Scoring — 3-осевая оценка качества патча поверх ProofOfFix.

ProofOfFix (gsc_proofoffix.py) отвечает «фикс работает?» (level/verified,
detector_fires_after, exploited_after). Чего нет — оценки КАЧЕСТВА патча.
Модуль добавляет 3 оси по FixEvidence.patch (edit-инструкции):
  - minimality: размер патча (кол-во инструкций) — выше = меньше правок
  - regression_risk: доля правок вне файла находки — выше = хуже
  - test_coverage: затронуты ли тесты
Не генерирует патч заново — переиспользует FixEvidence.

CLI: gsc.py fix-quality --evidence fix.json
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from gsc_proofoffix import FixEvidence  # переиспользуем готовый контракт


@dataclass
class FixQuality:
    finding_key: str
    rule_id: str
    verified: bool
    minimality: float      # 0..1, выше = меньше правок
    regression_risk: float  # 0..1, выше = хуже
    test_coverage: float    # 0..1
    score: float            # 0..1 агрегат
    verdict: str            # good|acceptable|risky

    def to_dict(self) -> dict:
        return asdict(self)


def _is_test_path(p: str) -> bool:
    low = p.lower()
    return ("test" in low or "spec" in low or low.startswith("tests/")) and \
        low.endswith((".py", ".js", ".ts", ".go", ".java", ".rs"))


def _patch_files(ev: FixEvidence) -> list[str]:
    """Извлекает пути файлов из edit-инструкций patch (list[dict])."""
    files = []
    for instr in ev.patch or []:
        if isinstance(instr, dict):
            fp = instr.get("file") or instr.get("file_path") or instr.get("path") or ""
            if fp:
                files.append(fp)
    return files


def score_fix(ev: FixEvidence) -> FixQuality:
    files = _patch_files(ev)
    n = max(len(files), 1)

    minimality = max(0.0, 1.0 - (n - 1) * 0.15)

    base = ev.file_path.split("/")[-1] if ev.file_path else ""
    out_of_scope = sum(1 for f in files if base and base not in f)
    regression_risk = round(out_of_scope / n, 3)

    test_coverage = 1.0 if any(_is_test_path(f) for f in files) else 0.0

    score = round(0.5 * minimality + 0.3 * (1.0 - regression_risk) + 0.2 * test_coverage, 3)
    verdict = "good" if score >= 0.75 else ("acceptable" if score >= 0.5 else "risky")
    return FixQuality(
        finding_key=ev.finding_key,
        rule_id=ev.rule_id,
        verified=ev.verified,
        minimality=round(minimality, 3),
        regression_risk=regression_risk,
        test_coverage=test_coverage,
        score=score,
        verdict=verdict,
    )


def score_from_evidence_json(path: str) -> FixQuality:
    """Читает evidence JSON (вывод `pof generate --output`), скорит."""
    data = json.loads(Path(path).read_text())
    fields = set(FixEvidence.__dataclass_fields__)
    ev = FixEvidence(**{k: v for k, v in data.items() if k in fields})
    return score_fix(ev)
