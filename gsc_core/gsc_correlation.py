# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC SAST↔DAST Correlation Engine.

Solar appScreener-style correlation: сопоставляет статические (SAST) находки с
динамическими (DAST/nuclei) и *подтверждает* уязвимость рантайм-сигналом.

До этого слоя `review_status='confirmed'` ставился LLM-rejudge + текстовыми
TP/FP-сигналами (см. gsc_cli/gsc_external.py `compute_confidence_v3`), а DAST
(nuclei) находки просто лежали рядом в `dast_findings` без привязки к SAST.
Этот модуль замыкает цикл: DAST-подтверждение → `review_status='confirmed'`.

Семантика (консервативная):
  - DAST-матч ПОДТВЕРЖДАЕТ SAST-находку (апгрейд до confirmed + evidence).
  - Отсутствие DAST-матча НЕ отрицает находку (review_status остаётся как был).
    «DAST молчит» ≠ «ложное срабатывание».

Матчинг — по каноническому классу уязвимости (нормализация rule_id ↔ template),
плюс guard: DAST-находки с severity='info' не подтверждают (шум).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

# ── rule_id → канонический класс ─────────────────────────────────────────────
# Покрывает registry-детекторы, которые реально подтверждаются динамикой.
_RULE_CLASS_PREFIX: dict[str, str] = {
    "GS004": "command_injection",   # dangerous subprocess
    "GS005": "sql_injection",
    "GS007": "idor",
    "GS012": "mass_assignment",
    "GS013": "graphql",
    "GS014": "info_leak",           # credential exposure
    "GS019": "auth_bypass",         # auth/session
    "GS020": "xss",
    "GS021": "ssrf",                # csrf_ssrf → подтверждается ssrf-темплейтами
    "GS022": "open_redirect",
    "GS024": "sql_injection",       # LLM SQLi
    "GS032": "prompt_injection",
    "GS040": "info_leak",           # PII disclosure
    "YAML-SSTI001": "ssti",
    "YAML-A7E2F001": "command_injection",  # reverse shell
}

# ── класс → ключевые слова для нормализации DAST-template ────────────────────
# Каноничная форма — underscore. Вход нормализуется (lower + '-'/' ' → '_').
_CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sql_injection": ("sql_injection", "sqli"),
    "command_injection": ("command_injection", "cmdi", "os_command",
                          "reverse_shell", "rce"),
    "xss": ("xss",),
    "ssrf": ("ssrf",),
    "open_redirect": ("open_redirect", "redirect"),
    "idor": ("idor",),
    "ssti": ("ssti", "template_injection"),
    "path_traversal": ("path_traversal", "lfi", "traversal"),
    "xxe": ("xxe",),
    "deserialization": ("deserialization", "pickle", "unserialize"),
    "auth_bypass": ("auth_bypass", "authentication_bypass"),
    "mass_assignment": ("mass_assignment",),
    "graphql": ("graphql",),
    "info_leak": ("info_leak", "exposure", "disclosure", "pii"),
    "prompt_injection": ("prompt_injection",),
}

# DAST-находки с этим severity не подтверждают (nuclei 'info' — шум).
_DAST_NOISE_SEVERITY = {"info", "unknown", ""}


def _norm(s: str) -> str:
    return str(s).lower().replace("-", "_").replace(" ", "_")


def _best_class(text: str) -> Optional[str]:
    """Класс с максимальным специфичным совпадением (сумма длин ключей).

    Длинное ключевое слово (напр. 'command_injection') перевешивает короткое
    общее ('rce'), а конкретный класс ('ssti') — общий ('rce' → command_injection).
    """
    t = _norm(text)
    if not t:
        return None
    best, best_score = None, 0
    for cls, kws in _CLASS_KEYWORDS.items():
        score = sum(len(k) for k in kws if k in t)
        if score > best_score:
            best, best_score = cls, score
    return best


def rule_to_class(rule_id: str, title: str = "") -> Optional[str]:
    """Нормализовать GSC rule_id в канонический класс уязвимости.

    Порядок: (1) префикс из _RULE_CLASS_PREFIX; (2) ключевые слова внутри
    самого rule_id (покрывает составные id вроде 'GS025-command_injection');
    (3) ключевые слова в title — для языковых детекторов GS035–GS039, где
    класс не виден из rule_id, а виден из заголовка ('SSTI via ...' и т.п.).
    """
    if not rule_id:
        return None
    rid = str(rule_id)
    for prefix, cls in _RULE_CLASS_PREFIX.items():
        if rid.startswith(prefix):
            return cls
    cls = _best_class(rid)
    if cls:
        return cls
    return _best_class(title) if title else None


def dast_to_class(template: dict) -> Optional[str]:
    """Нормализовать DAST/nuclei находку в канонический класс уязвимости.

    Ищет ключевые слова в template_id, name и tags (best-match по специфичности).
    """
    if not template:
        return None
    tags = template.get("tags") or []
    haystack = " ".join([
        str(template.get("template_id", "") or ""),
        str(template.get("name", "") or ""),
        " ".join(str(t) for t in tags),
    ])
    return _best_class(haystack)


def correlate_sast_dast(sast_findings: list[dict],
                        dast_findings: list[dict]) -> dict:
    """Сопоставить SAST-находки с DAST-находками и подтвердить совпадения.

    Возвращает:
      {
        "findings": [...],   # SAST-находки, подтверждённые — с апгрейдом полей
        "summary": {
            "sast_total": int, "dast_total": int,
            "confirmed_by_dast": int,
            "matched_pairs": [ {finding_key, rule_id, class, template_id}, ... ],
        }
      }

    Исходные списки не мутируются (возвращаются поверхностные копии находок).
    """
    # Индекс DAST по классу (отсеиваем severity='info' — не подтверждает).
    dast_by_class: dict[str, list[dict]] = defaultdict(list)
    for d in dast_findings:
        if not isinstance(d, dict):
            continue
        if str(d.get("severity", "")).lower() in _DAST_NOISE_SEVERITY:
            continue
        cls = dast_to_class(d)
        if cls:
            dast_by_class[cls].append(d)

    confirmed = 0
    matched_pairs: list[dict] = []
    enriched: list[dict] = []

    for f in sast_findings:
        nf = dict(f) if isinstance(f, dict) else dict(f)
        md = dict(f.get("metadata") or {})
        nf["metadata"] = md

        rule_id = f.get("rule_id") or f.get("pattern_title", "")
        cls = rule_to_class(rule_id, title=f.get("title", ""))
        matches = dast_by_class.get(cls, []) if cls else []

        if matches:
            d = matches[0]
            md["correlated_dast"] = True
            md["dast_template_id"] = d.get("template_id", "")
            md["dast_evidence"] = (d.get("evidence", "")
                                   or d.get("matched_at", ""))
            md["dast_severity"] = d.get("severity", "")
            # Рантайм-подтверждение авторитетнее LLM-предсказания.
            nf["review_status"] = "confirmed"
            nf["confidence"] = max(float(f.get("confidence", 0.5)), 0.90)
            confirmed += 1
            matched_pairs.append({
                "finding_key": f.get("finding_key", ""),
                "rule_id": rule_id,
                "class": cls,
                "template_id": d.get("template_id", ""),
            })

        enriched.append(nf)

    return {
        "findings": enriched,
        "summary": {
            "sast_total": len(sast_findings),
            "dast_total": len(dast_findings),
            "confirmed_by_dast": confirmed,
            "matched_pairs": matched_pairs,
        },
    }
