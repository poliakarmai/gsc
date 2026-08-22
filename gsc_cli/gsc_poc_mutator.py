#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""GSC PoC Payload Mutator v1.0 — adversarial re-attack (Shinobi-style).

Proof-of-Fix replay'ит ИСХОДНЫЙ PoC — это доказывает только, что конкретный
payload заблокирован. Поверхностный фикс (фильтр одной строки) всё ещё пропустит
мутированную обфускацию той же атаки. Этот модуль генерирует детерминированные
МУТАЦИИ payload'а (encoding/обфускация), чтобы re-PoC ловил «залатали симптом,
не причину».

Deterministic, no LLM. Дополняет gsc_proofoffix.py (re-PoC) и
gsc_mutation_tracker.py (который мутирует ПАТТЕРНЫ, а не payload'ы).
"""

from __future__ import annotations

import re
from urllib.parse import quote


def _url_encode(s: str, full: bool = True) -> str:
    if full:
        return quote(s, safe="")
    # encode only characters that commonly trip naive filters
    return "".join("%%%02X" % ord(c) if c in "<>(){}'$;|&/\\\"`=" else c for c in s)


def _double_encode(s: str) -> str:
    return _url_encode(_url_encode(s, True), True)


def _html_entities(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&#60;").replace(">", "&#62;")
             .replace("'", "&#39;").replace('"', "&#34;"))


def _case_swap(s: str) -> str:
    return s.swapcase()


def _unquote_space(s: str) -> str:
    return re.sub(r"\s+", "/**/", s)


def _tab_space(s: str) -> str:
    return re.sub(r"\s+", "\t", s)


# Kind-specific alternate payloads (same exploit class, different syntax).
_ALT_PAYLOADS: dict[str, list[str]] = {
    "command_injection": [
        "$(echo VULNERABLE)", "`echo VULNERABLE`", "| echo VULNERABLE",
        "${IFS}echo${IFS}VULNERABLE", ";echo$IFS VULNERABLE", "& echo VULNERABLE &",
    ],
    "ssti": [
        "{{ 7*7 }}", "${7*7}", "<%= 7*7 %>", "{{7 * 7}}", "{{config}}",
    ],
    "sql_injection": [
        "' OR 1=1 --", "admin' --", "' UNION SELECT 1,2,3 --", "') OR ('1'='1",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd", "/etc/passwd",
    ],
    "xss": [
        "<svg onload=alert(1)>", "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>", "javascript:alert(1)",
    ],
}


def mutate(payload: str, kind: str) -> list[str]:
    """Return a sorted list of deterministic mutated variants (original excluded).

    kind ∈ {command_injection, ssti, sql_injection, path_traversal, xss, generic}.
    """
    if not payload:
        return []
    variants: set[str] = set()

    # Generic obfuscations — apply to every class.
    variants.add(_url_encode(payload, True))
    variants.add(_url_encode(payload, False))
    variants.add(_double_encode(payload))
    variants.add(_case_swap(payload))
    variants.add(_tab_space(payload))

    # Class-specific obfuscations.
    if kind == "xss":
        variants.add(_html_entities(payload))
        variants.add(payload.replace("script", "ScRiPt"))
        variants.add(payload.replace("script", "scr\tipt"))
    elif kind == "sql_injection":
        variants.add(_unquote_space(payload))
        variants.add(payload.lower())
        variants.add(payload.upper())
        variants.add(payload.replace("'", '"'))
    elif kind == "path_traversal":
        variants.add(payload.replace("/", "%2f"))
        variants.add(payload.replace("/", "//"))
        variants.add(payload.replace("..", "%2e%2e"))
        variants.add(payload.replace("/", "\\"))
    elif kind == "ssti":
        variants.add(payload.replace(" ", ""))
    elif kind == "command_injection":
        variants.add(payload.replace(" ", "${IFS}"))

    # Alternate payloads from the same exploit class.
    for alt in _ALT_PAYLOADS.get(kind, []):
        variants.add(alt)

    variants.discard(payload)
    variants.discard("")
    return sorted(variants)


def adversarial_recheck(payload: str, kind: str, run_poc) -> dict:
    """Re-attack with mutated payloads. Returns per-variant exploit results.

    run_poc(mutated_payload: str) -> bool  (True = exploited).
    Used by Proof-of-Fix: if ANY mutation still exploits, the fix is superficial.
    """
    results = {}
    for variant in mutate(payload, kind):
        try:
            results[variant] = bool(run_poc(variant))
        except Exception:
            results[variant] = None
    return {
        "variants": len(results),
        "still_exploitable": sum(1 for v in results.values() if v is True),
        "results": results,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 3:
        print("Usage: gsc_poc_mutator.py <payload> <kind>")
        sys.exit(1)
    payload, kind = sys.argv[1], sys.argv[2]
    print(json.dumps(mutate(payload, kind), indent=2, ensure_ascii=False))
