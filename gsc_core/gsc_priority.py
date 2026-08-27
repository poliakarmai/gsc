# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Priority Scoring v1.0 — real-exploitation prioritisation.

Extends ``gsc_epss.compute_risk`` with two extra signals, matching the
Vulristics idea that a bare CVSS score is a poor prioritizer:

  * ``is_kev``   — CISA Known Exploited Vulnerabilities (exploited in the wild).
  * ``has_exploit`` — a public exploit / PoC is available (ExploitDB).

Priority is a function of *probability of exploitation* and *impact*:

    prob  = 1.0 if is_kev else max(epss, 0.9) if has_exploit else epss
    score = severity_weight * prob * reachability

A CRITICAL CVE with near-zero EPSS and no KEV/exploit signal therefore drops
to low priority — it is a real vuln nobody is exploiting. A KEV entry is
treated as certain (prob = 1.0) regardless of EPSS, because it is already
being exploited in the wild.

Stdlib only. Pure functions — no I/O, no network, no env.
"""

from __future__ import annotations

from typing import Optional

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
DEFAULT_WEIGHT = 0.5

# Probability of exploitation floor when a public exploit exists.
EXPLOIT_PROB = 0.9
# KEV = certain exploitation.
KEV_PROB = 1.0


def _clamp(value: Optional[float], lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(hi, v))


def _level_for(score: float) -> str:
    if score >= 0.7:
        return "critical"
    if score >= 0.4:
        return "high"
    if score >= 0.15:
        return "medium"
    return "low"


def compute_priority(
    severity: str,
    epss_score: float,
    is_kev: bool = False,
    has_exploit: bool = False,
    reachability: float = 1.0,
) -> dict:
    """Score a vulnerability by real exploitation risk, not bare CVSS.

    Returns a dict with ``score`` (0..1), ``level`` (critical/high/medium/low),
    ``exploitation_probability`` (0..1) and the ``signals`` that fed the score.
    """
    weight = SEVERITY_WEIGHT.get((severity or "MEDIUM").upper(), DEFAULT_WEIGHT)
    epss = _clamp(epss_score)
    reach = _clamp(reachability)

    if is_kev:
        prob = KEV_PROB
    elif has_exploit:
        prob = max(epss, EXPLOIT_PROB)
    else:
        prob = epss

    score = round(weight * prob * reach, 3)
    level = _level_for(score)

    return {
        "score": score,
        "level": level,
        "exploitation_probability": round(prob, 3),
        "signals": {
            "severity": (severity or "MEDIUM").upper(),
            "epss": epss,
            "is_kev": bool(is_kev),
            "has_exploit": bool(has_exploit),
            "reachability": reach,
        },
        "formula": (
            f"sev({weight}) × prob({prob:.2f}) × reach({reach}) = {score}"
        ),
    }


def priority_rank(priority: dict) -> int:
    """Ordering key: higher score first. Ties broken by level severity."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    level = (priority.get("level") or "low")
    return (priority.get("score", 0.0), order.get(level, 0))
