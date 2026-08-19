#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Scan Modes — quick/standard/deep.

Sn1per-inspired scan depth for different scenarios.
Applies overrides to existing profiles.
"""

from __future__ import annotations

from typing import Any, Dict

# ---------------------------------------------------------------------------
# Scan mode definitions — override existing profile settings
# ---------------------------------------------------------------------------
SCAN_MODES: Dict[str, Dict[str, Any]] = {
    "ci": {
        "description": "Детерминированный (regex-only) для calibration/CI: все правила, CRITICAL+HIGH, без LLM/PoC/chains.",
        "llm_enabled": False,
        "llm_max_calls": 0,
        "llm_severities": [],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.60,
        "show_uncertain": False,
        "disabled_rules_extra": [],
        "chain_budget": 0,
        "poc_budget": 0,
    },
    "calibrate": {
        "description": "Для calibration: LLM revalidate (confidence-boost), без PoC/rejudge/chains — детерминированный recall.",
        "llm_enabled": True,
        "llm_max_calls": 20,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.60,
        "show_uncertain": False,
        "disabled_rules_extra": [],
        "chain_budget": 0,
        "poc_budget": 0,
        "rejudge_enabled": False,
    },
    "quick": {
        "description": "Быстрая проверка — только CRITICAL, без LLM, 5 сек. Для CI/PR-быстро.",
        "llm_enabled": False,
        "llm_max_calls": 0,
        "llm_severities": [],
        "block_min_severity": "CRITICAL",
        "block_min_confidence": 0.90,
        "warn_min_severity": "CRITICAL",
        "warn_min_confidence": 0.85,
        "show_uncertain": False,
        "disabled_rules_extra": [
            "GS002", "GS003", "GS007", "GS008", "GS012", "GS013",
            "GS015", "GS018", "GS019", "GS022", "GS023", "GS025",
        ],
        "chain_budget": 0,
        "poc_budget": 0,
    },
    "standard": {
        "description": "Стандартная проверка — CRITICAL+HIGH, LLM 20. Баланс скорость/качество.",
        "llm_enabled": True,
        "llm_max_calls": 20,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.60,
        "show_uncertain": False,
        "disabled_rules_extra": ["GS003", "GS008", "GS015"],
        "chain_budget": 5,
        "poc_budget": 5,
    },
    "deep": {
        "description": "Глубокий аудит — все правила, LLM 50, chains, PoC. Для penetration test.",
        "llm_enabled": True,
        "llm_max_calls": 50,
        "llm_severities": ["CRITICAL", "HIGH", "MEDIUM"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.55,
        "show_uncertain": True,
        "disabled_rules_extra": [],
        "chain_budget": 10,
        "poc_budget": 10,
    },
}


def apply_scan_mode(profile: Dict[str, Any], scan_mode: str) -> Dict[str, Any]:
    """Apply scan mode overrides to a profile dict. Returns modified copy."""
    if scan_mode not in SCAN_MODES:
        return dict(profile)

    mode = SCAN_MODES[scan_mode]
    result = dict(profile)

    # Override with mode settings (mode takes priority over profile)
    for key in (
        "llm_enabled", "llm_max_calls", "llm_severities",
        "block_min_severity", "block_min_confidence",
        "warn_min_severity", "warn_min_confidence",
        "show_uncertain", "chain_budget", "poc_budget",
        "rejudge_enabled",
    ):
        if key in mode:
            result[key] = mode[key]

    # Merge disabled_rules_extra
    extra = mode.get("disabled_rules_extra", [])
    if extra:
        existing = set(result.get("disabled_rules", []))
        result["disabled_rules"] = sorted(existing | set(extra))

    return result


def get_mode_help() -> str:
    """Return help text for --scan-mode."""
    lines = ["Scan mode (overrides profile settings):"]
    for name, cfg in SCAN_MODES.items():
        lines.append(f"  {name:<10} {cfg['description']}")
    return "\n".join(lines)
