# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Detector Registry — mirrors CVE Lite's ALL_DETECTORS pattern.

Register detectors here to make them available to the audit engine.
Each detector module exports: RULE_ID, ECHELON, detect(), description.
"""

from __future__ import annotations

from typing import Callable, Sequence

from . import AuditContext, Finding

# ── Import detectors ─────────────────────────────────────────────────────────
from . import gs001_hardcoded_secret as _gs001
from . import gs002_world_readable as _gs002
from . import gs003_debug_prints as _gs003
from . import gs004_dangerous_subprocess as _gs004
from . import gs005_sql_injection as _gs005
from . import gs007_idor as _gs007
from . import gs008_dead_code as _gs008
from . import gs009_supply_chain as _gs009
from . import gs010_ssh_hardening as _gs010
from . import gs011_jwt_vulnerabilities as _gs011
from . import gs012_mass_assignment as _gs012
from . import gs013_graphql_security as _gs013
from . import gs014_credential_exposure as _gs014
from . import gs015_entry_points as _gs015
from . import gs016_linux_priv_esc as _gs016
from . import gs017_weak_passwords as _gs017
from . import gs018_payment_abuse as _gs018
from . import gs019_auth_session as _gs019
from . import gs020_xss_injection as _gs020
from . import gs021_csrf_ssrf as _gs021
from . import gs022_open_redirect as _gs022
from . import gs023_race_conditions as _gs023
from . import gs025_ai_provenance as _gs025
from . import gs032_prompt_injection as _gs032
from . import gs033_cicd as _gs033
from . import gs034_supply_chain as _gs034
from . import gs035_php as _gs035
from . import gs036_nodejs as _gs036
from . import gs037_python as _gs037
from . import gs038_go as _gs038
from . import gs039_ruby as _gs039
from . import gs040_pii_disclosure as _gs040
from . import gs041_crypto_secrets as _gs041
from . import gs042_solidity as _gs042
from . import gs043_honeypot as _gs043
from . import gs044_trading_bots as _gs044
from . import gs045_github_actions as _gs045
from . import gs046_cpp as _gs046

# ── Detector descriptor ──────────────────────────────────────────────────────

class DetectorEntry:
    """Lightweight descriptor — not the module itself."""

    def __init__(self, rule_id: str, echelon: int, detect_fn: Callable, description: str, noise_tier: str = "normal"):
        self.rule_id = rule_id
        self.echelon = echelon
        self.detect = detect_fn
        self.description = description
        self.noise_tier = noise_tier

    def __repr__(self):
        return f"DetectorEntry({self.rule_id}, echelon={self.echelon})"


# ── Lazy imports (must be defined BEFORE ALL_DETECTORS) ─────────────────────

def _lazy_gs024(ctx):
    """Lazy-load LLM SQLi detector — avoids API key requirement at import time."""
    try:
        from . import gs024_llm_sqli as _gs024
        return _gs024.detect(ctx)
    except Exception:
        return []


# ── Registry ─────────────────────────────────────────────────────────────────

ALL_DETECTORS: Sequence[DetectorEntry] = [
    DetectorEntry(
        rule_id=_gs001.RULE_ID,
        echelon=_gs001.ECHELON,
        detect_fn=_gs001.detect,
        description=_gs001.description,
    ),
    DetectorEntry(
        rule_id=_gs002.RULE_ID,
        echelon=_gs002.ECHELON,
        detect_fn=_gs002.detect,
        description=_gs002.description,
    ),
    DetectorEntry(
        rule_id=_gs003.RULE_ID,
        echelon=_gs003.ECHELON,
        detect_fn=_gs003.detect,
        description=_gs003.description,
    ),
    DetectorEntry(
        rule_id=_gs004.RULE_ID,
        echelon=_gs004.ECHELON,
        detect_fn=_gs004.detect,
        description=_gs004.description,
    ),
    DetectorEntry(
        rule_id=_gs005.RULE_ID,
        echelon=_gs005.ECHELON,
        detect_fn=_gs005.detect,
        description=_gs005.description,
    ),
    DetectorEntry(
        rule_id=_gs007.RULE_ID,
        echelon=_gs007.ECHELON,
        detect_fn=_gs007.detect,
        description=_gs007.description,
        noise_tier=getattr(_gs007, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs008.RULE_ID,
        echelon=_gs008.ECHELON,
        detect_fn=_gs008.detect,
        description=_gs008.description,
    ),
    DetectorEntry(
        rule_id=_gs009.RULE_ID,
        echelon=_gs009.ECHELON,
        detect_fn=_gs009.detect,
        description=_gs009.description,
    ),
    DetectorEntry(
        rule_id=_gs010.RULE_ID,
        echelon=_gs010.ECHELON,
        detect_fn=_gs010.detect,
        description=_gs010.description,
    ),
    DetectorEntry(
        rule_id=_gs011.RULE_ID,
        echelon=_gs011.ECHELON,
        detect_fn=_gs011.detect,
        description=_gs011.description,
    ),
    DetectorEntry(
        rule_id=_gs012.RULE_ID,
        echelon=_gs012.ECHELON,
        detect_fn=_gs012.detect,
        description=_gs012.description,
    ),
    DetectorEntry(
        rule_id=_gs013.RULE_ID,
        echelon=_gs013.ECHELON,
        detect_fn=_gs013.detect,
        description=_gs013.description,
    ),
    DetectorEntry(
        rule_id=_gs014.RULE_ID,
        echelon=_gs014.ECHELON,
        detect_fn=_gs014.detect,
        description=_gs014.description,
    ),
    DetectorEntry(
        rule_id=_gs015.RULE_ID,
        echelon=_gs015.ECHELON,
        detect_fn=_gs015.detect,
        description=_gs015.description,
    ),
    DetectorEntry(
        rule_id=_gs016.RULE_ID,
        echelon=_gs016.ECHELON,
        detect_fn=_gs016.detect,
        description=_gs016.description,
    ),
    DetectorEntry(
        rule_id=_gs017.RULE_ID,
        echelon=_gs017.ECHELON,
        detect_fn=_gs017.detect,
        description=_gs017.description,
        noise_tier=getattr(_gs017, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs018.RULE_ID,
        echelon=_gs018.ECHELON,
        detect_fn=_gs018.detect,
        description=_gs018.description,
        noise_tier=getattr(_gs018, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs019.RULE_ID,
        echelon=_gs019.ECHELON,
        detect_fn=_gs019.detect,
        description=_gs019.description,
        noise_tier=getattr(_gs019, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs020.RULE_ID,
        echelon=_gs020.ECHELON,
        detect_fn=_gs020.detect,
        description=_gs020.description,
        noise_tier=getattr(_gs020, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs021.RULE_ID,
        echelon=_gs021.ECHELON,
        detect_fn=_gs021.detect,
        description=_gs021.description,
        noise_tier=getattr(_gs021, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs022.RULE_ID,
        echelon=_gs022.ECHELON,
        detect_fn=_gs022.detect,
        description=_gs022.description,
        noise_tier=getattr(_gs022, "NOISE_TIER", "normal"),
    ),
    DetectorEntry(
        rule_id=_gs023.RULE_ID,
        echelon=_gs023.ECHELON,
        detect_fn=_gs023.detect,
        description=_gs023.description,
        noise_tier=_gs023.NOISE_TIER,
    ),
    DetectorEntry(
        rule_id=_gs025.RULE_ID,
        echelon=_gs025.ECHELON,
        detect_fn=_gs025.detect,
        description=_gs025.description,
        noise_tier=_gs025.NOISE_TIER,
    ),
    # 🆕 v2.0: Prompt injection detection for AI coding agents (GS032)
    DetectorEntry(
        rule_id=_gs032.RULE_ID,
        echelon=_gs032.ECHELON,
        detect_fn=_gs032.detect,
        description=_gs032.description,
        noise_tier=getattr(_gs032, "NOISE_TIER", "normal"),
    ),
    # 🆕 v2.0: CI/CD pipeline anti-patterns (GS033)
    DetectorEntry(
        rule_id=_gs033.RULE_ID,
        echelon=_gs033.ECHELON,
        detect_fn=_gs033.detect,
        description=_gs033.description,
        noise_tier=getattr(_gs033, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 v2.0: npm supply chain attack detection (GS034)
    DetectorEntry(
        rule_id=_gs034.RULE_ID,
        echelon=_gs034.ECHELON,
        detect_fn=_gs034.detect,
        description=_gs034.description,
        noise_tier=getattr(_gs034, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 v2.0: PHP vulnerability detection (GS035)
    DetectorEntry(
        rule_id=_gs035.RULE_ID,
        echelon=_gs035.ECHELON,
        detect_fn=_gs035.detect,
        description=_gs035.description,
        noise_tier=getattr(_gs035, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS036–GS039: language-specific vulnerability detectors
    DetectorEntry(
        rule_id=_gs036.RULE_ID,
        echelon=_gs036.ECHELON,
        detect_fn=_gs036.detect,
        description=_gs036.description,
        noise_tier=getattr(_gs036, "NOISE_TIER", "sensitive"),
    ),
    DetectorEntry(
        rule_id=_gs037.RULE_ID,
        echelon=_gs037.ECHELON,
        detect_fn=_gs037.detect,
        description=_gs037.description,
        noise_tier=getattr(_gs037, "NOISE_TIER", "sensitive"),
    ),
    DetectorEntry(
        rule_id=_gs038.RULE_ID,
        echelon=_gs038.ECHELON,
        detect_fn=_gs038.detect,
        description=_gs038.description,
        noise_tier=getattr(_gs038, "NOISE_TIER", "sensitive"),
    ),
    DetectorEntry(
        rule_id=_gs039.RULE_ID,
        echelon=_gs039.ECHELON,
        detect_fn=_gs039.detect,
        description=_gs039.description,
        noise_tier=getattr(_gs039, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS040: PII & information disclosure (from ZAP passive-scan signals)
    DetectorEntry(
        rule_id=_gs040.RULE_ID,
        echelon=_gs040.ECHELON,
        detect_fn=_gs040.detect,
        description=_gs040.description,
        noise_tier=getattr(_gs040, "NOISE_TIER", "normal"),
    ),
    # 🆕 GS041: crypto secrets — EVM private keys, BIP39 mnemonics, WIF, exchange API keys
    DetectorEntry(
        rule_id=_gs041.RULE_ID,
        echelon=_gs041.ECHELON,
        detect_fn=_gs041.detect,
        description=_gs041.description,
        noise_tier=getattr(_gs041, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS042: Solidity SAST — reentrancy, tx.origin, delegatecall, selfdestruct, unchecked, oracle
    DetectorEntry(
        rule_id=_gs042.RULE_ID,
        echelon=_gs042.ECHELON,
        detect_fn=_gs042.detect,
        description=_gs042.description,
        noise_tier=getattr(_gs042, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS043: honeypot / rug-pull — trading switch, blacklist, unrestricted mint, fee setter
    DetectorEntry(
        rule_id=_gs043.RULE_ID,
        echelon=_gs043.ECHELON,
        detect_fn=_gs043.detect,
        description=_gs043.description,
        noise_tier=getattr(_gs043, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS044: trading-bot audit — replay-prone signing, unvalidated orders, races, unauth endpoints
    DetectorEntry(
        rule_id=_gs044.RULE_ID,
        echelon=_gs044.ECHELON,
        detect_fn=_gs044.detect,
        description=_gs044.description,
        noise_tier=getattr(_gs044, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 GS045: GitHub Actions CI/CD security — permissions, env secrets, PR-target RCE
    DetectorEntry(
        rule_id=_gs045.RULE_ID,
        echelon=_gs045.ECHELON,
        detect_fn=_gs045.detect,
        description=_gs045.description,
        noise_tier=getattr(_gs045, "NOISE_TIER", "sensitive"),
    ),
    DetectorEntry(
        rule_id=_gs046.RULE_ID,
        echelon=_gs046.ECHELON,
        detect_fn=_gs046.detect,
        description=_gs046.description,
        noise_tier=getattr(_gs046, "NOISE_TIER", "sensitive"),
    ),
    # 🆕 v2.0: LLM-based SQLi detector (pilot, lazy-loaded)
    DetectorEntry(
        rule_id="GS024",
        echelon=2,
        detect_fn=_lazy_gs024,
        description="LLM-based SQL injection (pilot — replaces 87 regex patterns)",
        noise_tier="precise",
    ),
]

# ── YAML custom rules (declarative pattern DSL) ──
try:
    from . import yaml_rules as _yr
    for _mod_name in getattr(_yr, '__all__', []):
        try:
            _ym = getattr(_yr, _mod_name, None)
            if _ym is None:
                continue
            _det = getattr(_ym, 'detector', None)
            if _det and hasattr(_det, 'rule_id'):
                ALL_DETECTORS.append(DetectorEntry(
                    rule_id=_det.rule_id,
                    echelon=2,
                    detect_fn=_det.detect,
                    description=getattr(_ym, 'description', f'YAML rule: {_det.name}'),
                    noise_tier="custom",
                ))
        except Exception:
            pass
except ImportError:
    pass  # no YAML rules compiled

# Grouped by echelon for targeted runs
ECHELON_DETECTORS: dict[int, list[DetectorEntry]] = {}
for det in ALL_DETECTORS:
    ECHELON_DETECTORS.setdefault(det.echelon, []).append(det)

# Grouped by category (for CI/quick scans)
FAST_DETECTORS = [det for det in ALL_DETECTORS if det.echelon <= 2]  # echelons 1-2
FULL_DETECTORS = list(ALL_DETECTORS)  # all echelons


def get_detectors(echelon: int | None = None) -> list[DetectorEntry]:
    """Get detectors, optionally filtered by echelon."""
    if echelon is None:
        return list(ALL_DETECTORS)
    return ECHELON_DETECTORS.get(echelon, [])


def run_detectors(
    ctx: AuditContext,
    echelons: Sequence[int] | None = None,
) -> list[Finding]:
    """Run all (or filtered) detectors against context."""
    all_findings: list[Finding] = []
    for det in ALL_DETECTORS:
        if echelons is not None and det.echelon not in echelons:
            continue
        if det.rule_id in ctx.skipped_detectors:
            continue
        for f in det.detect(ctx):
            if f is not None:  # make_finding returns None on empty rule_id
                all_findings.append(f)
    return all_findings
