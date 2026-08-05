"""
GSC Detector Registry — mirrors CVE Lite's ALL_DETECTORS pattern.

Register detectors here to make them available to the audit engine.
Each detector module exports: RULE_ID, ECHELON, detect(), description.
"""

from __future__ import annotations

from typing import Callable, Sequence

from gsc_detectors import AuditContext, Detector, Finding


# ── Import detectors ─────────────────────────────────────────────────────────

import gsc_detectors.gs001_hardcoded_secret as _gs001
import gsc_detectors.gs002_world_readable as _gs002
import gsc_detectors.gs003_debug_prints as _gs003
import gsc_detectors.gs004_dangerous_subprocess as _gs004
import gsc_detectors.gs005_sql_injection as _gs005
import gsc_detectors.gs007_idor as _gs007
import gsc_detectors.gs008_dead_code as _gs008
import gsc_detectors.gs009_supply_chain as _gs009
import gsc_detectors.gs010_ssh_hardening as _gs010
import gsc_detectors.gs011_jwt_vulnerabilities as _gs011
import gsc_detectors.gs012_mass_assignment as _gs012
import gsc_detectors.gs013_graphql_security as _gs013
import gsc_detectors.gs014_credential_exposure as _gs014
import gsc_detectors.gs015_entry_points as _gs015
import gsc_detectors.gs016_linux_priv_esc as _gs016
import gsc_detectors.gs017_weak_passwords as _gs017
import gsc_detectors.gs018_payment_abuse as _gs018
import gsc_detectors.gs019_auth_session as _gs019
import gsc_detectors.gs020_xss_injection as _gs020
import gsc_detectors.gs021_csrf_ssrf as _gs021
import gsc_detectors.gs022_open_redirect as _gs022
import gsc_detectors.gs023_race_conditions as _gs023
import gsc_detectors.gs025_ai_provenance as _gs025
import gsc_detectors.gs025_ai_code as _gs025_code


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
        import gsc_detectors.gs020_llm_sqli as _gs024
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
        rule_id=_gs025_code.RULE_ID,
        echelon=_gs025_code.ECHELON,
        detect_fn=_gs025_code.detect,
        description=_gs025_code.description,
        noise_tier=_gs025_code.NOISE_TIER,
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
        all_findings.extend(det.detect(ctx))
    return all_findings
