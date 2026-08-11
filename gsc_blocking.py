# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
"""
GSC Blocking Engine (Phase 5 — v0.26).

Phase rules (PROJECT.md 4):
  blocking-critical:  CRITICAL >= 0.90
  blocking-standard:  CRITICAL >= 0.90, HIGH >= 0.85
  + chain CRITICAL >= 0.90 in blocking-standard ONLY

Blocking = phase AND threshold AND detector_allowed AND no override.
Shadow mode: compute but set blocking=False.
PoC boost: +0.05 effective confidence for PoC-validated findings.
"""
from __future__ import annotations
from typing import Any, Optional

PHASE_THRESHOLDS: dict = {
    "blocking-critical": [("CRITICAL", 0.90)],
    "blocking-standard": [("CRITICAL", 0.90), ("HIGH", 0.85)],
}
SEVERITY_ORDER: dict = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CHAIN_BLOCK_CONFIDENCE: float = 0.90
POC_BOOST: float = 0.05
POC_BOOST_CAP: float = 0.95

# ── Precision Gate (measured on 10 real projects, Aug 2026) ──
# Detectors BELOW WARN_THRESHOLD → warn-only, never block
# Detectors ABOVE BLOCK_THRESHOLD → full blocking
# Unlisted detectors → default allow (backward compatible)
PRECISION_GATE: dict[str, float] = {
    # From precision-report: ~15-20% CRITICAL precision overall
    "GS001": 0.15,     # Hardcoded secrets — high FP on configs
    "GS005": 0.25,     # SQL injection — FP without taint source
    "GS025": 0.10,     # AI provenance — mostly config values
    "GS037": 0.20,     # Python vulns — broad patterns
    "GS007": 0.05,     # IDOR — very noisy on real code
    "GS015": 0.15,     # Entry points — many FPs
    # Higher precision detectors
    "GS004": 0.70,     # subprocess injection
    "GS029": 0.60,     # Cross-repo secrets
}
PRECISION_WARN_THRESHOLD = 0.30
PRECISION_BLOCK_THRESHOLD = 0.70


class BlockingEngine:
    """Single source of blocking truth for all phases."""

    def __init__(self, db, phase: str, config: dict | None = None,
                 github_context: bool = False):
        self.db = db
        self.phase = phase
        self.config = config or {}
        self.policy = self.config.get("policy", {})
        self.github_context = github_context
        self.shadow = bool(
            self.config.get("shadow", False)) and github_context
        self.poc_boost = bool(self.config.get("poc_boost", False))
        self._tp_cache: Optional[list] = None

    # ── Detector policy (Phase 3 auto-mode) ──────────────────

    def _tp_stats(self) -> list[dict]:
        if self._tp_cache is None:
            self._tp_cache = self.db.detector_tp_rates()
        return self._tp_cache

    def detector_allowed(self, rule_id: str) -> tuple[bool, str]:
        """Check if detector is allowed. Shadow = scan but don't block.
        Deactivated = skip entirely. Full = normal behavior.
        """
        # ── NEW: detector_status table (GSAUTO shadow detectors) ──
        try:
            from gsc_shadow_manager import ShadowDetectorManager
            sm = ShadowDetectorManager(self.db)
            status = sm.get_status(rule_id)
            if status == "deactivated":
                return False, "detector deactivated"
            if status == "shadow":
                return True, "shadow (scan only, non-blocking)"
        except ImportError:
            pass

        # ── Existing logic ──
        det = rule_id.split("-")[0]
        if det == "GS028":
            if self.config.get("invariants_enforce"):
                return True, "invariants enforce opt-in"
            return False, "invariants_enforce disabled"
        overrides = self.policy.get("overrides", {})
        if det in overrides:
            return overrides[det] == "allow", "manual policy override"
        if self.policy.get("mode", "auto") == "manual":
            return False, "manual mode"
        min_verdicts = int(self.policy.get("min_verdicts", 10))
        min_tp = float(self.policy.get("min_tp_rate", 0.70))
        stats = next(
            (s for s in self._tp_stats() if s["detector"] == det), None)
        if stats is None:
            return False, "no verdict history"
        if stats["verdicts"] < min_verdicts:
            return False, f"verdicts {stats['verdicts']} < {min_verdicts}"
        if (stats.get("tp_rate") or 0.0) < min_tp:
            return False, f"tp_rate {stats['tp_rate']:.0%} < {min_tp:.0%}"
        return True, "auto policy"

    # ── Effective confidence (PoC boost) ─────────────────────

    def _effective_confidence(self, f: dict) -> float:
        conf = f.get("confidence", 0.0)
        meta = f.get("metadata", {})
        if self.poc_boost and meta.get("poc") and not meta.get("poc_failed"):
            boosted = min(POC_BOOST_CAP, conf + POC_BOOST)
            if boosted > conf:
                f.setdefault("metadata", {})["poc_boost_applied"] = True
            return boosted
        return conf

    # ── Core logic ───────────────────────────────────────────

    def apply(self, findings: list[dict], overrides: set[str],
              bypass: bool, chains: list[dict] | None = None) -> dict:
        """Mutate findings; return summary for comment/metrics.

        🆕 Precision Gate: detectors with measured precision < 30% → warn-only.
        """
        for f in findings:
            f["blocking"] = False

        summary = self._init_summary(bypass)
        if bypass:
            summary["bypass_reason"] = "label bypass"
            return summary

        thresholds = PHASE_THRESHOLDS.get(self.phase)
        if not thresholds:
            return summary

        skipped_low_precision = []

        for f in findings:
            if f.get("confidence", 0.0) < 0.35:
                continue
            if not self._meets_threshold(f, thresholds,
                                         self._effective_confidence(f)):
                continue
            rule_id = f.get("rule_id", f.get("pattern_title", ""))

            # 🆕 Precision Gate: low-precision detectors → warn, never block
            if self._is_low_precision(rule_id):
                f.setdefault("metadata", {})["blocking_skipped"] = (
                    f"low measured precision ({PRECISION_GATE.get(rule_id, 0):.0%} < {PRECISION_WARN_THRESHOLD:.0%})")
                skipped_low_precision.append(f.get("finding_key", "?"))
                continue

            allowed, why = self.detector_allowed(rule_id)
            if not allowed:
                f.setdefault("metadata", {})["blocking_skipped"] = why
                summary["skipped"].append((f.get("finding_key", "?"), why))
                continue
            if f.get("finding_key") in overrides:
                f["metadata"] = f.get("metadata", {})
                f["metadata"]["overridden"] = True
                summary["skipped"].append((f["finding_key"], "override"))
                continue
            self._mark_blocking(f, summary)

        if skipped_low_precision:
            summary["precision_skipped"] = len(skipped_low_precision)

        # ── Chain blocking (Phase 5) ──
        if self.phase == "blocking-standard":
            self._apply_chain_blocking(findings, chains or [],
                                       overrides, summary)
        return summary

    def _is_low_precision(self, rule_id: str) -> bool:
        """Check if detector has measured precision below warn threshold."""
        if not rule_id:
            return False
        # Check full rule_id, then base prefix
        # GS025-hardcoded_secret → GS025; GSAUTO-88-python → GSAUTO (unlisted, allow)
        prec = PRECISION_GATE.get(rule_id)
        if prec is not None:
            return prec < PRECISION_WARN_THRESHOLD
        # Try base: everything before second dash (GS025-hardcoded → GS025)
        parts = rule_id.split("-")
        if len(parts) >= 2 and parts[0].startswith("GS"):
            base = parts[0]
            prec = PRECISION_GATE.get(base)
        return prec is not None and prec < PRECISION_WARN_THRESHOLD

    def _init_summary(self, bypass: bool) -> dict:
        return {
            "blocked": [], "shadow_blocked": [], "skipped": [],
            "precision_skipped": 0,
            "chain_blocked": [], "shadow": self.shadow, "bypass": bypass,
        }

    def _mark_blocking(self, f: dict, summary: dict) -> None:
        f["metadata"] = f.get("metadata", {})
        f["metadata"]["blocking_reason"] = (
            f"phase:{self.phase} sev:{f.get('severity')} "
            f"conf:{f.get('confidence', 0):.2f}")
        if self.shadow:
            f["metadata"]["shadow_block"] = True
            summary["shadow_blocked"].append(f["finding_key"])
        else:
            f["blocking"] = True
            summary["blocked"].append(f["finding_key"])

    # ── Chain blocking (Phase 5) ─────────────────────────────

    def _apply_chain_blocking(self, findings: list[dict],
                               chains: list[dict], overrides: set[str],
                               summary: dict):
        by_key = {f["finding_key"]: f for f in findings}
        for chain in chains:
            ckey = chain.get("chain_key", "")
            if chain.get("composed_severity") != "CRITICAL":
                continue
            if chain.get("confidence", 0.0) < CHAIN_BLOCK_CONFIDENCE:
                continue
            # Community verdict: fp chain never blocks
            if self._chain_status(ckey) == "fp":
                summary["skipped"].append((ckey, "chain verdict: fp"))
                continue

            members = [by_key[k] for k in chain.get("finding_keys", [])
                       if k in by_key]
            if not members:
                continue
            top = max(members, key=lambda f: SEVERITY_ORDER.get(
                f.get("severity", f.get("category", "LOW")), 1))

            if top.get("finding_key") in overrides:
                summary["skipped"].append(
                    (ckey, "top member overridden"))
                continue
            allowed, why = self.detector_allowed(
                top.get("rule_id", top.get("pattern_title", "")))
            if not allowed:
                summary["skipped"].append(
                    (ckey, f"top detector: {why}"))
                continue

            top["metadata"] = top.get("metadata", {})
            top["metadata"]["blocking_reason"] = f"chain:{ckey}"
            if self.shadow:
                top["metadata"]["shadow_block"] = True
                summary["shadow_blocked"].append(top["finding_key"])
            else:
                top["blocking"] = True
                summary["chain_blocked"].append(ckey)

    def _chain_status(self, chain_key: str) -> str:
        try:
            row = self.db.get_chain(chain_key)
            return row["status"] if row else "open"
        except Exception:
            return "open"

    # ── Threshold helpers ────────────────────────────────────

    @staticmethod
    def _meets_threshold(f: dict, thresholds: list,
                         conf: float | None = None) -> bool:
        sev = f.get("severity", f.get("category", ""))
        if conf is None:
            conf = f.get("confidence", 0.0)
        return any(sev == s and conf >= c for s, c in thresholds)
