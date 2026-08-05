#!/usr/bin/env python3
"""
GSC Blocking Engine (Phase 4).

Phase rules (PROJECT.md 4):
  blocking-critical:  CRITICAL 0.90
  blocking-standard:  CRITICAL 0.90 + HIGH 0.85

Blocking = phase AND threshold AND detector allowed AND no override.
Shadow mode: decision computed but blocking=False (dry-run for Phase 4).
"""
from __future__ import annotations
from typing import Any, Optional

PHASE_THRESHOLDS: dict = {
    "blocking-critical": [("CRITICAL", 0.90)],
    "blocking-standard": [("CRITICAL", 0.90), ("HIGH", 0.85)],
}


class BlockingEngine:
    """Single point of blocking decisions. Replaces _apply_rollout_phase."""

    def __init__(self, db, phase: str, config: dict | None = None,
                 github_context: bool = False):
        self.db = db
        self.phase = phase
        self.config = config or {}
        self.policy = self.config.get("policy", {})
        self.github_context = github_context
        self.shadow = bool(
            self.config.get("shadow", False)) and github_context
        self._tp_cache: Optional[list] = None

    # ── Detector policy ──────────────────────────────────────

    def _tp_stats(self) -> list[dict]:
        if self._tp_cache is None:
            self._tp_cache = self.db.detector_tp_rates()
        return self._tp_cache

    def detector_allowed(self, rule_id: str) -> tuple[bool, str]:
        det = rule_id.split("-")[0]

        # GS028: invariants only block with explicit repo opt-in
        if det == "GS028":
            if self.config.get("invariants_enforce"):
                return True, "invariants enforce opt-in"
            return False, "invariants_enforce disabled"

        overrides = self.policy.get("overrides", {})
        if det in overrides:
            ok = overrides[det] == "allow"
            return ok, "manual policy override"

        if self.policy.get("mode", "auto") == "manual":
            return False, "manual mode: no explicit allow"

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

    # ── Core logic ───────────────────────────────────────────

    def apply(self, findings: list[dict], overrides: set[str],
              bypass: bool) -> dict:
        """Mutate findings; return summary for comment/metrics."""
        # Reset: engine is sole source of blocking truth
        for f in findings:
            f["blocking"] = False

        summary: dict[str, Any] = {
            "blocked": [], "shadow_blocked": [], "skipped": [],
            "shadow": self.shadow, "bypass": bypass,
        }
        if bypass:
            summary["bypass_reason"] = "label bypass"
            return summary

        thresholds = PHASE_THRESHOLDS.get(self.phase)
        if not thresholds:
            return summary

        for f in findings:
            if f.get("confidence", 0.0) < 0.35:
                continue
            if not self._meets_threshold(f, thresholds):
                continue
            allowed, why = self.detector_allowed(
                f.get("rule_id", f.get("pattern_title", "")))
            if not allowed:
                f.setdefault("metadata", {})["blocking_skipped"] = why
                summary["skipped"].append(
                    (f.get("finding_key", "?"), why))
                continue
            if f.get("finding_key") in overrides:
                f["metadata"] = f.get("metadata", {})
                f["metadata"]["overridden"] = True
                summary["skipped"].append(
                    (f["finding_key"], "override"))
                continue
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
        return summary

    @staticmethod
    def _meets_threshold(f: dict, thresholds: list) -> bool:
        sev = f.get("severity", f.get("category", ""))
        conf = f.get("confidence", 0.0)
        return any(sev == s and conf >= c for s, c in thresholds)
