#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the Work-vs-Value report (Phase 5, GSC ROADMAP).

Pure unit tests — no DB, no LLM, no network, no env reads. Exercises:

  * ``work_vs_value_report(findings)`` — the public aggregator. The core
    promise is "of N CRITICAL, only this many actually need your engineers
    this sprint". We verify the bucket counts, the actionable set
    definition, the percent fields, the breakdowns, and the markdown body
    shape.
  * Defensive normalisation — bad / missing fields never crash the report;
    a noisy upstream pipeline still gets a usable answer.
  * Severity filter — non-CRITICAL findings are ignored by default and can
    be opted in via the ``severities=`` parameter.
"""
from __future__ import annotations

import pytest

from gsc_cli.gsc_work_vs_value import (
    LOW_EPSS_THRESHOLD,
    work_vs_value_report,
)


# ── helpers ────────────────────────────────────────────────────────────


def _crit(reachable=True, deploy_context="prod", epss=0.5, severity="CRITICAL"):
    """Build a critical finding dict with sensible defaults."""
    return {
        "severity": severity,
        "reachable": reachable,
        "deploy_context": deploy_context,
        "epss_score": epss,
    }


# ── happy path: bucket counts match the contract ────────────────────────


def test_empty_findings_returns_zeros():
    r = work_vs_value_report([])
    assert r["total_crit"] == 0
    assert r["reachable"] == 0
    assert r["dev_only"] == 0
    assert r["low_epss"] == 0
    assert r["actionable"] == 0
    assert r["reachable_pct"] == 0.0
    assert r["actionable_pct"] == 0.0
    assert r["noise_removed"] == 0
    assert r["by_severity"] == {}
    # Markdown is still rendered (header + "nothing to triage" notice).
    assert "Work-vs-Value Report" in r["markdown"]
    assert "nothing to triage" in r["markdown"]


def test_doctest_example():
    """The exact example from the work_vs_value_report docstring."""
    r = work_vs_value_report([
        _crit(reachable=True, deploy_context="prod", epss=0.8),
        _crit(reachable=True, deploy_context="dev", epss=0.9),
        _crit(reachable=False, deploy_context="prod", epss=0.0),
    ])
    assert r["total_crit"] == 3
    assert r["reachable"] == 2
    assert r["dev_only"] == 1
    assert r["low_epss"] == 1
    assert r["actionable"] == 1


def test_actionable_requires_all_three_signals():
    """Actionable = reachable AND NOT dev AND NOT low_epss.

    A finding is actionable only when all three conditions hold at once.
    """
    findings = [
        # Reachable + prod + high EPSS → actionable
        _crit(reachable=True, deploy_context="prod", epss=0.8),
        # Reachable + dev + high EPSS → not actionable (dev container)
        _crit(reachable=True, deploy_context="dev", epss=0.8),
        # Reachable + prod + low EPSS → not actionable (low EPSS)
        _crit(reachable=True, deploy_context="prod", epss=0.01),
        # Not reachable + prod + high EPSS → not actionable (not called)
        _crit(reachable=False, deploy_context="prod", epss=0.9),
        # Reachable + dev + low EPSS → not actionable (both filters fire)
        _crit(reachable=True, deploy_context="dev", epss=0.0),
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 5
    assert r["reachable"] == 4
    assert r["dev_only"] == 2
    assert r["low_epss"] == 2
    # Only the first one survives all three filters.
    assert r["actionable"] == 1


def test_all_filters_clear_everything():
    """If every finding is noise, actionable must drop to 0."""
    findings = [
        _crit(reachable=True, deploy_context="dev", epss=0.0),   # dev + low
        _crit(reachable=True, deploy_context="dev", epss=0.5),   # dev
        _crit(reachable=True, deploy_context="prod", epss=0.01),  # low
        _crit(reachable=False, deploy_context="dev", epss=0.5),  # dev
        _crit(reachable=False, deploy_context="prod", epss=0.01), # low
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 5
    assert r["actionable"] == 0
    assert r["noise_removed"] == 5
    assert r["actionable_pct"] == 0.0


def test_no_filters_clear_nothing():
    """All findings reachable + prod + high EPSS → 100% actionable."""
    findings = [_crit(reachable=True, deploy_context="prod", epss=0.9) for _ in range(7)]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 7
    assert r["reachable"] == 7
    assert r["dev_only"] == 0
    assert r["low_epss"] == 0
    assert r["actionable"] == 7
    assert r["reachable_pct"] == 100.0
    assert r["actionable_pct"] == 100.0
    assert r["noise_removed"] == 0


# ── percentages and noise_removed ──────────────────────────────────────


def test_percentages_round_to_one_decimal():
    findings = [
        _crit(reachable=True, deploy_context="prod", epss=0.9),  # actionable
        _crit(reachable=False, deploy_context="prod", epss=0.0),  # noise
        _crit(reachable=True, deploy_context="prod", epss=0.0),   # noise (low epss)
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 3
    assert r["actionable"] == 1
    # 1/3 = 33.333... → rounds to 33.3
    assert r["actionable_pct"] == 33.3
    assert r["noise_removed"] == 2
    assert r["noise_removed"] == r["total_crit"] - r["actionable"]


def test_low_epss_threshold_at_boundary():
    """EPSS exactly at the threshold is NOT low — it counts as high."""
    findings = [_crit(epss=LOW_EPSS_THRESHOLD)]
    r = work_vs_value_report(findings)
    assert r["low_epss"] == 0
    assert r["actionable"] == 1  # reachable=True by default, prod, epss >= threshold


def test_low_epss_just_below_threshold():
    """EPSS strictly below the threshold is low."""
    findings = [_crit(epss=LOW_EPSS_THRESHOLD - 1e-6)]
    r = work_vs_value_report(findings)
    assert r["low_epss"] == 1
    assert r["actionable"] == 0


def test_custom_low_epss_threshold():
    """A higher threshold widens the "low EPSS" bucket."""
    findings = [_crit(epss=0.3) for _ in range(3)]
    # Default threshold (0.05) — none are low.
    r_default = work_vs_value_report(findings)
    assert r_default["low_epss"] == 0
    # Custom threshold (0.5) — all 3 are now low.
    r_custom = work_vs_value_report(findings, low_epss_threshold=0.5)
    assert r_custom["low_epss"] == 3
    assert r_custom["actionable"] == 0
    # Threshold is echoed in the result for the caller's audit trail.
    assert r_custom["low_epss_threshold"] == 0.5


# ── severity filter ────────────────────────────────────────────────────


def test_non_critical_findings_are_ignored_by_default():
    findings = [
        _crit(severity="HIGH", reachable=True, deploy_context="prod", epss=0.9),
        _crit(severity="MEDIUM", reachable=True, deploy_context="prod", epss=0.9),
        _crit(severity="LOW", reachable=True, deploy_context="prod", epss=0.9),
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 0
    # but by_severity records the full distribution for context
    assert r["by_severity"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1}


def test_severities_widens_the_lens():
    findings = [
        _crit(severity="CRITICAL", epss=0.9),
        _crit(severity="HIGH", epss=0.9),
        _crit(severity="MEDIUM", epss=0.9),
    ]
    r = work_vs_value_report(findings, severities=("CRITICAL", "HIGH"))
    assert r["total_crit"] == 2
    assert r["reachable"] == 2
    assert r["actionable"] == 2
    assert r["severities"] == ["CRITICAL", "HIGH"]


def test_severity_filter_is_case_insensitive():
    findings = [_crit(severity="critical"), _crit(severity="Critical")]
    r = work_vs_value_report(findings, severities=("critical",))
    assert r["total_crit"] == 2


def test_severity_filter_falls_back_to_critical_on_garbage():
    """Garbage severity list (all unknown / empty) → default to CRITICAL."""
    r = work_vs_value_report([_crit()], severities=("BOOM", ""))
    # No finding has severity "BOOM" or "" — the kept severities are
    # reset to ("CRITICAL",) by the function, and the CRIT finding matches.
    assert r["total_crit"] == 1
    assert r["severities"] == ["CRITICAL"]


# ── defensive normalisation ────────────────────────────────────────────


def test_missing_fields_default_conservatively():
    """A bare {} has no severity -> treated as INFO, excluded from CRITICAL."""
    r = work_vs_value_report([{}])
    assert r["total_crit"] == 0
    assert r["reachable"] == 0
    assert r["dev_only"] == 0
    assert r["low_epss"] == 0
    assert r["actionable"] == 0
    assert "nothing to triage" in r["markdown"]


def test_critical_missing_subfields_defaults():
    """CRITICAL with no reachable/deploy/epss -> conservative defaults."""
    r = work_vs_value_report([{"severity": "CRITICAL"}])
    assert r["total_crit"] == 1
    assert r["reachable"] == 0       # default reachable=False
    assert r["dev_only"] == 0        # default deploy=prod
    assert r["low_epss"] == 1        # epss=0.0 < 0.05
    assert r["actionable"] == 0


def test_non_dict_entries_are_skipped():
    """A bad upstream pipeline (None / str / list mixed in) must not crash."""
    # Cast to ``list[dict]`` to silence the static type checker — the
    # function itself is total and tolerates non-dict entries by design.
    findings: list[dict] = [
        None,                       # type: ignore[list-item]
        "not a finding",            # type: ignore[list-item]
        ["nested", "list"],         # type: ignore[list-item]
        _crit(),
        42,                         # type: ignore[list-item]
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 1


def test_reachable_accepts_truthy_strings_and_ints():
    findings = [
        {"severity": "CRITICAL", "reachable": "true", "deploy_context": "prod", "epss_score": 0.9},
        {"severity": "CRITICAL", "reachable": "YES", "deploy_context": "prod", "epss_score": 0.9},
        {"severity": "CRITICAL", "reachable": 1, "deploy_context": "prod", "epss_score": 0.9},
        {"severity": "CRITICAL", "reachable": 0, "deploy_context": "prod", "epss_score": 0.9},
        {"severity": "CRITICAL", "reachable": "no", "deploy_context": "prod", "epss_score": 0.9},
    ]
    r = work_vs_value_report(findings)
    # First three are truthy; last two are not.
    assert r["reachable"] == 3


def test_epss_score_clamps_to_unit_interval():
    """Out-of-range EPSS values get clamped into [0.0, 1.0]."""
    findings = [
        {"severity": "CRITICAL", "reachable": True, "deploy_context": "prod", "epss_score": 1.5},
        {"severity": "CRITICAL", "reachable": True, "deploy_context": "prod", "epss_score": -0.3},
    ]
    r = work_vs_value_report(findings)
    # Both clamp: 1.5→1.0 (high), -0.3→0.0 (low) → 1 low, 1 actionable
    assert r["total_crit"] == 2
    assert r["low_epss"] == 1
    assert r["actionable"] == 1


def test_epss_score_accepts_string_numbers():
    findings = [
        {"severity": "CRITICAL", "reachable": True, "deploy_context": "prod", "epss_score": "0.9"},
        {"severity": "CRITICAL", "reachable": True, "deploy_context": "prod", "epss_score": "bogus"},
    ]
    r = work_vs_value_report(findings)
    assert r["total_crit"] == 2
    # "0.9" → 0.9 (high), "bogus" → 0.0 (low)
    assert r["low_epss"] == 1
    assert r["actionable"] == 1


def test_deploy_context_other_values_count_as_prod():
    """``base_image`` / unknown labels are not 'dev' → not filtered out."""
    findings = [
        _crit(deploy_context="base_image", epss=0.9),
        _crit(deploy_context="staging", epss=0.9),
        _crit(deploy_context="", epss=0.9),
    ]
    r = work_vs_value_report(findings)
    assert r["dev_only"] == 0
    # All three are reachable + (not dev) + high epss → actionable
    assert r["actionable"] == 3


# ── breakdown dicts and markdown shape ─────────────────────────────────


def test_by_severity_counts_all_input_severities():
    findings = [
        _crit(severity="CRITICAL"),
        _crit(severity="CRITICAL"),
        _crit(severity="HIGH"),
        _crit(severity="LOW"),
    ]
    r = work_vs_value_report(findings)
    assert r["by_severity"] == {"CRITICAL": 2, "HIGH": 1, "LOW": 1}


def test_deploy_breakdown_reflects_kept_severities_only():
    """The breakdown is built from the FILTERED set, not the raw input."""
    findings = [
        _crit(deploy_context="prod"),
        _crit(deploy_context="dev"),
        # Non-CRITICAL → excluded from the breakdown.
        _crit(severity="HIGH", deploy_context="base_image"),
    ]
    r = work_vs_value_report(findings)
    assert r["deploy_breakdown"] == {"prod": 1, "dev": 1}


def test_epss_breakdown_low_vs_high():
    findings = [
        _crit(epss=0.0),
        _crit(epss=0.01),
        _crit(epss=0.04),
        _crit(epss=0.05),   # boundary → high
        _crit(epss=0.5),
        _crit(epss=0.9),
    ]
    r = work_vs_value_report(findings)
    assert r["epss_breakdown"] == {"low": 3, "high": 3}


def test_markdown_contains_key_numbers():
    findings = [
        _crit(reachable=True, deploy_context="prod", epss=0.8),  # actionable
        _crit(reachable=True, deploy_context="dev", epss=0.5),   # dev noise
    ]
    md = work_vs_value_report(findings)["markdown"]
    assert "## Work-vs-Value Report" in md
    assert "**Total CRITICAL findings:** 2" in md
    assert "| Reachable (called in code) | 2 | 100.0%" in md
    assert "| In dev container (not prod) | 1 | 50.0%" in md
    assert "| Low EPSS (< 0.05) | 0 | 0.0%" in md
    assert "**Actionable (work to do)** | **1** | **50.0%**" in md
    assert "**Noise removed:** 1 of 2 (50.0%)" in md


def test_markdown_uses_custom_threshold_label():
    findings = [_crit(epss=0.1)]
    md = work_vs_value_report(findings, low_epss_threshold=0.2)["markdown"]
    # Threshold label is reflected in the markdown so the report stands
    # alone (manager can read it without grepping the code).
    assert "Low EPSS (< 0.2)" in md


# ── pure-function invariants ──────────────────────────────────────────


def test_pure_function_no_side_effects():
    """Calling the report twice on the same input must return equal values."""
    findings = [_crit() for _ in range(4)]
    r1 = work_vs_value_report(findings)
    r2 = work_vs_value_report(findings)
    assert r1 == r2
    # And the input list itself is not mutated.
    assert len(findings) == 4
    assert all(isinstance(f, dict) for f in findings)


def test_findings_must_not_be_mutated():
    """The function must not rewrite the caller's finding dicts."""
    original = _crit(reachable=True, deploy_context="prod", epss=0.9)
    snapshot = dict(original)
    work_vs_value_report([original])
    assert original == snapshot


def test_does_not_read_os_environ(monkeypatch):
    """Pure function — must not depend on environment variables.

    Stripping PATH / HOME / DEEPSEEK_API_KEY / etc. must not change the
    output. This catches the classic 'os.environ read at module scope'
    mistake: such a read happens at import time, but we still verify the
    function body itself is env-free by clearing the environment and
    re-invoking it.
    """
    findings = [_crit() for _ in range(3)]
    clean = {k: v for k, v in __import__("os").environ.items()
             if k in {"PATH", "HOME", "DEEPSEEK_API_KEY", "GSC_API_KEY"}}
    r1 = work_vs_value_report(findings)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("GSC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    r2 = work_vs_value_report(findings)
    assert r1 == r2


# ── module constants ──────────────────────────────────────────────────


def test_default_low_epss_threshold_is_0_05():
    assert LOW_EPSS_THRESHOLD == 0.05


def test_severity_rank_is_canonical():
    """Mirrors the severity ladder used across GSC (revalidate, blocking, etc.)."""
    from gsc_cli.gsc_work_vs_value import SEVERITY_RANK
    assert SEVERITY_RANK == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
