#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the fine-grained criteria rejudge (Phase 2, GSC ROADMAP).

The fine-grained rejudge replaces the coarse binary TP/FP verdict with three
independent criteria:

  * source_to_sink   — tainted data CAN flow from the cited source to the cited sink
  * reachability     — an external attacker can actually REACH the vulnerable code
  * exploitability   — the vulnerability is practically EXPLOITABLE (PoV exists)

Aggregation rules (deterministic):

  * TP         iff all three criteria are explicitly confirmed
  * FP         iff at least one criterion is denied AND no criterion is uncertain
  * UNCERTAIN  otherwise (any uncertain criterion, or report is empty)
  * demote=True unless verdict == TP

These tests are pure: no subprocess calls to ``rejudge``, no network, no LLM.
We exercise ``parse_criteria`` and ``fine_grained_verdict`` directly.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the repo importable when pytest is invoked from elsewhere.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from gsc_cli import gsc_rejudge as rj  # noqa: E402


# ---------------------------------------------------------------------------
# Dataclass shape: Criterion + CriteriaReport
# ---------------------------------------------------------------------------

class TestCriterionDataclass:
    def test_defaults(self):
        c = rj.Criterion(name="reachability", verdict=None)
        assert c.name == "reachability"
        assert c.verdict is None
        # Confidence is clamped to [0, 100] and defaults to _DEFAULT_CONFIDENCE
        # (50) so an absent-confidence LLM response still produces a usable
        # value downstream.
        assert 0 <= c.confidence <= 100
        assert c.evidence == ""

    def test_confidence_clamped_low(self):
        c = rj.Criterion(name="reachability", verdict=True, confidence=-999)
        assert c.confidence == 0

    def test_confidence_clamped_high(self):
        c = rj.Criterion(name="reachability", verdict=True, confidence=9999)
        assert c.confidence == 100

    def test_confidence_non_numeric_uses_default(self):
        c = rj.Criterion(name="reachability", verdict=True, confidence="nope")
        # Non-int coerced to the default (50) and clamped.
        assert 0 <= c.confidence <= 100

    def test_verdict_true_false_none_distinct(self):
        """The tri-state verdict must be preserved exactly — no bool-to-int
        coercion would let a False accidentally pass an ``is True`` check."""
        a = rj.Criterion(name="x", verdict=True)
        b = rj.Criterion(name="x", verdict=False)
        c = rj.Criterion(name="x", verdict=None)
        assert a.verdict is True
        assert b.verdict is False
        assert c.verdict is None
        # And the membership test used by the aggregator must agree.
        assert a.verdict is not False
        assert b.verdict is not True
        assert c.verdict is not True
        assert c.verdict is not False


class TestCriteriaReport:
    def _mk(self, sts, reach, expl):
        return rj.CriteriaReport(
            source_to_sink=rj.Criterion(name="source_to_sink", verdict=sts),
            reachability=rj.Criterion(name="reachability", verdict=reach),
            exploitability=rj.Criterion(name="exploitability", verdict=expl),
        )

    def test_criteria_returns_canonical_order(self):
        report = self._mk(True, True, True)
        names = [c.name for c in report.criteria()]
        assert names == ["source_to_sink", "reachability", "exploitability"]

    def test_all_confirmed_true_only_when_every_yes(self):
        assert self._mk(True, True, True).all_confirmed is True
        assert self._mk(True, True, False).all_confirmed is False
        assert self._mk(True, None, True).all_confirmed is False
        assert self._mk(None, None, None).all_confirmed is False

    def test_any_denied_true_on_single_false(self):
        assert self._mk(True, False, True).any_denied is True
        assert self._mk(False, False, False).any_denied is True
        assert self._mk(True, True, True).any_denied is False
        # Uncertain is NOT a denial.
        assert self._mk(True, None, True).any_denied is False

    def test_any_uncertain_true_on_single_none(self):
        assert self._mk(True, None, True).any_uncertain is True
        assert self._mk(None, None, None).any_uncertain is True
        assert self._mk(True, True, False).any_uncertain is False


# ---------------------------------------------------------------------------
# Verdict vocabulary normaliser
# ---------------------------------------------------------------------------

class TestNormaliseVerdictToken:
    @pytest.mark.parametrize("token,expected", [
        ("yes", True), ("YES", True), ("Yes.", True),
        ("true", True), ("confirmed", True), ("positive", True),
        ("pass", True), ("ok", True),
        ("no", False), ("NO", False), ("no,", False),
        ("false", False), ("rejected", False), ("negative", False),
        ("fail", False), ("not", False),
        ("uncertain", None), ("unknown", None), ("unclear", None),
        ("maybe", None), ("n/a", None), ("na", None),
    ])
    def test_known_tokens(self, token, expected):
        assert rj._normalise_verdict_token(token) is expected

    def test_empty_returns_none(self):
        assert rj._normalise_verdict_token("") is None
        assert rj._normalise_verdict_token("   ") is None

    def test_unknown_returns_none(self):
        # Anything not in the vocabulary is uncertain, not a guess.
        assert rj._normalise_verdict_token("perhaps") is None
        assert rj._normalise_verdict_token("lol") is None


# ---------------------------------------------------------------------------
# parse_criteria — tolerant multi-criteria parser
# ---------------------------------------------------------------------------

class TestParseCriteria:
    def test_empty_text_yields_all_uncertain(self):
        report = rj.parse_criteria("")
        assert report.source_to_sink.verdict is None
        assert report.reachability.verdict is None
        assert report.exploitability.verdict is None
        # No criterion confirmed → not a TP downstream.
        assert report.all_confirmed is False

    def test_canonical_three_line_format(self):
        text = (
            "source_to_sink: yes (confidence: 80)\n"
            "reachability: yes (confidence: 70)\n"
            "exploitability: yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        assert report.source_to_sink.verdict is True
        assert report.source_to_sink.confidence == 80
        assert report.reachability.verdict is True
        assert report.reachability.confidence == 70
        assert report.exploitability.verdict is True
        assert report.exploitability.confidence == 60

    def test_only_some_criteria_present_others_uncertain(self):
        text = "source_to_sink: yes (confidence: 80)\n"
        report = rj.parse_criteria(text)
        assert report.source_to_sink.verdict is True
        # Missing criteria must be uncertain, not crash.
        assert report.reachability.verdict is None
        assert report.exploitability.verdict is None

    def test_alternative_yes_synonyms(self):
        for syn in ("true", "confirmed", "positive", "pass", "ok"):
            text = (
                f"source_to_sink: {syn} (confidence: 80)\n"
                f"reachability: {syn} (confidence: 80)\n"
                f"exploitability: {syn} (confidence: 80)\n"
            )
            report = rj.parse_criteria(text)
            assert report.all_confirmed is True, f"synonym {syn!r} did not parse as yes"

    def test_alternative_no_synonyms(self):
        for syn in ("false", "rejected", "negative", "fail", "not"):
            text = (
                f"source_to_sink: {syn} (confidence: 80)\n"
                f"reachability: {syn} (confidence: 80)\n"
                f"exploitability: {syn} (confidence: 80)\n"
            )
            report = rj.parse_criteria(text)
            # Each criterion is denied → aggregator should classify as FP.
            agg = rj.fine_grained_verdict(report)
            assert agg["verdict"] == "FP", f"synonym {syn!r} did not parse as no"

    def test_equals_separator(self):
        text = (
            "source_to_sink = yes (confidence: 80)\n"
            "reachability = yes (confidence: 70)\n"
            "exploitability = yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        assert report.all_confirmed is True

    def test_markdown_header_separator(self):
        text = (
            "### source_to_sink\n"
            "yes (confidence: 80)\n\n"
            "### reachability\n"
            "yes (confidence: 70)\n\n"
            "### exploitability\n"
            "yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        assert report.all_confirmed is True

    def test_trailing_punctuation_tolerated(self):
        text = (
            "source_to_sink: yes.\n"
            "reachability: yes,\n"
            "exploitability: yes!\n"
        )
        report = rj.parse_criteria(text)
        assert report.all_confirmed is True

    def test_evidence_extracted_from_backticks(self):
        text = (
            "source_to_sink: yes (confidence: 80)\n"
            "  evidence: `request.args.get('q') -> eval(q)`\n"
        )
        report = rj.parse_criteria(text)
        assert report.source_to_sink.evidence == "request.args.get('q') -> eval(q)"

    def test_evidence_extracted_from_code_label(self):
        text = (
            "reachability: no (confidence: 90)\n"
            "  Code: requires admin role\n"
        )
        report = rj.parse_criteria(text)
        assert report.reachability.verdict is False
        assert report.reachability.evidence == "requires admin role"

    def test_case_insensitive(self):
        text = (
            "Source_To_Sink: YES (Confidence: 80)\n"
            "REACHABILITY: Yes (Confidence: 70)\n"
            "Exploitability: yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        assert report.all_confirmed is True

    def test_confidence_clamped_per_criterion(self):
        text = (
            "source_to_sink: yes (confidence: 200)\n"
            "reachability: yes (confidence: -10)\n"
            "exploitability: yes (confidence: 50)\n"
        )
        report = rj.parse_criteria(text)
        assert report.source_to_sink.confidence == 100
        assert report.reachability.confidence == 0
        assert report.exploitability.confidence == 50

    def test_unknown_token_marks_uncertain_not_false(self):
        """A typo like 'ya' must not be coerced to True; it must be uncertain."""
        text = (
            "source_to_sink: ya (confidence: 80)\n"
            "reachability: yes (confidence: 70)\n"
            "exploitability: yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        assert report.source_to_sink.verdict is None
        # Aggregator must treat this as UNCERTAIN (one uncertain, two yes).
        agg = rj.fine_grained_verdict(report)
        assert agg["verdict"] == "UNCERTAIN"

    def test_blocks_do_not_bleed_into_each_other(self):
        """A confidence: N in block A must not leak into block B."""
        text = (
            "source_to_sink: yes (confidence: 80)\n"
            "reachability: no (confidence: 90)\n"
            "exploitability: yes (confidence: 60)\n"
        )
        report = rj.parse_criteria(text)
        # Per-criterion confidence must be exactly the value that appeared
        # in its own block.
        assert report.source_to_sink.confidence == 80
        assert report.reachability.confidence == 90
        assert report.exploitability.confidence == 60

    def test_raw_preserved(self):
        text = "source_to_sink: yes\nreachability: yes\nexploitability: yes\n"
        report = rj.parse_criteria(text)
        assert report.raw == text

    def test_pure_function_no_io(self, monkeypatch):
        """parse_criteria must not touch env, network or filesystem."""
        # Make any env lookup explode — if parse_criteria reads os.environ
        # at module import (anti-pattern) this would have already failed at
        # import time. As a second line of defence, nuke os.environ during
        # the call to catch any sneaky read inside the function.
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        report = rj.parse_criteria("source_to_sink: yes\nreachability: yes\nexploitability: yes\n")
        assert report.all_confirmed is True


# ---------------------------------------------------------------------------
# fine_grained_verdict — aggregator
# ---------------------------------------------------------------------------

class TestFineGrainedVerdict:
    def _report(self, sts, reach, expl, confs=(80, 70, 60)):
        return rj.CriteriaReport(
            source_to_sink=rj.Criterion(name="source_to_sink", verdict=sts, confidence=confs[0]),
            reachability=rj.Criterion(name="reachability", verdict=reach, confidence=confs[1]),
            exploitability=rj.Criterion(name="exploitability", verdict=expl, confidence=confs[2]),
        )

    def test_all_yes_is_tp_no_demote(self):
        agg = rj.fine_grained_verdict(self._report(True, True, True))
        assert agg["verdict"] == "TP"
        assert agg["demote"] is False
        assert agg["all_confirmed"] is True
        assert agg["any_denied"] is False
        assert agg["any_uncertain"] is False

    def test_all_no_is_fp_demote(self):
        agg = rj.fine_grained_verdict(self._report(False, False, False))
        assert agg["verdict"] == "FP"
        assert agg["demote"] is True
        assert agg["any_denied"] is True
        assert agg["any_uncertain"] is False

    def test_single_no_among_yes_is_fp_demote(self):
        agg = rj.fine_grained_verdict(self._report(True, False, True))
        assert agg["verdict"] == "FP"
        assert agg["demote"] is True
        assert agg["any_denied"] is True

    def test_single_uncertain_is_uncertain_demote(self):
        agg = rj.fine_grained_verdict(self._report(True, None, True))
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True
        assert agg["any_uncertain"] is True

    def test_all_uncertain_is_uncertain_demote(self):
        agg = rj.fine_grained_verdict(self._report(None, None, None))
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True

    def test_denial_with_uncertain_is_still_uncertain(self):
        """A single no AND a single uncertain must NOT be classified as FP —
        the LLM is hedging, so we cannot call it a clean false positive."""
        agg = rj.fine_grained_verdict(self._report(True, False, None))
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True

    def test_confidence_is_mean_of_three(self):
        agg = rj.fine_grained_verdict(self._report(True, True, True, confs=(80, 70, 60)))
        # (80 + 70 + 60) / 3 = 70
        assert agg["confidence"] == 70

    def test_confidence_rounded_and_clamped(self):
        # (100 + 0 + 0) / 3 = 33.33 -> rounds to 33
        agg = rj.fine_grained_verdict(self._report(True, True, True, confs=(100, 0, 0)))
        assert agg["confidence"] == 33

    def test_criteria_breakdown_shape(self):
        agg = rj.fine_grained_verdict(self._report(True, False, None))
        assert len(agg["criteria"]) == 3
        names = [c["name"] for c in agg["criteria"]]
        assert names == ["source_to_sink", "reachability", "exploitability"]
        # Each per-criterion entry has the documented wire-format keys.
        for entry in agg["criteria"]:
            assert set(entry.keys()) == {
                "name", "verdict", "verdict_bool", "confidence", "evidence",
            }
        # And the verdict string is one of the three canonical labels.
        for entry in agg["criteria"]:
            assert entry["verdict"] in ("yes", "no", "uncertain")
            assert entry["verdict_bool"] in (True, False, None)

    def test_demote_only_false_for_tp(self):
        """Property: demote is the exact inverse of (verdict == 'TP')."""
        for sts in (True, False, None):
            for reach in (True, False, None):
                for expl in (True, False, None):
                    agg = rj.fine_grained_verdict(self._report(sts, reach, expl))
                    assert agg["demote"] is (agg["verdict"] != "TP"), (
                        f"sts={sts} reach={reach} expl={expl} -> "
                        f"verdict={agg['verdict']} demote={agg['demote']}"
                    )

    def test_handles_none_report_defensively(self):
        """Passing None must NOT raise — the helper is total so callers can
        blindly chain fine_grained_verdict(parse_criteria(x))."""
        agg = rj.fine_grained_verdict(None)  # type: ignore[arg-type]
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True
        assert len(agg["criteria"]) == 3

    def test_does_not_mutate_report(self):
        report = self._report(True, True, True)
        before = report.criteria()
        rj.fine_grained_verdict(report)
        after = report.criteria()
        for a, b in zip(before, after):
            assert a.verdict == b.verdict
            assert a.confidence == b.confidence
            assert a.evidence == b.evidence

    def test_json_serialisable(self):
        import json
        agg = rj.fine_grained_verdict(self._report(True, True, True))
        # Round-trip through json.dumps — everything in the result must be
        # JSON-friendly because callers (DB writer, PR comment, audit log)
        # serialise the result.
        blob = json.dumps(agg)
        restored = json.loads(blob)
        assert restored["verdict"] == "TP"
        assert restored["demote"] is False


# ---------------------------------------------------------------------------
# End-to-end: parse_criteria() + fine_grained_verdict() on real-shaped text
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_promotional_tp_example(self):
        text = (
            "source_to_sink: yes (confidence: 85)\n"
            "  evidence: `request.args.get('q') -> eval(q)`\n"
            "reachability: yes (confidence: 75)\n"
            "  evidence: `public /search endpoint, no auth`\n"
            "exploitability: yes (confidence: 70)\n"
            "  evidence: `RCE via eval, PoC: ?q=__import__(\"os\").system(\"id\")`\n"
        )
        agg = rj.fine_grained_verdict(rj.parse_criteria(text))
        assert agg["verdict"] == "TP"
        assert agg["demote"] is False

    def test_demote_reachability_missing(self):
        text = (
            "source_to_sink: yes (confidence: 90)\n"
            "  evidence: `taint from input to sink`\n"
            "exploitability: yes (confidence: 80)\n"
            "  evidence: `RCE possible`\n"
        )
        agg = rj.fine_grained_verdict(rj.parse_criteria(text))
        # reachability is missing -> uncertain -> demote
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True

    def test_demote_no_reachability(self):
        text = (
            "source_to_sink: yes (confidence: 80)\n"
            "reachability: no (confidence: 90)\n"
            "  evidence: `admin-only endpoint behind VPN`\n"
            "exploitability: yes (confidence: 70)\n"
        )
        agg = rj.fine_grained_verdict(rj.parse_criteria(text))
        assert agg["verdict"] == "FP"
        assert agg["demote"] is True
        # Per-criterion detail preserved.
        reach = [c for c in agg["criteria"] if c["name"] == "reachability"][0]
        assert reach["verdict_bool"] is False
        assert reach["evidence"] == "admin-only endpoint behind VPN"

    def test_all_missing_is_uncertain(self):
        agg = rj.fine_grained_verdict(rj.parse_criteria(""))
        assert agg["verdict"] == "UNCERTAIN"
        assert agg["demote"] is True
        assert agg["confidence"] == 50  # all three defaults
