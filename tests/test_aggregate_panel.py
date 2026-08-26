#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the multi-model panel + judge aggregator (Phase 2, GSC ROADMAP).

Two pure helpers are exercised here:

  * ``aggregate_panel(verdicts)`` — N-way majority vote over isolated
    reviewer verdicts, with a ``disagreement`` / ``split`` flag for the
    triage layer to escalate to a judge.
  * ``judge_verdict(panel_result, judge_verdict, judge_confidence)`` —
    follow-up judge step that *overrides split panels* and (with rules)
    can override majority / unanimous panels too.

These tests are pure: no LLM, no subprocess, no network, no env reads.
The two helpers live in ``gsc_cli.gsc_revalidate`` next to the
two-model ``cross_model_vote`` so the same vocabulary (``VERDICTS``)
is shared.
"""
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

# Make the repo importable when pytest is invoked from elsewhere.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from gsc_cli import gsc_revalidate as rv  # noqa: E402


# ---------------------------------------------------------------------------
# aggregate_panel — shape, unanimity, majority, split, edge cases
# ---------------------------------------------------------------------------

class TestAggregatePanelShape:
    """The contract: 7 documented keys, with the documented types."""

    def test_unanimous_three_yes(self):
        r = rv.aggregate_panel(
            [("true-positive", 90), ("true-positive", 80), ("true-positive", 70)]
        )
        assert r["verdict"] == "true-positive"
        assert r["confidence"] == 80         # mean of 90/80/70
        assert r["agreement_pct"] == 1.0
        assert r["disagreement"] is False
        assert r["unanimous"] is True
        assert r["split"] is False
        assert r["votes"] == {"true-positive": 3}

    def test_two_to_one_majority(self):
        r = rv.aggregate_panel(
            [("true-positive", 90), ("true-positive", 80), ("false-positive", 30)]
        )
        # Strict majority: 2/3 > 0.5 → not a split.
        assert r["verdict"] == "true-positive"
        assert r["agreement_pct"] == pytest.approx(2 / 3, abs=1e-4)
        assert r["disagreement"] is False
        assert r["unanimous"] is False
        assert r["split"] is False
        # Mean of ALL three confidences (90+80+30)/3 = 66.67 → 67
        assert r["confidence"] == 67
        assert r["votes"] == {"true-positive": 2, "false-positive": 1}

    def test_three_way_split_is_disagreement(self):
        r = rv.aggregate_panel(
            [("true-positive", 90), ("false-positive", 80), ("uncertain", 60)]
        )
        # 1-1-1 — no strict majority → disagreement & split both True.
        assert r["disagreement"] is True
        assert r["split"] is True
        assert r["unanimous"] is False
        assert r["agreement_pct"] == pytest.approx(1 / 3, abs=1e-4)
        # Tie-break: VERDICTS order — "false-positive", "true-positive", "uncertain".
        # So the top of the tie is the FIRST label in VERDICTS order among the
        # tied bucket: we must verify determinism, not the specific label.
        assert r["verdict"] in ("true-positive", "false-positive", "uncertain")
        assert r["confidence"] == 77  # (90+80+60)/3 = 76.67 → 77
        # All three labels present in the votes dict.
        assert r["votes"]["true-positive"] == 1
        assert r["votes"]["false-positive"] == 1
        assert r["votes"]["uncertain"] == 1

    def test_split_unanimous_aliases_agree(self):
        """disagreement and split are aliases by design — they must always
        be equal. Callers may pick whichever reads better at the call site."""
        for verdicts in (
            [],
            [("true-positive", 50)],
            [("true-positive", 50), ("false-positive", 50)],
            [("true-positive", 50), ("false-positive", 50), ("uncertain", 50)],
            [("true-positive", 50), ("true-positive", 50), ("false-positive", 50)],
        ):
            r = rv.aggregate_panel(verdicts)
            assert r["disagreement"] == r["split"], (
                f"disagreement != split for input {verdicts}: {r}"
            )


class TestAggregatePanelEdgeCases:
    def test_empty_input(self):
        r = rv.aggregate_panel([])
        assert r["verdict"] == "uncertain"
        assert r["confidence"] == 0
        assert r["agreement_pct"] == 0.0
        assert r["disagreement"] is True
        assert r["unanimous"] is False
        assert r["split"] is True
        assert r["votes"] == {}

    def test_single_vote_unanimous(self):
        r = rv.aggregate_panel([("true-positive", 77)])
        assert r["verdict"] == "true-positive"
        assert r["confidence"] == 77
        assert r["agreement_pct"] == 1.0
        assert r["unanimous"] is True
        assert r["disagreement"] is False
        assert r["votes"] == {"true-positive": 1}

    def test_two_vote_split_is_disagreement(self):
        # 1-1 with 2 voters — also no strict majority (top*2=2 == total).
        r = rv.aggregate_panel([("true-positive", 90), ("false-positive", 80)])
        assert r["disagreement"] is True
        assert r["split"] is True
        assert r["unanimous"] is False
        # Tie-break: "true-positive" comes first in VERDICTS order
        # ("true-positive", "false-positive", "fixed", "uncertain").
        assert r["verdict"] == "true-positive"
        assert r["confidence"] == 85  # (90+80)/2

    def test_four_voters_with_majority(self):
        r = rv.aggregate_panel(
            [
                ("true-positive", 90),
                ("true-positive", 80),
                ("true-positive", 70),
                ("false-positive", 50),
            ]
        )
        # 3/4 — strict majority (3*2=6 > 4).
        assert r["verdict"] == "true-positive"
        assert r["disagreement"] is False
        assert r["unanimous"] is False
        assert r["agreement_pct"] == pytest.approx(0.75, abs=1e-4)
        assert r["confidence"] == 73  # (90+80+70+50)/4 = 72.5 → 73

    def test_confidence_clamped_to_range(self):
        r = rv.aggregate_panel(
            [("true-positive", 200), ("true-positive", -100), ("true-positive", 50)]
        )
        # All coerce to [0, 100], then mean: (100+0+50)/3 = 50.
        assert 0 <= r["confidence"] <= 100
        assert r["confidence"] == 50

    def test_four_way_split(self):
        """A 4-way 1-1-1-1 panel must still flag disagreement (no majority)."""
        r = rv.aggregate_panel(
            [
                ("true-positive", 90),
                ("false-positive", 80),
                ("fixed", 70),
                ("uncertain", 60),
            ]
        )
        assert r["disagreement"] is True
        assert r["split"] is True
        assert r["unanimous"] is False
        assert r["agreement_pct"] == pytest.approx(0.25, abs=1e-4)

    def test_accepts_list_pairs_not_just_tuples(self):
        """Callers may pass 2-element lists instead of tuples — both are
        supported. This matters because JSON-decoded inputs come back as lists."""
        r = rv.aggregate_panel(
            [["true-positive", 90], ["true-positive", 80], ["true-positive", 70]]
        )
        assert r["verdict"] == "true-positive"
        assert r["unanimous"] is True

    def test_skips_malformed_pairs(self):
        """Pairs missing the verdict or confidence are silently dropped —
        the aggregator must be total, not crash on bad input."""
        r = rv.aggregate_panel(
            [
                ("true-positive", 90),
                None,                       # dropped
                ("false-positive",),        # too short — dropped
                ("", 80),                   # empty verdict — dropped
                (None, 80),                 # None verdict — dropped
                ("uncertain",),              # too short — dropped
                ("true-positive", "nope"),   # unparseable confidence → 0
                ("true-positive", 70),
            ]
        )
        # We end up with 3 valid pairs: TP/90, TP/0, TP/70. Unanimous TP.
        assert r["verdict"] == "true-positive"
        assert r["unanimous"] is True
        # (90+0+70)/3 = 53.33 → 53
        assert r["confidence"] == 53

    def test_all_malformed_yields_uncertain(self):
        r = rv.aggregate_panel([None, ("", 50), (None, 50), ("uncertain",)])
        assert r["verdict"] == "uncertain"
        assert r["confidence"] == 0
        assert r["disagreement"] is True
        assert r["votes"] == {}

    def test_does_not_mutate_input(self):
        verdicts = [("true-positive", 90), ("false-positive", 80), ("uncertain", 70)]
        snapshot = deepcopy(verdicts)
        rv.aggregate_panel(verdicts)
        assert verdicts == snapshot

    def test_tie_break_is_deterministic(self):
        """Same input must produce the same output across calls — the
        tie-break is canonical VERDICTS order, not hash order."""
        verdicts = [("true-positive", 50), ("false-positive", 50), ("uncertain", 50)]
        first = rv.aggregate_panel(verdicts)
        for _ in range(20):
            again = rv.aggregate_panel(verdicts)
            assert again == first
        # And the winner is the FIRST tied label in VERDICTS order.
        assert first["verdict"] == "true-positive"  # 't' < 'f' < 'u' in VERDICTS

    def test_json_serialisable(self):
        """The aggregator result is round-tripped through JSON by callers
        (DB writers, audit logs, PR comments) so it must be JSON-friendly."""
        r = rv.aggregate_panel(
            [("true-positive", 90), ("false-positive", 80), ("true-positive", 70)]
        )
        blob = json.dumps(r)
        restored = json.loads(blob)
        assert restored == r
        # votes must serialise as a plain dict (not a Counter).
        assert isinstance(r["votes"], dict)

    def test_pure_function_no_io(self, monkeypatch):
        """aggregate_panel must NOT touch env / network / filesystem."""
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        r = rv.aggregate_panel(
            [("true-positive", 90), ("true-positive", 80), ("true-positive", 70)]
        )
        assert r["unanimous"] is True


# ---------------------------------------------------------------------------
# judge_verdict — 5 rules, audit fields, immutability
# ---------------------------------------------------------------------------

def _make_unanimous(verdict="true-positive", conf=80):
    """Build a synthetic unanimous panel result (3 of 3 agree)."""
    return rv.aggregate_panel(
        [(verdict, conf), (verdict, conf), (verdict, conf)]
    )


def _make_split():
    """Build a synthetic 1-1-1 split panel."""
    return rv.aggregate_panel(
        [("true-positive", 90), ("false-positive", 80), ("uncertain", 70)]
    )


def _make_majority(verdict="true-positive", conf=85):
    """Build a synthetic 2-1 majority panel."""
    return rv.aggregate_panel(
        [(verdict, conf), (verdict, max(10, conf - 10)), ("false-positive", 30)]
    )


class TestJudgeVerdictShape:
    """The contract: every key from the panel result survives, plus 6 new
    judge-specific keys, in a freshly-allocated dict (no mutation)."""

    def test_panel_keys_preserved(self):
        p = _make_unanimous()
        r = rv.judge_verdict(p, "true-positive", 90)
        for k, v in p.items():
            assert r[k] == v, f"key {k!r} changed: {v!r} -> {r[k]!r}"

    def test_judge_keys_present(self):
        p = _make_unanimous()
        r = rv.judge_verdict(p, "true-positive", 90)
        # All 6 new keys must be present.
        for k in (
            "final_verdict", "final_confidence", "judge_verdict",
            "judge_confidence", "judge_overrode", "judge_overrode_split",
            "reason",
        ):
            assert k in r, f"missing key {k!r} in judge result"

    def test_does_not_mutate_input_panel(self):
        p = _make_unanimous(conf=80)
        snapshot = deepcopy(p)
        rv.judge_verdict(p, "false-positive", 95)
        assert p == snapshot


class TestJudgeVerdictRules:
    """The 5 rules in the docstring must fire in the documented order."""

    def test_rule4_split_panel_judge_replaces(self):
        """Rule 4: split panel → judge wins (regardless of confidence)."""
        p = _make_split()
        # Pick a judge verdict that is DIFFERENT from the tie-break winner
        # ("true-positive" wins the tie because it's first in VERDICTS), so
        # the override-flag assertion is meaningful.
        r = rv.judge_verdict(p, "false-positive", 5)
        assert r["final_verdict"] == "false-positive"
        assert r["final_confidence"] == 5
        assert r["judge_overrode_split"] is True
        assert r["judge_overrode"] is True
        assert r["reason"] == "judge_replaces_split"

    def test_rule4_split_judge_agrees_no_label_override_flag(self):
        """When the split judge happens to pick the same label as the
        panel's tie-break winner, judge_overrode (label-change flag) is
        False, but judge_overrode_split is still True (the structural
        replacement happened; the label just happened to coincide). This
        lets callers distinguish 'judge flipped the call' from 'judge
        backed the panel by coincidence'."""
        p = _make_split()
        # tie-break winner is "true-positive" (first in VERDICTS order).
        r = rv.judge_verdict(p, "true-positive", 80)
        assert r["judge_overrode_split"] is True
        # judge_overrode reflects label-change, not structural replacement.
        assert r["judge_overrode"] is False

    def test_rule2_unanimous_match_judge_boosts(self):
        """Rule 2: unanimous panel + same-label judge → boost (mean)."""
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "true-positive", 90)
        assert r["final_verdict"] == "true-positive"
        # (80 + 90) / 2 = 85
        assert r["final_confidence"] == 85
        assert r["judge_overrode"] is False
        assert r["judge_overrode_split"] is False
        assert r["reason"] == "judge_boosted_unanimous"

    def test_rule2_unanimous_match_odd_average_rounds(self):
        """The boost is integer-rounded (round-half-up): 80+91=171/2=85.5→86."""
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "true-positive", 91)
        assert r["final_confidence"] == 86

    def test_rule3_unanimous_disagree_judge_overrides(self):
        """Rule 3: unanimous panel + disagreeing judge → judge wins
        (the more authoritative model overrides the cheap consensus)."""
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "false-positive", 95)
        assert r["final_verdict"] == "false-positive"
        assert r["final_confidence"] == 95
        assert r["judge_overrode"] is True
        assert r["judge_overrode_split"] is False
        assert r["reason"] == "judge_unanimity_override"

    def test_rule5_majority_low_confidence_judge_panel_survives(self):
        """Rule 5: majority (2-1) + low-confidence disagreeing judge → panel
        survives. A 20-conf judge must not flip a 90-conf majority."""
        p = _make_majority(verdict="true-positive", conf=90)
        # mean conf for 2-1: (90+80+30)/3 = 66.67 → 67
        assert p["confidence"] == 67
        r = rv.judge_verdict(p, "false-positive", 20)
        assert r["final_verdict"] == "true-positive"
        assert r["final_confidence"] == 67
        assert r["judge_overrode"] is False
        assert r["judge_overrode_split"] is False
        assert r["reason"] == "panel_survives"

    def test_rule5_majority_high_confidence_judge_wins(self):
        """Rule 5: majority + high-confidence disagreeing judge → judge wins."""
        p = _make_majority(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "false-positive", 95)
        assert r["final_verdict"] == "false-positive"
        assert r["final_confidence"] == 95
        assert r["judge_overrode"] is True
        assert r["judge_overrode_split"] is False
        assert r["reason"] == "judge_overrode_majority"

    def test_rule5_majority_tied_confidence_panel_survives(self):
        """Rule 5 strict: judge must be STRICTLY higher than panel — tie goes
        to the panel. (20+50)/2=35 panel conf, judge=35 → panel wins."""
        p = rv.aggregate_panel(
            [("true-positive", 20), ("true-positive", 50), ("false-positive", 30)]
        )
        # (20+50+30)/3 = 33.33 → 33
        assert p["confidence"] == 33
        r = rv.judge_verdict(p, "false-positive", 33)
        # Tied at 33 → panel survives (rule: strictly higher).
        assert r["final_verdict"] == "true-positive"
        assert r["reason"] == "panel_survives"

    def test_rule5_majority_agrees_no_override(self):
        """2-1 majority where the judge agrees with the majority → panel
        survives, no override flag."""
        p = _make_majority(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "true-positive", 90)
        assert r["final_verdict"] == "true-positive"
        assert r["judge_overrode"] is False
        assert r["reason"] == "panel_survives"


class TestJudgeVerdictDefensive:
    """Total function: never raises, always returns the documented shape."""

    def test_none_panel_input_still_works(self):
        r = rv.judge_verdict(None, "true-positive", 80)  # type: ignore[arg-type]
        # None is treated as an "uncertain" panel → split → judge replaces.
        assert r["final_verdict"] == "true-positive"
        assert r["final_confidence"] == 80
        assert r["judge_overrode_split"] is True
        assert r["reason"] == "judge_replaces_split"

    def test_non_dict_panel_input_still_works(self):
        r = rv.judge_verdict("not a dict", "true-positive", 80)  # type: ignore[arg-type]
        assert r["final_verdict"] == "true-positive"
        assert r["judge_overrode_split"] is True

    def test_empty_judge_verdict_becomes_uncertain(self):
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "", 80)
        assert r["judge_verdict"] == "uncertain"
        # Empty judge → unanimous TP, judge=uncertain: that's a disagreement.
        assert r["final_verdict"] == "uncertain"
        assert r["judge_overrode"] is True
        assert r["reason"] == "judge_unanimity_override"

    def test_none_judge_verdict_becomes_uncertain(self):
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, None, 80)  # type: ignore[arg-type]
        assert r["judge_verdict"] == "uncertain"

    def test_judge_confidence_clamped_high(self):
        p = _make_split()
        r = rv.judge_verdict(p, "true-positive", 9999)
        assert r["judge_confidence"] == 100
        assert r["final_confidence"] == 100

    def test_judge_confidence_clamped_low(self):
        p = _make_split()
        r = rv.judge_verdict(p, "true-positive", -100)
        assert r["judge_confidence"] == 0
        assert r["final_confidence"] == 0

    def test_judge_confidence_non_numeric_uses_zero(self):
        p = _make_split()
        r = rv.judge_verdict(p, "true-positive", "nope")  # type: ignore[arg-type]
        assert r["judge_confidence"] == 0

    def test_pure_function_no_io(self, monkeypatch):
        """judge_verdict must not touch env / network / filesystem."""
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        p = _make_split()
        r = rv.judge_verdict(p, "true-positive", 80)
        assert r["final_verdict"] == "true-positive"

    def test_json_serialisable(self):
        """Round-trip through JSON — judge result is stored in the audit log."""
        p = _make_unanimous(verdict="true-positive", conf=80)
        r = rv.judge_verdict(p, "true-positive", 90)
        blob = json.dumps(r)
        restored = json.loads(blob)
        assert restored == r


class TestJudgeVerdictAllVerdicts:
    """The judge must handle the full VERDICTS vocabulary, not just TP/FP."""

    @pytest.mark.parametrize("verdict", ["true-positive", "false-positive", "fixed", "uncertain"])
    def test_unanimous_match_across_vocabulary(self, verdict):
        p = _make_unanimous(verdict=verdict, conf=80)
        r = rv.judge_verdict(p, verdict, 90)
        assert r["final_verdict"] == verdict
        assert r["reason"] == "judge_boosted_unanimous"

    @pytest.mark.parametrize("verdict", ["true-positive", "false-positive", "fixed", "uncertain"])
    def test_unanimous_disagree_across_vocabulary(self, verdict):
        p = _make_unanimous(verdict=verdict, conf=80)
        other = "false-positive" if verdict != "false-positive" else "true-positive"
        r = rv.judge_verdict(p, other, 95)
        assert r["final_verdict"] == other
        assert r["reason"] == "judge_unanimity_override"


# ---------------------------------------------------------------------------
# End-to-end: aggregate_panel + judge_verdict on the same input
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_classic_three_tp_unanimous(self):
        """3 reviewers all say TP, judge agrees → no override, boost applied."""
        panel = rv.aggregate_panel(
            [("true-positive", 90), ("true-positive", 80), ("true-positive", 70)]
        )
        assert panel["unanimous"] is True
        result = rv.judge_verdict(panel, "true-positive", 95)
        assert result["final_verdict"] == "true-positive"
        assert result["final_confidence"] == 88  # (80+95)/2 = 87.5 → 88
        assert result["judge_overrode"] is False
        assert result["reason"] == "judge_boosted_unanimous"

    def test_classic_three_way_split(self):
        """1-1-1 panel → judge gets to decide."""
        panel = rv.aggregate_panel(
            [("true-positive", 90), ("false-positive", 80), ("uncertain", 60)]
        )
        assert panel["split"] is True
        result = rv.judge_verdict(panel, "true-positive", 85)
        assert result["final_verdict"] == "true-positive"
        assert result["final_confidence"] == 85
        assert result["judge_overrode_split"] is True

    def test_classic_two_to_one_judge_aligns(self):
        """2-1 majority, judge agrees → no override."""
        panel = rv.aggregate_panel(
            [("true-positive", 90), ("true-positive", 80), ("false-positive", 30)]
        )
        result = rv.judge_verdict(panel, "true-positive", 75)
        assert result["final_verdict"] == "true-positive"
        assert result["judge_overrode"] is False

    def test_classic_two_to_one_judge_overrides_with_high_conf(self):
        """2-1 majority, judge disagrees with higher confidence → override."""
        panel = rv.aggregate_panel(
            [("true-positive", 60), ("true-positive", 70), ("false-positive", 30)]
        )
        # panel mean: (60+70+30)/3 = 53.33 → 53
        assert panel["confidence"] == 53
        result = rv.judge_verdict(panel, "false-positive", 90)
        assert result["final_verdict"] == "false-positive"
        assert result["judge_overrode"] is True
        assert result["reason"] == "judge_overrode_majority"
