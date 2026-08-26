#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for logprob-based confidence extraction (Phase 2, GSC ROADMAP).

Replaces the fragile regex-based ``_extract_confidence`` with a calibrated
signal derived from the LLM's per-token logprobs. These tests are pure:
they never hit the network or call the LLM — they feed canned
``logprobs`` payloads to ``confidence_from_logprobs`` and check the
resulting percentage.

Four input shapes are supported (see docstring of
:func:`gsc_cli.gsc_rejudge.confidence_from_logprobs`):

  1. OpenAI v2 — ``logprobs.content`` is a list of
     ``{"token": str, "logprob": float, ...}`` entries.
  2. OpenAI legacy — ``logprobs.top_logprobs`` is a list of
     ``{token: logprob, ...}`` dicts.
  3. Flat list — ``[{"token", "logprob"}, ...]`` or
     ``[(token, logprob), ...]``.
  4. Single dict — ``{"token": str, "logprob": float}``.

Plus a convenience: the full ``{"choices": [...]}`` response is unwrapped
automatically. The function is total — malformed input returns ``None``,
and the higher-level :func:`extract_confidence` falls back to the regex
path.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

# Make the repo importable when pytest is invoked from elsewhere.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from gsc_cli import gsc_rejudge as rj  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lp(prob: float) -> float:
    """Convert a probability in (0, 1] to a natural-log logprob."""
    return math.log(prob)


# ---------------------------------------------------------------------------
# _logprob_to_percent — single-value conversion
# ---------------------------------------------------------------------------

class TestLogprobToPercent:
    def test_prob_one_is_100(self):
        # logprob == 0  →  prob == 1.0  →  100%
        assert rj._logprob_to_percent(0.0) == 100.0

    def test_prob_half_is_50(self):
        # logprob(0.5) ≈ -0.693  →  prob 0.5  →  50%
        assert rj._logprob_to_percent(_lp(0.5)) == pytest.approx(50.0)

    def test_prob_tenth_is_10(self):
        assert rj._logprob_to_percent(_lp(0.1)) == pytest.approx(10.0)

    def test_floor_clamp_keeps_value_near_zero(self):
        # A wildly negative logprob (token was a needle in a haystack)
        # is clamped to _LOGPROB_FLOOR, then converted via exp(). The
        # resulting probability is near-zero (not exactly zero — by
        # design, so a single bad token does not poison the average).
        out = rj._logprob_to_percent(-100.0)
        assert 0.0 <= out < 0.001  # essentially 0%, but non-negative

    def test_ceil_clamp_to_100(self):
        # Symmetric: a positive logprob is impossible (probability > 1)
        # but if the API ever returns one, we still produce 100%, not garbage.
        assert rj._logprob_to_percent(0.5) == 100.0

    def test_none_returns_zero(self):
        assert rj._logprob_to_percent(None) == 0.0

    def test_non_numeric_returns_zero(self):
        assert rj._logprob_to_percent("nope") == 0.0
        assert rj._logprob_to_percent(object()) == 0.0

    def test_nan_returns_zero(self):
        assert rj._logprob_to_percent(float("nan")) == 0.0

    def test_returns_float_in_zero_to_100(self):
        for v in (0.0, -0.5, -1.0, -5.0, -20.0, 0.0):
            p = rj._logprob_to_percent(v)
            assert 0.0 <= p <= 100.0


# ---------------------------------------------------------------------------
# _normalise_logprobs — shape detection
# ---------------------------------------------------------------------------

class TestNormaliseLogprobs:
    def test_none_returns_none(self):
        assert rj._normalise_logprobs(None) is None

    def test_single_dict_with_logprob_key(self):
        out = rj._normalise_logprobs({"token": "TP", "logprob": -0.5})
        assert out == [-0.5]

    def test_single_legacy_dict(self):
        # {"TP": -0.5}  — no "logprob" key, but values are numeric
        out = rj._normalise_logprobs({"TP": -0.5, "FP": -2.0})
        # Order of dict values is preserved (Python 3.7+); the API contract
        # here is "use whatever values you find".
        assert out == [-0.5, -2.0]

    def test_single_dict_non_numeric_returns_none(self):
        assert rj._normalise_logprobs({"token": "TP", "logprob": "nope"}) is None

    def test_flat_list_of_dicts_v2(self):
        out = rj._normalise_logprobs([
            {"token": "TP", "logprob": -0.1},
            {"token": " con", "logprob": -0.2},
        ])
        assert out == [-0.1, -0.2]

    def test_flat_list_of_tuples(self):
        out = rj._normalise_logprobs([("TP", -0.1), ("FP", -2.0)])
        assert out == [-0.1, -2.0]

    def test_flat_list_of_lists(self):
        out = rj._normalise_logprobs([["TP", -0.1], ["FP", -2.0]])
        assert out == [-0.1, -2.0]

    def test_flat_list_of_bare_numbers(self):
        out = rj._normalise_logprobs([-0.1, -0.2, -0.3])
        assert out == [-0.1, -0.2, -0.3]

    def test_list_mixed_shapes(self):
        out = rj._normalise_logprobs([
            {"token": "TP", "logprob": -0.1},
            ("FP", -0.2),
            -0.3,
            None,  # skipped
            "stray",  # skipped
        ])
        assert out == [-0.1, -0.2, -0.3]

    def test_empty_list_returns_none(self):
        assert rj._normalise_logprobs([]) is None

    def test_non_iterable_returns_none(self):
        assert rj._normalise_logprobs(42) is None
        assert rj._normalise_logprobs(3.14) is None


# ---------------------------------------------------------------------------
# confidence_from_logprobs — the public API
# ---------------------------------------------------------------------------

class TestConfidenceFromLogprobs:
    # --- OpenAI v2 shape (preferred) ---

    def test_openai_v2_single_token_high_confidence(self):
        # Token "TP" with logprob -0.05 → prob ≈ 0.95 → 95%
        logprobs = {"content": [{"token": "TP", "logprob": -0.05}]}
        assert rj.confidence_from_logprobs(logprobs) == 95

    def test_openai_v2_single_token_low_confidence(self):
        # Token "FP" with logprob -2.3 → prob ≈ 0.1 → 10%
        logprobs = {"content": [{"token": "FP", "logprob": -2.3}]}
        assert rj.confidence_from_logprobs(logprobs) == 10

    def test_openai_v2_multi_token_uses_chosen(self):
        # Each entry's `logprob` is the *chosen* token's probability mass;
        # we average across all chosen tokens.
        logprobs = {
            "content": [
                {"token": "EXPLOIT", "logprob": -0.1},   # ~90%
                {"token": "ABLE", "logprob": -0.2},      # ~82%
                # Average prob = (0.905 + 0.819) / 2 ≈ 86% → 86
            ]
        }
        # Don't pin the exact value (rounding) — just the ballpark.
        out = rj.confidence_from_logprobs(logprobs)
        assert 84 <= out <= 88

    def test_openai_v2_drops_top_logprobs_field(self):
        # The `top_logprobs` field is a list of alternatives; we MUST NOT
        # double-count it. The chosen token is already in `logprob`.
        logprobs = {
            "content": [
                {
                    "token": "TP",
                    "logprob": -0.1,            # chosen: ~90%
                    "top_logprobs": [            # alternatives — MUST ignore
                        {"token": "TP", "logprob": -0.1},
                        {"token": "FP", "logprob": -0.5},
                    ],
                }
            ]
        }
        out = rj.confidence_from_logprobs(logprobs)
        # If we accidentally included top_logprobs, the average would be
        # much lower (mixing in 0.6 from "FP"). 90% is the right answer.
        assert out == 90

    # --- OpenAI legacy shape ---

    def test_legacy_top_logprobs(self):
        logprobs = {
            "top_logprobs": [
                {"TP": -0.05, "FP": -3.0},  # chosen = TP, prob 0.95
            ]
        }
        assert rj.confidence_from_logprobs(logprobs) == 95

    def test_legacy_top_logprobs_multi_token(self):
        logprobs = {
            "top_logprobs": [
                {"EXPLOIT": -0.1},
                {"ABLE": -0.1},
            ]
        }
        # both ~90% → avg ~90
        out = rj.confidence_from_logprobs(logprobs)
        assert 89 <= out <= 91

    # --- Flat list shape ---

    def test_flat_list_of_dicts(self):
        out = rj.confidence_from_logprobs([
            {"token": "TP", "logprob": _lp(0.9)},
            {"token": "FP", "logprob": _lp(0.1)},
        ])
        # (90 + 10) / 2 = 50
        assert out == 50

    def test_flat_list_of_tuples(self):
        out = rj.confidence_from_logprobs([("TP", _lp(0.99))])
        assert out == 99

    def test_bare_number_list(self):
        out = rj.confidence_from_logprobs([_lp(0.75), _lp(0.75)])
        assert out == 75

    # --- Single dict shape ---

    def test_single_dict(self):
        out = rj.confidence_from_logprobs({"token": "TP", "logprob": -1.0})
        # prob = e^-1 ≈ 0.368 → 37%
        assert out == 37

    # --- Wrapped response shape ---

    def test_full_response_wrapper_v2(self):
        # Caller passes the entire chat-completions response; we dig in.
        response = {
            "choices": [
                {
                    "message": {"content": "TP"},
                    "logprobs": {
                        "content": [{"token": "TP", "logprob": -0.1}],
                    },
                }
            ]
        }
        assert rj.confidence_from_logprobs(response) == 90

    def test_full_response_wrapper_legacy(self):
        response = {
            "choices": [
                {
                    "message": {"content": "TP"},
                    "logprobs": {
                        "top_logprobs": [{"TP": -0.1, "FP": -2.0}],
                    },
                }
            ]
        }
        out = rj.confidence_from_logprobs(response)
        # -0.1 → ~90% (rounded)
        assert 89 <= out <= 91

    def test_full_response_with_empty_choices_returns_none(self):
        assert rj.confidence_from_logprobs({"choices": []}) is None

    # --- Degenerate input ---

    def test_none_returns_none(self):
        assert rj.confidence_from_logprobs(None) is None

    def test_empty_list_returns_none(self):
        assert rj.confidence_from_logprobs([]) is None

    def test_garbage_string_returns_none(self):
        # A bare string is iterable (its chars) but no character is a usable
        # logprob. We return None rather than guessing.
        assert rj.confidence_from_logprobs("nope") is None

    def test_int_input_returns_none(self):
        assert rj.confidence_from_logprobs(42) is None

    def test_dict_without_logprob_or_choices_returns_none(self):
        # {"foo": "bar"} is unrecognised — no logprob-like data anywhere.
        assert rj.confidence_from_logprobs({"foo": "bar"}) is None

    def test_very_negative_logprob_clamps_to_zero(self):
        # A near-zero probability token still contributes 0% (clamped), not
        # negative noise that would skew the average.
        out = rj.confidence_from_logprobs([_lp(1e-9), _lp(0.99)])
        # (0 + 99) / 2 = 49.5 → 50 (rounded banker's; we use standard half-up)
        assert 49 <= out <= 50

    def test_very_positive_logprob_clamps_to_100(self):
        # Defensive: positive logprobs (prob > 1) are impossible but if the
        # API ever returns one, we still produce a valid percentage.
        out = rj.confidence_from_logprobs([0.5, 0.0])
        # (100 + 100) / 2 = 100
        assert out == 100

    def test_result_clamped_to_100(self):
        # Property: the result is always in [0, 100] regardless of input.
        for prob in (1e-12, 0.001, 0.5, 0.999, 1.0):
            out = rj.confidence_from_logprobs([{"logprob": _lp(prob)}])
            assert 0 <= out <= 100


# ---------------------------------------------------------------------------
# extract_confidence — wrapper with regex fallback
# ---------------------------------------------------------------------------

class TestExtractConfidenceWrapper:
    def test_logprobs_take_precedence_when_given(self):
        # Caller supplies logprobs → we use them, NOT the text.
        out = rj.extract_confidence(
            "confidence: 5",  # would yield 5 via regex
            logprobs=[{"token": "TP", "logprob": _lp(0.9)}],  # yields 90
        )
        assert out == 90

    def test_logprobs_none_falls_back_to_regex(self):
        assert rj.extract_confidence("confidence: 75", logprobs=None) == 75
        assert rj.extract_confidence("confidence: 75") == 75

    def test_logprobs_empty_list_falls_back_to_regex(self):
        # Empty list → confidence_from_logprobs returns None → fall through.
        assert rj.extract_confidence("confidence: 88", logprobs=[]) == 88

    def test_logprobs_garbage_falls_back_to_regex(self):
        # Unparseable logprobs → fall through to regex.
        assert rj.extract_confidence("confidence: 42", logprobs="nope") == 42

    def test_logprobs_garbage_no_regex_returns_default(self):
        # No logprobs AND no regex match → default 50 (legacy behaviour).
        assert rj.extract_confidence("no confidence here", logprobs="nope") == 50

    def test_text_only_legacy_path_unchanged(self):
        # The single-arg call must behave exactly like _extract_confidence —
        # this is the backward-compat contract. (The legacy regex uses
        # `[:\s]*` between "conf" and the number — it accepts `:` and
        # whitespace but NOT `=`. This is pre-existing behaviour, not
        # something we change here.)
        assert rj.extract_confidence("Confidence: 60") == 60
        assert rj.extract_confidence("conf  60") == 60
        assert rj.extract_confidence("no number at all") == 50

    def test_text_with_logprob_wrapper_response(self):
        response = {
            "choices": [
                {"logprobs": {"content": [{"token": "TP", "logprob": -0.5}]}}
            ]
        }
        # exp(-0.5) ≈ 0.607 → 61%
        out = rj.extract_confidence("confidence: 99", logprobs=response)
        assert 60 <= out <= 61


# ---------------------------------------------------------------------------
# _extract_confidence — backward compat: behaviour unchanged
# ---------------------------------------------------------------------------

class TestExtractConfidenceBackwardCompat:
    def test_still_returns_int(self):
        # The legacy contract: always returns int, never None.
        result = rj._extract_confidence("confidence: 70")
        assert isinstance(result, int)
        assert result == 70

    def test_still_default_50_on_no_match(self):
        assert rj._extract_confidence("nothing to see here") == 50

    def test_still_tolerates_whitespace(self):
        assert rj._extract_confidence("confidence  :   80") == 80

    def test_still_case_insensitive(self):
        assert rj._extract_confidence("CONFIDENCE: 90") == 90
        assert rj._extract_confidence("Conf: 40") == 40

    def test_still_works_with_other_text_around(self):
        # The original behaviour: any "confidence: N" anywhere in the text.
        assert rj._extract_confidence(
            "Some preamble\nconfidence: 65\nSome epilogue"
        ) == 65


# ---------------------------------------------------------------------------
# Integration: validate_poc is unaffected
# ---------------------------------------------------------------------------

class TestValidatePocIntegration:
    """The PoC path currently passes no logprobs, so the regex path is what
    runs. We must not regress that behaviour."""

    def test_legacy_validate_poc_default_50(self, monkeypatch):
        # Stub out the subprocess call so validate_poc runs in isolation.
        # The default confidence (50) should come from _extract_confidence,
        # not from any logprob path — because no logprobs are passed.
        # Note: validate_poc needs >=2 votes for a non-NEEDS_REVIEW verdict;
        # we just verify the confidence-default path here.
        monkeypatch.setattr(
            rj, "rejudge",
            lambda prompt, timeout=120: (True, "verdict: EXPLOITABLE"),
        )
        out = rj.validate_poc("some PoC text")
        # No "confidence: N" in the canned text → legacy default 50.
        assert out["confidence"] == 50
        assert isinstance(out["confidence"], int)

    def test_validate_poc_parses_confidence_from_text(self, monkeypatch):
        monkeypatch.setattr(
            rj, "rejudge",
            lambda prompt, timeout=120: (True, "verdict: EXPLOITABLE\nconfidence: 77")
        )
        out = rj.validate_poc("some PoC text")
        assert out["confidence"] == 77
