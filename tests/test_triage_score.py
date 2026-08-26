#!/usr/bin/env python3
"""Tests for the auto-triage scoring fusion (Phase 2)."""

from gsc_cli.gsc_revalidate import triage_score


def test_tp_multi_regex_escalates():
    r = triage_score(3, "true-positive", 90)
    assert r["category"] == "escalate"
    assert r["score"] >= 70


def test_fp_auto_closes():
    r = triage_score(1, "false-positive", 60)
    assert r["category"] == "auto-close"
    assert r["score"] < 30


def test_uncertain_needs_review():
    r = triage_score(1, "uncertain", 50)
    assert r["category"] == "needs-review"


def test_low_score_auto_closes():
    # even without an explicit FP verdict, a rock-bottom score auto-closes
    r = triage_score(0, "uncertain", 0)
    assert r["category"] == "auto-close"


def test_score_clamped_to_bounds():
    r = triage_score(3, "true-positive", 200)
    assert 0 <= r["score"] <= 100


def test_zero_regex_hits_lowers_score():
    # scanner/LLM divergence: no regex hit penalises the score
    base = triage_score(1, "true-positive", 80)["score"]
    diverged = triage_score(0, "true-positive", 80)["score"]
    assert diverged < base


def test_bad_input_is_total():
    r = triage_score(None, None, "garbage")
    assert r["category"] in ("auto-close", "needs-review", "escalate")
    assert 0 <= r["score"] <= 100
