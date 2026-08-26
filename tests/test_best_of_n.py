#!/usr/bin/env python3
"""Tests for the Best-of-N self-verification aggregator."""

from gsc_cli.gsc_revalidate import best_of_n_verdict


def test_unanimous_verdict():
    r = best_of_n_verdict([("true-positive", 80), ("true-positive", 70)])
    assert r["verdict"] == "true-positive"
    assert r["confidence"] == 75
    assert r["agreement_pct"] == 1.0
    assert r["disagreement"] is False


def test_majority_of_three():
    r = best_of_n_verdict(
        [("true-positive", 90), ("true-positive", 80), ("false-positive", 70)]
    )
    assert r["verdict"] == "true-positive"
    assert r["confidence"] == 80
    assert r["disagreement"] is False
    assert abs(r["agreement_pct"] - 0.6667) < 1e-6


def test_split_is_disagreement():
    r = best_of_n_verdict([("true-positive", 80), ("false-positive", 60)])
    assert r["disagreement"] is True
    # deterministic tie-break: true-positive wins by VERDICTS order
    assert r["verdict"] == "true-positive"


def test_empty_returns_uncertain():
    r = best_of_n_verdict([])
    assert r["verdict"] == "uncertain"
    assert r["confidence"] == 0
    assert r["disagreement"] is True


def test_confidence_clamped_to_bounds():
    r = best_of_n_verdict([("true-positive", 200), ("true-positive", -50)])
    assert 0 <= r["confidence"] <= 100
