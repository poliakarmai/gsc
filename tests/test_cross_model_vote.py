#!/usr/bin/env python3
"""Tests for cross-model voting aggregation (Phase 2)."""

from gsc_cli.gsc_revalidate import cross_model_vote


def test_agreement_no_demote():
    r = cross_model_vote("true-positive", "true-positive", 90, 80)
    assert r["verdict"] == "true-positive"
    assert r["confidence"] == 85
    assert r["disagreement"] is False
    assert r["demote_severity"] is False
    assert r["demote_confidence"] is False


def test_disagreement_demotes():
    r = cross_model_vote("true-positive", "false-positive", 90, 80)
    assert r["disagreement"] is True
    assert r["demote_severity"] is True
    assert r["demote_confidence"] is True
    # model A verdict survives on disagreement
    assert r["verdict"] == "true-positive"


def test_confidence_averaged_and_clamped():
    r = cross_model_vote("true-positive", "true-positive", 200, -100)
    assert 0 <= r["confidence"] <= 100


def test_both_false_positive_agrees():
    r = cross_model_vote("false-positive", "false-positive", 70, 60)
    assert r["verdict"] == "false-positive"
    assert r["disagreement"] is False
    assert r["demote_severity"] is False
