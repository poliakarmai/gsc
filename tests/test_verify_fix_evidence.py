# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""tests/test_verify_fix_evidence.py — GSC-003: unified Proof-of-Fix semantics.

A PR may only be opened on a positive verification signal (tests or DAST), and
"verified" is reserved for before/after exploit evidence (ProofOfFix._classify).
rescan-only must never produce ready_for_pr=True.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gsc_verify_fix import _ready_for_pr, VerifyReport
from gsc_proofoffix import FixEvidence, ProofOfFix


def test_rescan_only_not_ready_for_pr():
    ready, reason = _ready_for_pr(tests_positive=False, dast_positive=False)
    assert ready is False
    assert "no positive verification" in reason


def test_tests_signal_ready_for_pr():
    ready, _ = _ready_for_pr(tests_positive=True, dast_positive=False)
    assert ready is True


def test_dast_signal_ready_for_pr():
    ready, _ = _ready_for_pr(tests_positive=False, dast_positive=True)
    assert ready is True


def test_both_signals_ready_for_pr():
    ready, _ = _ready_for_pr(tests_positive=True, dast_positive=True)
    assert ready is True


def test_verify_report_has_evidence_field():
    r = VerifyReport(result=None, finding_key="abc")
    assert r.evidence == "rescan"  # this verifier proves "finding gone", not exploit
    assert r.ready_for_pr is False


def test_classify_verified_requires_exploit_evidence():
    # verified = exploitable BEFORE and NOT exploitable AFTER (gold standard)
    assert ProofOfFix._classify(True, False, True, False) == "verified"
    # detector stopped firing but PoC still triggers after → NOT verified
    assert ProofOfFix._classify(True, True, True, False) != "verified"
    # no exploit signal, only detector went quiet → structural, not verified
    assert ProofOfFix._classify(False, False, True, False) == "structural"


def test_fix_evidence_tracks_skips():
    ev = FixEvidence(finding_key="abc")
    assert ev.dast_skipped is False
    assert ev.dast_skip_reason == ""
    assert ev.deep_verify_error == ""
    assert ev.verified is False
