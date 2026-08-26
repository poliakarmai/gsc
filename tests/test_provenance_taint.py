# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for provenance (data lineage) and taint (untrusted-influence) primitives."""

from gsc_core.gsc_provenance import is_agent_generated, mark, origin_of
from gsc_core.gsc_taint import mark_tainted, require_untainted, tainted


def test_provenance_mark_and_lookup():
    mark("/tmp/poc_verify.py", "agent", "poc_generation")
    assert origin_of("/tmp/poc_verify.py") == "agent"
    assert is_agent_generated("/tmp/poc_verify.py") is True


def test_provenance_unknown_is_not_agent():
    assert origin_of("/nonexistent/file.py") is None
    assert is_agent_generated("/nonexistent/file.py") is False


def test_provenance_repo_origin():
    mark("/repo/app.py", "repo")
    assert origin_of("/repo/app.py") == "repo"
    assert is_agent_generated("/repo/app.py") is False


def test_taint_mark_and_check():
    rec = mark_tainted({"rule_id": "GS001"})
    assert tainted(rec) is True
    assert require_untainted(rec) is False


def test_taint_unmarked():
    rec = {"rule_id": "GS001"}
    assert tainted(rec) is False
    assert require_untainted(rec) is True


def test_make_finding_invariant_flag():
    from gsc_core.gsc_detectors.base import make_finding
    f = make_finding("GS001", "t", "critical", 0.9, "a.py", 1, "s", invariant=True)
    assert f["invariant"] is True
    f2 = make_finding("GS001", "t", "critical", 0.9, "a.py", 1, "s")
    assert f2["invariant"] is False
