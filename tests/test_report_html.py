# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for the self-contained HTML report generator (Phase 13)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gsc_cli"))

from gsc_report_html import is_needs_decision, render_html  # noqa: E402


def _sample():
    return {
        "repo": "quillvoice-api",
        "commit": "02647a0",
        "findings": [
            {"finding_key": "k1", "rule_id": "GS005", "title": "SQL injection in invoice search",
             "severity": "CRITICAL", "file_path": "src/invoices.ts", "line_number": 26},
            {"finding_key": "k2", "rule_id": "GS001", "title": "Hardcoded secret committed",
             "severity": "HIGH", "file_path": ".env", "line_number": 2},
        ],
    }


def test_render_html_structure():
    out = render_html(_sample())
    assert out.startswith("<!DOCTYPE html>")
    assert "<title>GSC Security Review</title>" in out
    assert "SQL injection" in out
    assert "TOTAL" in out
    assert "NEEDS DECISION" in out  # GS001 secret → rotation required


def test_render_html_summary_counts():
    out = render_html(_sample())
    assert ">2<" in out  # total count card
    assert "CRITICAL" in out


def test_render_html_escapes_markup():
    scan = {"findings": [{"finding_key": "k", "rule_id": "GS005",
                          "title": "<script>alert(1)</script>",
                          "severity": "CRITICAL", "file_path": "a.py", "line_number": 1}]}
    out = render_html(scan)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_needs_decision_rules():
    assert is_needs_decision({"rule_id": "GS001"}) is True
    assert is_needs_decision({"rule_id": "GS029"}) is True
    assert is_needs_decision({"rule_id": "GS005"}) is False
    assert is_needs_decision({"rule_id": "GS005", "metadata": {"committed": True}}) is True


def test_needs_decision_anchored_no_false_positive():
    # Anchored regex: a hypothetical GS0010/GS029x must NOT match.
    assert is_needs_decision({"rule_id": "GS0010"}) is False
    assert is_needs_decision({"rule_id": "GS0290"}) is False
    assert is_needs_decision({"rule_id": "GS001-var"}) is True


def test_render_html_empty():
    out = render_html({"findings": []})
    assert "<!DOCTYPE html>" in out
    assert "0" in out
