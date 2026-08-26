#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the LLM Receipt Contract (Phase 2, GSC ROADMAP).

The contract requires every LLM verdict on a finding to cite concrete code
as a receipt — file path, line number, and a short code fragment. Verdicts
without a valid receipt are INCOMPLETE and trigger a deterministic
severity/confidence demotion.

These tests are pure: no subprocess calls to the real `rejudge` binary, no
network, no LLM. We exercise the validator directly and use a stub of
`gsc_cli.gsc_rejudge.rejudge` so `revalidate_findings` can be tested
end-to-end with a synthetic verdict string.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make the repo importable when pytest is invoked from elsewhere.
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from gsc_cli import gsc_rejudge as rj  # noqa: E402


# ---------------------------------------------------------------------------
# Receipt dataclass
# ---------------------------------------------------------------------------

class TestReceipt:
    def test_defaults_are_invalid(self):
        rcpt = rj.Receipt()
        assert rcpt.is_valid is False
        assert rcpt.file == ""
        assert rcpt.line == 0
        assert rcpt.code == ""

    def test_partial_receipt_invalid(self):
        """Missing any one of file/line/code → invalid."""
        assert rj.Receipt(file="a.py", line=1, code="").is_valid is False
        assert rj.Receipt(file="a.py", line=0, code="x=1").is_valid is False
        assert rj.Receipt(file="", line=1, code="x=1").is_valid is False

    def test_zero_line_is_invalid(self):
        rcpt = rj.Receipt(file="a.py", line=0, code="x=1")
        assert rcpt.is_valid is False

    def test_full_receipt_is_valid(self):
        rcpt = rj.Receipt(file="src/a.py", line=42, code="eval(x)")
        assert rcpt.is_valid is True


# ---------------------------------------------------------------------------
# parse_receipt — tolerant parser over free-form verdict text
# ---------------------------------------------------------------------------

class TestParseReceipt:
    def test_empty_input_returns_none(self):
        assert rj.parse_receipt("") is None

    def test_no_reference_returns_none(self):
        # No file:line reference at all.
        assert rj.parse_receipt("This is a true positive because of obvious reasons.") is None

    def test_file_colon_line_with_code_keyword(self):
        text = "Finding 1: TP\nReceipt: src/app.py:42  Code: eval(user_input)\n"
        rcpt = rj.parse_receipt(text)
        assert rcpt is not None
        assert rcpt.file == "src/app.py"
        assert rcpt.line == 42
        assert rcpt.code == "eval(user_input)"

    def test_file_prefix_with_colon(self):
        text = "File: pkg/util.py:13 is where the issue is."
        rcpt = rj.parse_receipt(text)
        assert rcpt is not None
        assert rcpt.file == "pkg/util.py"
        assert rcpt.line == 13

    def test_file_line_keyword_alternative(self):
        """Accept `path/to/file.py line 42` as an alternative format."""
        text = "The vulnerability is in lib/foo.py line 99.\n`return shell=True`"
        rcpt = rj.parse_receipt(text)
        assert rcpt is not None
        assert rcpt.file == "lib/foo.py"
        assert rcpt.line == 99
        assert rcpt.code  # picked up the backtick fragment

    def test_code_extracted_from_backticks(self):
        text = "src/db.py:7 — `cursor.execute(query)`"
        rcpt = rj.parse_receipt(text)
        assert rcpt is not None
        assert rcpt.file == "src/db.py"
        assert rcpt.line == 7
        assert rcpt.code == "cursor.execute(query)"

    def test_code_field_alternative_label(self):
        for label in ("Code:", "Snippet:", "Evidence:", "Quote:"):
            text = f"src/a.py:5 {label} password = 'secret123'"
            rcpt = rj.parse_receipt(text)
            assert rcpt is not None, f"failed for {label}"
            assert rcpt.code == "password = 'secret123'", f"failed for {label}"

    def test_large_line_number(self):
        rcpt = rj.parse_receipt("app.py:12345 — `x=1`")
        assert rcpt is not None
        assert rcpt.line == 12345


# ---------------------------------------------------------------------------
# validate_receipt — the gate the demotion logic relies on
# ---------------------------------------------------------------------------

class TestValidateReceipt:
    def test_none_is_invalid(self):
        assert rj.validate_receipt(None) is False

    def test_empty_receipt_is_invalid(self):
        assert rj.validate_receipt(rj.Receipt()) is False

    def test_file_only_is_invalid(self):
        assert rj.validate_receipt(rj.Receipt(file="a.py")) is False

    def test_file_and_line_without_code_is_invalid(self):
        """A reference without an actual code fragment is not enough evidence."""
        assert rj.validate_receipt(rj.Receipt(file="a.py", line=10)) is False

    def test_full_receipt_is_valid(self):
        assert rj.validate_receipt(rj.Receipt(file="a.py", line=10, code="x=1")) is True


# ---------------------------------------------------------------------------
# demote_finding_for_missing_receipt — severity + confidence down-shift
# ---------------------------------------------------------------------------

class TestDemoteFinding:
    def test_critical_demotes_to_high(self):
        f = {"severity": "CRITICAL", "confidence": 80}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["severity"] == "HIGH"
        assert out["original_severity"] == "CRITICAL"
        assert out["receipt_status"] == "INCOMPLETE"
        assert out["confidence"] == 55  # 80 - 25

    def test_high_demotes_to_medium(self):
        f = {"severity": "HIGH", "confidence": 70}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["severity"] == "MEDIUM"
        assert out["confidence"] == 45

    def test_low_demotes_to_info(self):
        f = {"severity": "LOW", "confidence": 30}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["severity"] == "INFO"
        assert out["confidence"] == 5

    def test_unknown_severity_unchanged(self):
        f = {"severity": "BOGUS", "confidence": 50}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["severity"] == "BOGUS"  # not in demotion table
        assert out["confidence"] == 25  # penalty still applied
        assert out["receipt_status"] == "INCOMPLETE"

    def test_confidence_floored_at_zero(self):
        f = {"severity": "CRITICAL", "confidence": 10}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["confidence"] == 0

    def test_missing_confidence_treated_as_zero(self):
        f = {"severity": "HIGH"}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["confidence"] == 0

    def test_does_not_mutate_input(self):
        f = {"severity": "CRITICAL", "confidence": 80}
        rj.demote_finding_for_missing_receipt(f)
        assert f["severity"] == "CRITICAL"
        assert f["confidence"] == 80
        assert "receipt_status" not in f

    def test_original_confidence_preserved_in_metadata(self):
        f = {"severity": "CRITICAL", "confidence": 90, "metadata": {"foo": "bar"}}
        out = rj.demote_finding_for_missing_receipt(f)
        assert out["metadata"]["original_confidence"] == 90
        assert out["metadata"]["foo"] == "bar"  # existing keys preserved


# ---------------------------------------------------------------------------
# revalidate_findings — end-to-end with a stubbed LLM
# ---------------------------------------------------------------------------

def _write_scan(tmp_path: Path) -> Path:
    """Write a minimal scan.json with 2 CRITICAL + 1 HIGH finding."""
    scan = {
        "findings": [
            {
                "rule_id": "GS001",
                "title": "Eval injection",
                "file": "src/app.py",
                "line": 42,
                "snippet": "result = eval(user_input)",
                "severity": "CRITICAL",
                "confidence": 80,
            },
            {
                "rule_id": "GS008",
                "title": "Hardcoded secret",
                "file": "src/db.py",
                "line": 7,
                "snippet": "API_KEY = 'sk-xxx'",
                "severity": "CRITICAL",
                "confidence": 75,
            },
            {
                "rule_id": "GS029",
                "title": "Weak crypto",
                "file": "lib/crypto.py",
                "line": 99,
                "snippet": "hashlib.md5(data)",
                "severity": "HIGH",
                "confidence": 60,
            },
        ]
    }
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(scan))
    return p


class TestRevalidateFindings:
    def test_empty_findings_short_circuits(self, tmp_path, monkeypatch):
        called = {"n": 0}

        def fake_rejudge(prompt, timeout=120):
            called["n"] += 1
            return True, ""

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({"findings": []}))

        result = rj.revalidate_findings(str(scan))
        assert result["status"] == "ok"
        assert result["revalidated"] == 0
        assert result["message"] == "No CRITICAL/HIGH findings"
        assert called["n"] == 0  # no LLM call needed

    def test_filters_to_critical_and_high(self, tmp_path, monkeypatch):
        """MEDIUM/LOW findings must not be sent to the rejudge prompt."""
        seen_prompts = []

        def fake_rejudge(prompt, timeout=120):
            seen_prompts.append(prompt)
            # Two CRITICAL findings, both cited correctly.
            return True, (
                "Finding 1: TP — Receipt: src/app.py:42  Code: eval(user_input)\n"
                "Finding 2: FP — Receipt: src/db.py:7  Code: API_KEY = 'sk-xxx'\n"
            )

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)

        scan_data = {
            "findings": [
                {"rule_id": "X", "title": "low",  "file": "a.py", "line": 1, "snippet": "x", "severity": "LOW"},
                {"rule_id": "X", "title": "med",  "file": "b.py", "line": 1, "snippet": "x", "severity": "MEDIUM"},
                {"rule_id": "X", "title": "crit", "file": "src/app.py", "line": 42, "snippet": "eval(x)", "severity": "CRITICAL"},
            ]
        }
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps(scan_data))

        result = rj.revalidate_findings(str(scan))
        assert result["revalidated"] == 1, "only the CRITICAL one should be revalidated"
        # The MEDIUM/LOW titles must NOT appear in the prompt sent to the LLM.
        assert "low" not in seen_prompts[0]
        assert "med" not in seen_prompts[0]

    def test_receipts_parsed_per_finding(self, tmp_path, monkeypatch):
        def fake_rejudge(prompt, timeout=120):
            return True, (
                "Finding 1: TP — Receipt: src/app.py:42  Code: eval(user_input)\n"
                "Finding 2: TP — Receipt: src/db.py:7  Code: API_KEY = 'sk-xxx'\n"
                "Finding 3: FP — Receipt: lib/crypto.py:99  Code: hashlib.md5(data)\n"
            )

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        result = rj.revalidate_findings(str(_write_scan(tmp_path)))
        assert result["revalidated"] == 3
        assert result["incomplete"] == 0
        assert len(result["receipts"]) == 3
        for r in result["receipts"]:
            assert r["receipt_ok"] is True
            assert r["receipt"] is not None
            assert r["receipt"]["file"]
            assert r["receipt"]["line"] > 0
            assert r["receipt"]["code"]

    def test_missing_receipt_marked_incomplete(self, tmp_path, monkeypatch):
        """If the LLM returns a verdict without any file:line citation, every
        finding is INCOMPLETE and the caller can demote them."""
        def fake_rejudge(prompt, timeout=120):
            # No file:line reference anywhere — bare verdict only.
            return True, "All three findings are true positives based on the code shown."

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        result = rj.revalidate_findings(str(_write_scan(tmp_path)))
        assert result["incomplete"] == 3
        assert all(not r["receipt_ok"] for r in result["receipts"])
        # Caller can demote each finding using the demote helper.
        for r in result["receipts"]:
            # Simulate what a real consumer would do with each finding.
            demoted = rj.demote_finding_for_missing_receipt(
                {"severity": "CRITICAL", "confidence": 80, "rule_id": r["rule_id"]}
            )
            assert demoted["receipt_status"] == "INCOMPLETE"
            assert demoted["severity"] == "HIGH"
            assert demoted["confidence"] == 55

    def test_partial_receipt_only_file_line_marked_incomplete(self, tmp_path, monkeypatch):
        """file:line present but no code fragment → still INCOMPLETE."""
        def fake_rejudge(prompt, timeout=120):
            return True, "Receipt: src/app.py:42 — TP\n"  # no Code: field

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        # Single-finding scan for clarity.
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "findings": [{
                "rule_id": "GS001", "title": "Eval", "file": "src/app.py",
                "line": 42, "snippet": "eval(x)", "severity": "CRITICAL",
            }]
        }))
        result = rj.revalidate_findings(str(scan))
        assert result["incomplete"] == 1
        assert result["receipts"][0]["receipt_ok"] is False
        # The file:line was still extracted, but without `code` it fails validation.
        assert result["receipts"][0]["receipt"] is not None
        assert result["receipts"][0]["receipt"]["file"] == "src/app.py"
        assert result["receipts"][0]["receipt"]["line"] == 42
        assert result["receipts"][0]["receipt"]["code"] == ""

    def test_prompt_includes_full_snippet_evidence(self, tmp_path, monkeypatch):
        """The prompt must include more than the old 100-char snippet cap."""
        seen = []

        def fake_rejudge(prompt, timeout=120):
            seen.append(prompt)
            return True, "Receipt: src/app.py:1  Code: x"

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        long_snippet = "x" * 250  # > 100 (old cap) but <= 300 (new cap)
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({
            "findings": [{
                "rule_id": "GS001", "title": "Eval", "file": "src/app.py",
                "line": 1, "snippet": long_snippet, "severity": "CRITICAL",
            }]
        }))
        rj.revalidate_findings(str(scan))
        # The new snippet cap (300) must be honoured; old cap (100) would have
        # truncated this snippet to 100 chars.
        assert long_snippet in seen[0], "snippet should not be truncated to 100 chars"

    def test_rejudge_failure_still_returns_receipts(self, tmp_path, monkeypatch):
        """Even if the subprocess fails, we still return a structured result."""
        def fake_rejudge(prompt, timeout=120):
            return False, "Rejudge not installed"

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        result = rj.revalidate_findings(str(_write_scan(tmp_path)))
        assert result["status"] == "error"
        assert result["incomplete"] == 3  # no receipt in empty output
        assert len(result["receipts"]) == 3

    def test_prompt_does_not_exceed_10_findings(self, tmp_path, monkeypatch):
        """Batch is capped at 10 to bound the LLM context window."""
        findings = [
            {"rule_id": f"R{i}", "title": f"t{i}", "file": f"f{i}.py",
             "line": i, "snippet": "x", "severity": "CRITICAL"}
            for i in range(15)
        ]
        seen = []

        def fake_rejudge(prompt, timeout=120):
            seen.append(prompt)
            return True, "ok"

        monkeypatch.setattr(rj, "rejudge", fake_rejudge)
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps({"findings": findings}))
        result = rj.revalidate_findings(str(scan))
        assert result["revalidated"] == 10
        # Only 10 `--- Finding` headers in the prompt.
        assert seen[0].count("--- Finding") == 10
