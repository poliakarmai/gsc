#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Integration tests for semantic (AST/Data Flow) NL-policy enforcement.

Covers the bridge between gsc_nlpolicy (NL policy compiler) and
gsc_policy_taint / PythonTaintAnalyzer: a policy that carries a taint triple
is enforced with data-flow analysis on Python files instead of per-line regex.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for p in (str(_REPO), str(_REPO / "gsc_cli")):
    if p not in sys.path:
        sys.path.insert(0, p)

from gsc_nlpolicy import PolicyError, _semantic_matches, compile_policy  # noqa: E402


class FakeLLMTaint:
    def ask(self, prompt, max_tokens=None):
        return ('{"rule_id": "GS028-x", "severity": "HIGH", '
                '"pattern": "db.execute|request.args", '
                '"taint": {"sources": ["request.args"], "sinks": ["db.execute"], '
                '"sanitizers": ["html.escape"]}}')


class FakeLLMNoTaint:
    def ask(self, prompt, max_tokens=None):
        return '{"rule_id": "GS028-x", "severity": "HIGH", "pattern": "abc123", "taint": null}'


class FakeLLMBadTaint:
    def ask(self, prompt, max_tokens=None):
        return ('{"rule_id": "GS028-x", "severity": "HIGH", "pattern": "abc123", '
                '"taint": {"sources": [], "sinks": []}}')


VULN = 'def handler():\n    q = request.args.get("q")\n    db.execute(f"SELECT * FROM t WHERE x={q}")\n'
CLEAN = ('def handler():\n    q = html.escape(request.args.get("q"))\n'
         '    db.execute(f"SELECT * FROM t WHERE x={q}")\n')


def test_compile_policy_keeps_valid_taint():
    c = compile_policy("user input must not reach SQL", llm=FakeLLMTaint())
    assert c["taint"] == {"sources": ["request.args"], "sinks": ["db.execute"],
                          "sanitizers": ["html.escape"]}


def test_compile_policy_null_taint_stays_none():
    c = compile_policy("no secrets in logs", llm=FakeLLMNoTaint())
    assert c["taint"] is None


def test_compile_policy_invalid_taint_falls_back_to_none():
    c = compile_policy("x", llm=FakeLLMBadTaint())
    assert c["taint"] is None


def test_semantic_matches_finds_source_to_sink(tmp_path):
    taint = {"sources": ["request.args"], "sinks": ["db.execute"], "sanitizers": []}
    (tmp_path / "vuln.py").write_text(VULN)
    m = _semantic_matches(taint, VULN, tmp_path / "vuln.py", tmp_path)
    assert len(m) == 1
    assert m[0]["line"] == 3
    assert m[0]["file"] == "vuln.py"


def test_semantic_matches_sanitizer_suppresses(tmp_path):
    taint = {"sources": ["request.args"], "sinks": ["db.execute"], "sanitizers": ["html.escape"]}
    (tmp_path / "clean.py").write_text(CLEAN)
    m = _semantic_matches(taint, CLEAN, tmp_path / "clean.py", tmp_path)
    assert m == []
