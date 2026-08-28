# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Unit tests for gsc_core.gsc_policy_taint.

Contract under test (pure functions, no I/O):

  - compile_taint_rule(sources, sinks, sanitizers=None) -> dict | None
  - validate_taint_spec(taint) -> (bool, str)
  - apply_taint_rule(source_re, sink_re, sanitizer_re, content) -> list[int] | None
"""

from __future__ import annotations

import pytest

from gsc_core.gsc_policy_taint import (
    apply_taint_rule,
    compile_taint_rule,
    validate_taint_spec,
)


# ── compile_taint_rule ───────────────────────────────────────────


def test_compile_taint_rule_returns_three_keys():
    rule = compile_taint_rule(["request.args"], ["db.execute"], [])
    assert isinstance(rule, dict)
    assert set(rule.keys()) == {"source_re", "sink_re", "sanitizer_re"}
    assert rule["source_re"] == "request.args"
    assert rule["sink_re"] == "db.execute"
    assert rule["sanitizer_re"] == ""


def test_compile_taint_rule_joins_alternation():
    rule = compile_taint_rule(
        ["request\\.args", "request\\.form"],
        ["db\\.execute", "cursor\\.execute"],
        ["html\\.escape"],
    )
    assert rule["source_re"] == "request\\.args|request\\.form"
    assert rule["sink_re"] == "db\\.execute|cursor\\.execute"
    assert rule["sanitizer_re"] == "html\\.escape"


def test_compile_taint_rule_empty_sources_returns_none():
    assert compile_taint_rule([], ["db.execute"], []) is None


def test_compile_taint_rule_empty_sinks_returns_none():
    assert compile_taint_rule(["request.args"], [], []) is None


def test_compile_taint_rule_invalid_regex_returns_none():
    # "(" is an unclosed group → re.error
    assert compile_taint_rule(["("], ["db.execute"], []) is None


def test_compile_taint_rule_invalid_sink_regex_returns_none():
    assert compile_taint_rule(["x"], ["["], []) is None


def test_compile_taint_rule_sanitizer_defaults_to_empty_string():
    rule = compile_taint_rule(["src"], ["sink"])  # no sanitizers kwarg
    assert rule["sanitizer_re"] == ""


# ── validate_taint_spec ──────────────────────────────────────────


def test_validate_taint_spec_minimal_valid():
    assert validate_taint_spec({"sources": ["x"], "sinks": ["y"]}) == (True, "")


def test_validate_taint_spec_with_sanitizers_valid():
    assert validate_taint_spec(
        {"sources": ["x"], "sinks": ["y"], "sanitizers": ["z"]}
    ) == (True, "")


def test_validate_taint_spec_empty_sources_rejected():
    ok, reason = validate_taint_spec({"sources": [], "sinks": ["y"]})
    assert ok is False
    assert "sources" in reason


def test_validate_taint_spec_missing_sinks_rejected():
    ok, reason = validate_taint_spec({"sources": ["x"]})
    assert ok is False
    assert "sinks" in reason


def test_validate_taint_spec_not_a_dict_rejected():
    ok, reason = validate_taint_spec(["sources", "sinks"])  # type: ignore[arg-type]
    assert ok is False
    assert reason  # non-empty


def test_validate_taint_spec_non_string_in_list_rejected():
    ok, reason = validate_taint_spec({"sources": [123], "sinks": ["y"]})
    assert ok is False
    assert "sources" in reason


def test_validate_taint_spec_does_not_raise_on_garbage():
    # Defensive: any input must return a tuple, never raise.
    assert validate_taint_spec(None) == (False, "taint must be a dict")
    assert validate_taint_spec(42) == (False, "taint must be a dict")


# ── apply_taint_rule ─────────────────────────────────────────────


TAINTED_CODE = """\
def handler():
    q = request.args.get("q")
    db.execute(f"SELECT * FROM t WHERE x={q}")
"""


SANITIZED_CODE = """\
def handler():
    q = html.escape(request.args.get("q"))
    db.execute(f"SELECT * FROM t WHERE x={q}")
"""


def test_apply_taint_rule_finds_taint_path():
    violations = apply_taint_rule(
        source_re="request.args",
        sink_re="db.execute",
        sanitizer_re="",
        content=TAINTED_CODE,
    )
    assert violations is not None
    assert len(violations) > 0
    # The sink call is on line 3 of TAINTED_CODE.
    assert 3 in violations


def test_apply_taint_rule_non_python_returns_none():
    # "def broken(" is a SyntaxError → ast.parse fails → analyzer returns None.
    assert apply_taint_rule("src", "sink", "", "def broken(") is None


def test_apply_taint_rule_sanitizer_suppresses_violation():
    # html.escape on the tainted expression clears taint on the
    # assigned variable, so the sink call sees a clean argument.
    violations = apply_taint_rule(
        source_re="request.args",
        sink_re="db.execute",
        sanitizer_re="html.escape",
        content=SANITIZED_CODE,
    )
    assert violations is not None
    assert violations == []


def test_apply_taint_rule_invalid_regex_returns_none():
    # "[" is an unclosed character class, "(" an unclosed group → re.error.
    assert apply_taint_rule("[", "sink", "", TAINTED_CODE) is None
    assert apply_taint_rule("src", "(", "", TAINTED_CODE) is None


def test_apply_taint_rule_no_taint_returns_empty_list():
    clean_code = "x = 1\nprint(x)\n"
    violations = apply_taint_rule("request.args", "db.execute", "", clean_code)
    assert violations is not None
    assert violations == []


# ── Smoke: full round-trip via validate → compile → apply ────────


def test_round_trip_validate_compile_apply():
    spec = {
        "sources": ["request\\.args"],
        "sinks": ["db\\.execute"],
        "sanitizers": [],
    }
    ok, _ = validate_taint_spec(spec)
    assert ok

    rule = compile_taint_rule(spec["sources"], spec["sinks"], spec["sanitizers"])
    assert rule is not None

    violations = apply_taint_rule(
        rule["source_re"], rule["sink_re"], rule["sanitizer_re"], TAINTED_CODE
    )
    assert violations is not None
    assert 3 in violations
