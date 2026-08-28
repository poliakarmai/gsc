# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""Semantic (AST / data-flow) enforcement of GSC NL policies.

The NL policy compiler (``gsc_cli.gsc_nlpolicy``) emits a single regex that
matches ``source|sink|sanitizer`` tokens per line. That is fast but shallow —
it cannot tell whether a tainted value actually *reaches* a sink through
intermediate variables, branches, or function calls.

This module bridges the two worlds: it lets a policy declare a taint triple
``{sources, sinks, sanitizers}`` (lists of regex fragments) and hands the
compiled patterns to ``gsc_core.gsc_ast_dataflow.PythonTaintAnalyzer``, which
performs intra-procedural data-flow analysis on real Python code.

All functions in this module are PURE — no filesystem, network, or process
side effects. They are safe to call from CLI handlers, server workers, and
tests.
"""

from __future__ import annotations

import re
from typing import Optional

from gsc_core.gsc_ast_dataflow import PythonTaintAnalyzer


# Public keys of the dict returned by ``compile_taint_rule``. Kept as a
# module-level constant so tests and downstream code can iterate over them
# without string-typo bugs.
TAINT_RULE_KEYS = ("source_re", "sink_re", "sanitizer_re")


def compile_taint_rule(
    sources: list[str],
    sinks: list[str],
    sanitizers: Optional[list[str]] = None,
) -> Optional[dict]:
    """Build a taint-rule dict from raw regex fragments.

    Each input list is joined with ``|`` to form an alternation regex.
    Every resulting pattern is validated with ``re.compile``; on
    ``re.error`` (malformed pattern) the function returns ``None`` instead
    of raising, so the caller can fall back to a less strict mode.

    Empty ``sources`` or ``sinks`` are rejected: a taint rule without
    either side is semantically meaningless and almost always a bug in
    the upstream policy generator.

    Args:
        sources: Non-empty list of regex fragments matching taint origins
            (e.g. ``["request.args", "request\\.form"]``).
        sinks: Non-empty list of regex fragments matching dangerous sinks
            (e.g. ``["db.execute", "subprocess\\.Popen"]``).
        sanitizers: Optional list of regex fragments matching sanitizing
            calls; an empty list is allowed and means "no sanitizers".

    Returns:
        ``{"source_re": str, "sink_re": str, "sanitizer_re": str}`` on
        success, or ``None`` if validation fails (empty required list or
        invalid regex).
    """
    if not sources or not sinks:
        return None

    sanitizer_patterns = sanitizers or []
    if not isinstance(sources, list) or not isinstance(sinks, list):
        return None
    if not isinstance(sanitizer_patterns, list):
        return None

    source_re = "|".join(sources)
    sink_re = "|".join(sinks)
    sanitizer_re = "|".join(sanitizer_patterns)

    # Validate every pattern eagerly so the caller never gets back a dict
    # that would later crash ``PythonTaintAnalyzer`` on first use.
    try:
        re.compile(source_re)
        re.compile(sink_re)
        re.compile(sanitizer_re)
    except re.error:
        return None

    return {
        "source_re": source_re,
        "sink_re": sink_re,
        "sanitizer_re": sanitizer_re,
    }


def validate_taint_spec(taint: dict) -> tuple[bool, str]:
    """Validate the shape of a taint spec coming from a policy.

    The spec is expected to be a ``dict`` with:
      - ``"sources"``    : non-empty ``list[str]``
      - ``"sinks"``      : non-empty ``list[str]``
      - ``"sanitizers"`` : optional ``list[str]`` (may be empty)

    The function is defensive: it never raises on malformed input, it
    always returns a ``(ok, reason)`` tuple. The ``reason`` is an empty
    string on success and a short human-readable message on failure.

    Args:
        taint: Candidate spec, typically the value of a policy's
            ``taint`` key in YAML/JSON.

    Returns:
        ``(True, "")`` on success, ``(False, "<reason>")`` otherwise.
    """
    if not isinstance(taint, dict):
        return False, "taint must be a dict"

    sources = taint.get("sources")
    sinks = taint.get("sinks")
    sanitizers = taint.get("sanitizers", [])

    if not isinstance(sources, list) or not sources or not all(
        isinstance(s, str) and s for s in sources
    ):
        return False, "sources must be a non-empty list of non-empty strings"
    if not isinstance(sinks, list) or not sinks or not all(
        isinstance(s, str) and s for s in sinks
    ):
        return False, "sinks must be a non-empty list of non-empty strings"
    if sanitizers is None:
        sanitizers = []
    if not isinstance(sanitizers, list) or not all(
        isinstance(s, str) for s in sanitizers
    ):
        return False, "sanitizers must be a list of strings"

    return True, ""


def apply_taint_rule(
    source_re: str,
    sink_re: str,
    sanitizer_re: str,
    content: str,
) -> Optional[list[int]]:
    """Run a compiled taint rule against a piece of Python source.

    Thin wrapper over ``PythonTaintAnalyzer``: it compiles the three
    pattern strings, instantiates the analyzer, and returns
    ``analyzer.analyze(content)``.

    Semantics of the return value mirror the analyzer contract:
      - ``list[int]`` — sorted unique line numbers of sink violations.
      - ``None`` — input is not parseable Python, or one of the patterns
        is not a valid regex. The caller is expected to fall back to the
        cheaper regex-per-line mode in that case.

    Args:
        source_re: Compiled alternation pattern matching taint sources.
        sink_re: Compiled alternation pattern matching dangerous sinks.
        sanitizer_re: Compiled alternation pattern matching sanitizers;
            pass ``""`` if the rule has none.
        content: Full Python source to analyze.

    Returns:
        List of 1-based violation line numbers, or ``None`` if analysis
        cannot run.
    """
    try:
        src = re.compile(source_re)
        sink = re.compile(sink_re)
        # Empty sanitizer list must NOT compile to re.compile(""), which
        # matches every position and would wrongly suppress every sink.
        san = re.compile(sanitizer_re) if sanitizer_re else re.compile(r"(?!)")
    except re.error:
        return None

    analyzer = PythonTaintAnalyzer(source_re=src, sink_re=sink, sanitizer_re=san)
    return analyzer.analyze(content)
