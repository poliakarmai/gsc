# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""tests/test_poc_dispatch.py — PoF PoC format dispatch (curl/bash vs python).

Regression for the bug where deterministic curl/bash PoCs were written verbatim
into poc_verify.py and executed as Python → SyntaxError → exploited always
False → "verified" unreachable. Also covers the GSC-001 fail-closed isolation
gate on "verified".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
import shutil

from gsc_proofoffix import (
    _run_poc_sandboxed,
    _generate_poc_code,
    _isolation_allows_verified,
    ProofOfFix,
)


def test_generate_poc_code_returns_curl_fmt_for_sqli():
    code, fmt = _generate_poc_code({"rule_id": "GS005", "title": "SQL injection"}, "x = 1\n")
    assert fmt == "curl"
    assert "curl" in code


def test_run_poc_sandboxed_curl_executes_as_shell():
    d = tempfile.mkdtemp()
    try:
        # A curl/bash PoC must NOT be run as Python (that would be SyntaxError).
        r = _run_poc_sandboxed("echo VULNERABLE", d, fmt="curl", target_code="")
        assert r["exploited"] is True
        assert "VULNERABLE" in r["output"].upper()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_run_poc_sandboxed_python_backcompat():
    d = tempfile.mkdtemp()
    try:
        r = _run_poc_sandboxed('print("VULNERABLE: exploit works")', d)
        assert r["exploited"] is True
        assert "isolation" in r
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_isolation_gate_requires_container_on_both_runs():
    assert _isolation_allows_verified("docker", "docker") is True
    assert _isolation_allows_verified("podman", "podman") is True
    assert _isolation_allows_verified("rlimit", "docker") is False
    assert _isolation_allows_verified("docker", "rlimit") is False
    assert _isolation_allows_verified("", "") is False


def test_classify_contract_unchanged():
    assert ProofOfFix._classify(True, False, True, False) == "verified"
    assert ProofOfFix._classify(False, False, True, False) == "structural"
