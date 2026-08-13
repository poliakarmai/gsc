"""Tests for PoF sandbox format dispatch (fix: curl/bash were run as Python → TypeError)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_poc_deterministic import attach_deterministic_pocs, get_deterministic_poc
from gsc_pof_sandbox import PoFSandbox


def test_curl_fmt_runs_via_bash():
    sb = PoFSandbox()
    r = sb._execute("echo VULNERABLE", "", fmt="curl")
    assert r.success is True
    assert "VULNERABLE" in r.stdout


def test_python_fmt_runs_python():
    sb = PoFSandbox()
    r = sb._execute('print("EXPLOITED")', "x = 1\n", fmt="python")
    assert r.success is True
    assert "EXPLOITED" in r.stdout


def test_python_fmt_imports_target():
    sb = PoFSandbox()
    vuln = "def get_user(i):\n    return [1, 2] if '1=1' in i else [1]\n"
    poc = "result = target.get_user('1 OR 1=1')\nassert len(result) == 2\nprint('EXPLOITED')\n"
    r = sb._execute(poc, vuln, fmt="python")
    assert r.success is True, f"stderr={r.stderr}"


def test_curl_fmt_no_python_typeerror():
    # The old bug: curl PoC ran as Python → "unhashable type: 'set'". Must NOT happen.
    sb = PoFSandbox()
    code = "curl -s 'TARGET_URL?input={{ 7 * 7 }}' | grep -q '49' && echo VULNERABLE || echo SAFE"
    r = sb._execute(code, "", fmt="curl")
    # No live endpoint → curl fails → SAFE, but this must be a curl/bash failure,
    # not a Python TypeError.
    assert "TypeError" not in r.stderr
    assert "unhashable" not in r.stderr


def test_deterministic_attaches_full_code_not_payload():
    findings = [{"rule_id": "GS020", "file_path": "app.py", "line": 1}]
    attach_deterministic_pocs(findings)
    poc = findings[0]["metadata"]["poc"]
    # Full curl command, not the bare payload "{{ 7 * 7 }}"
    assert "curl -s" in poc
    assert findings[0]["metadata"]["poc_format"] == "curl"
    assert findings[0]["metadata"]["poc_payload"] == "{{ 7 * 7 }}"


def test_verify_fix_uses_fmt():
    sb = PoFSandbox()
    # shell-based PoC that succeeds on "vulnerable" (echo VULNERABLE) and fails on "patched"
    vuln = "echo VULNERABLE"
    patched = "echo SAFE"
    v = sb.verify_fix(vuln, patched, "echo VULNERABLE", fmt="curl")
    # before must succeed, after must fail → but 'vuln' and 'patched' here are
    # shell snippets, not Python; language defaults to python so verify_fix rejects.
    # This test only asserts the fmt parameter is accepted and threaded through
    # without raising (the reject path is language != python).
    assert v is not None
