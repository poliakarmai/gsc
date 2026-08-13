#!/usr/bin/env python3
"""tests/test_nuclei_export.py — nuclei export round-trip tests (+5)."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_nuclei_export import (
    _parse_curl_command,
    _parse_python_requests,
    _extract_markers,
    export_finding_to_nuclei,
)

passed = 0
failed = 0

def run_case(name, fn):
    global passed, failed
    try:
        fn()
        print(f'  ✅ {name}')
        passed += 1
    except Exception as e:
        print(f'  ❌ {name}: {e}')
        failed += 1


def t1():
    poc = "curl http://example.com/api?id=1' OR '1'='1"
    request = _parse_curl_command(poc)
    assert request is not None, "should parse curl GET"
    assert request["method"] == "GET"
    assert "{{BaseURL}}" in request["path"][0]
    assert "id=1" in request["path"][0]
run_case('parse curl GET', t1)


def t2():
    poc = ('curl -X POST -H "Content-Type: application/json" '
           '-d \'{"id":"1"}\' http://example.com/api')
    request = _parse_curl_command(poc)
    assert request is not None, "should parse curl POST"
    assert request["method"] == "POST"
    assert request["body"] == '{"id":"1"}'
    assert request["headers"]["Content-Type"] == "application/json"
run_case('parse curl POST', t2)


def t3():
    poc = ('import requests\n'
           'r = requests.get("http://example.com/api", '
           'params={"id": "1"})\n'
           'print("VULNERABLE")')
    request = _parse_python_requests(poc)
    assert request is not None, "should parse python requests"
    assert request["method"] == "GET"
    assert "{{BaseURL}}" in request["path"][0]
    assert "id=1" in request["path"][0]
run_case('parse python requests GET', t3)


def t4():
    poc = 'print("VULNERABLE: SQL injection works")'
    markers = _extract_markers(poc)
    assert "VULNERABLE" in markers
run_case('extract VULNERABLE marker', t4)


def t5():
    finding = {
        "finding_key": "abc123def456",
        "rule_id": "GS001",
        "severity": "CRITICAL",
        "file_path": "app.py",
        "line_number": 42,
        "confidence": 0.95,
        "title": "SQL Injection",
        "detail": "sql injection here",
        "category": "CRITICAL",
    }
    poc = 'curl http://example.com/api?id=1\\\' OR \\\'1\\\'=\\\'1\nprint("VULNERABLE")'
    template = export_finding_to_nuclei(finding, poc)
    assert template is not None, "should export"
    assert template.id == "gsc-abc123def456"
    assert template.severity == "critical"
    yaml_text = template.to_yaml()
    assert "id: gsc-abc123def456" in yaml_text
    assert "severity: critical" in yaml_text
    assert "{{BaseURL}}" in yaml_text
    assert "VULNERABLE" in yaml_text
run_case('full finding → nuclei YAML round-trip', t5)


def t6():
    finding = {"finding_key": "x" * 12, "rule_id": "GS001", "severity": "HIGH",
               "file_path": "x.py", "line_number": 1, "detail": "x", "category": "HIGH"}
    poc = "# complex Python code that can't be parsed\n..."
    template = export_finding_to_nuclei(finding, poc)
    assert template is None, "unparseable PoC should skip"
run_case('skip unparseable PoC', t6)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
