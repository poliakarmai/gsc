#!/usr/bin/env python3
"""tests/test_compliance_secrets.py — compliance + GS029 tests (+7)."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_compliance import compliance_for, enrich_finding
from gsc_detectors.gs029_secrets import GS029SecretsDetector

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
    assert compliance_for("GS001")["cwe"] == "CWE-89"
    # sub-rule fallback by prefix
    assert compliance_for("GS025-permissive_cors")["cwe"] == "CWE-1188"
    assert compliance_for("GS030-PYSEC-2018-58")["cwe"] == "CWE-1104"
    assert compliance_for("GS028-INV-001")["cwe"] == "CWE-693"
run_case('compliance base + subrule fallback', t1)


def t2():
    assert compliance_for("GS999-unknown") == {}
run_case('compliance unknown rule → empty', t2)


def t3():
    f = {"rule_id": "GS017", "file_path": "a.py"}
    enrich_finding(f)
    assert f["metadata"]["compliance"]["cwe"] == "CWE-521"
    assert f["metadata"]["compliance"]["owasp"] == "A07:2021-Auth"
run_case('enrich_finding injects compliance', t3)


def t4():
    det = GS029SecretsDetector()
    hits = det.detect("app.py", 'aws = "AKIAIOSFODNN7EXAMPLE"')
    assert len(hits) == 1
    assert hits[0]["rule_id"] == "GS029-aws_access_key"
    assert hits[0]["severity"] == "CRITICAL"
run_case('GS029 detects AWS key', t4)


def t5():
    det = GS029SecretsDetector()
    hits = det.detect("app.py", 'aws = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in hits[0]["detail"]
    assert "<redacted:" in hits[0]["detail"]
run_case('GS029 redacts snippet', t5)


def t6():
    det = GS029SecretsDetector()
    assert det.detect("a.py", 'password = "aaaaaaaaaaaa"') == []
    assert len(det.detect("a.py", 'password = "Xk9#mQ2vL7pR4z"')) == 1
run_case('GS029 entropy filter', t6)


def t7():
    det = GS029SecretsDetector()
    assert det.detect("tests/fixtures.py", 'aws = "AKIAIOSFODNN7EXAMPLE"') == []
run_case('GS029 excludes test paths', t7)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
