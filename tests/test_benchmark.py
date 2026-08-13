#!/usr/bin/env python3
"""tests/test_benchmark.py — OWASP Benchmark tests (+7)."""
import sys, os, tempfile
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from benchmark.cwe_map import build_cwe_to_rules, coverage_report
from benchmark.adapter import parse_expected_csv
from benchmark.scorer import CweScore, overall_score
from benchmark.runner import is_detected

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
    cwe_map = build_cwe_to_rules()
    assert "GS001" in cwe_map.get("CWE-89", [])
run_case('cwe_map reverse: GS001 → CWE-89', t1)


def t2():
    cwe_map = {"CWE-89": ["GS001"]}
    cov = coverage_report(cwe_map)
    assert cov["coverage_pct"] < 100.0
    uncov = {u["cwe"] for u in cov["uncovered"]}
    assert "CWE-79" in uncov
run_case('coverage report: uncovered CWEs', t2)


def t3():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    tmp.write("# test, category, vuln, cwe\n"
              "BenchmarkTest00001,hash,false,328\n"
              "BenchmarkTest00002,sqli,true,89\n")
    tmp.close()
    exp = parse_expected_csv(tmp.name)
    assert exp["BenchmarkTest00001"] == (False, "CWE-328")
    assert exp["BenchmarkTest00002"] == (True, "CWE-89")
    os.unlink(tmp.name)
run_case('parse expected CSV', t3)


def t4():
    s = CweScore(cwe="CWE-89", tp=80, fp=10, fn=20, tn=90)
    assert abs(s.tpr - 80/100) < 1e-6
    assert abs(s.fpr - 10/100) < 1e-6
    assert abs(s.precision - 80/90) < 1e-6
    assert abs(s.owasp_score - 0.70) < 1e-6
run_case('CweScore math', t4)


def t5():
    s = CweScore(cwe="CWE-79", tp=0, fp=0, fn=0, tn=0)
    assert s.tpr == 0.0 and s.fpr == 0.0 and s.precision == 0.0
    assert s.owasp_score == 0.0
run_case('CweScore division-by-zero guard', t5)


def t6():
    findings = [{"rule_id": "GS001-subvariant"}]
    assert is_detected(findings, ["GS001"]) is True
    assert is_detected(findings, ["GS017"]) is False
run_case('is_detected base_rule match', t6)


def t7():
    scores = {
        "CWE-89": CweScore(cwe="CWE-89", tp=10, fp=0, fn=0, tn=10),
        "CWE-79": CweScore(cwe="CWE-79", tp=0, fp=0, fn=0, tn=0),
    }
    assert overall_score(scores) == 1.0  # only CWE-89 counted
run_case('overall_score skips empty CWE', t7)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
