#!/usr/bin/env python3
"""tests/test_epss.py — EPSS exploitability tests (+7)."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_epss import extract_cve_id, compute_risk, enrich_sca_findings, EpssClient

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f'  ✅ {name}')
        passed += 1
    except Exception as e:
        print(f'  ❌ {name}: {e}')
        failed += 1


def t1():
    assert extract_cve_id({"vuln_id": "CVE-2021-44228"}) == "CVE-2021-44228"
test('extract CVE from vuln_id', t1)


def t2():
    meta = {"vuln_id": "GHSA-xxxx", "aliases": ["CVE-2021-44228"]}
    assert extract_cve_id(meta) == "CVE-2021-44228"
test('extract CVE from aliases', t2)


def t3():
    assert extract_cve_id({"vuln_id": "cve-2021-44228"}) == "CVE-2021-44228"
test('extract CVE normalizes case', t3)


def t4():
    assert extract_cve_id({"vuln_id": "PYSEC-2018-58", "aliases": []}) is None
test('extract CVE None for PYSEC-only', t4)


def t5():
    r = compute_risk("CRITICAL", 0.9, 1.0)
    assert r["level"] == "critical"  # 1.0*0.9=0.9
    r2 = compute_risk("HIGH", 0.91, 1.0)
    assert r2["level"] == "critical"  # 0.8*0.91=0.73
    r3 = compute_risk("CRITICAL", 0.002, 1.0)
    assert r3["level"] == "low"       # 1.0*0.002=0.002
test('compute_risk levels', t5)


def t6():
    r = compute_risk("CRITICAL", 1.5, 2.0)
    assert r["score"] <= 1.0
test('compute_risk clamps out-of-range', t6)


def t7():
    import gsc_epss
    findings = [{
        "rule_id": "GS030-CVE-2021-44228",
        "severity": "CRITICAL", "confidence": 0.90,
        "metadata": {"sca": {"vuln_id": "CVE-2021-44228",
                             "aliases": [], "package": "log4j"}}}]
    orig = gsc_epss.EpssClient.query
    gsc_epss.EpssClient.query = lambda self, ids: {
        "CVE-2021-44228": {"epss": 0.97, "percentile": 0.9999, "date": "2026-08-01"}}
    try:
        enriched = enrich_sca_findings(findings)
        meta = enriched[0]["metadata"]
        assert meta["exploit_signal"] == "actively_exploited"
        assert enriched[0]["confidence"] > 0.90
        assert meta["risk"]["level"] == "critical"
    finally:
        gsc_epss.EpssClient.query = orig
test('enrich marks actively_exploited', t7)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
