#!/usr/bin/env python3
"""tests/test_sbom.py — SBOM + VEX tests (+7)."""
import sys, os
os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

from gsc_sbom import make_purl, component_id, generate_sbom, enrich_vex

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    assert make_purl("PyPI", "requests", "2.25.0") == "pkg:pypi/requests@2.25.0"
test('make_purl pypi', t1)

def t2():
    assert make_purl("npm", "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
test('make_purl npm scoped', t2)

def t3():
    assert make_purl("Go", "github.com/gin-gonic/gin", "1.7.0") == "pkg:golang/github.com/gin-gonic/gin@1.7.0"
test('make_purl Go full path', t3)

def t4():
    assert make_purl("PyPI", "flask", None) == "pkg:pypi/flask"
test('make_purl no version', t4)

def t5():
    from gsc_sca import Package
    pkgs = [Package("requests","2.25.0","PyPI","r.txt",1,"requests==2.25.0"),
            Package("requests","2.25.0","PyPI","r2.txt",5,"requests==2.25.0")]
    sbom = generate_sbom(pkgs)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 1
test('generate_sbom dedup + spec', t5)

def t6():
    sbom = {"components": []}
    findings = [{"severity":"CRITICAL","metadata":{"sca":{"vuln_id":"CVE-2021-44228",
        "package":"log4j","ecosystem":"Maven","current_version":"2.14.0","fixed_version":"2.15.0"}}}]
    epss = {"CVE-2021-44228":{"epss":0.97,"percentile":0.999}}
    result = enrich_vex(sbom, findings, epss)
    v = result["vulnerabilities"][0]
    assert v["id"] == "CVE-2021-44228"
    assert v["analysis"]["state"] == "affected"
    prio = [p for p in v["properties"] if p["name"]=="gsc:priority"][0]
    assert prio["value"] == "critical"
test('enrich_vex with EPSS priority', t6)

def t7():
    sbom = {"components": []}
    findings = [{"severity":"HIGH","metadata":{"sca":{"vuln_id":"CVE-2020-1234",
        "package":"x","ecosystem":"PyPI","current_version":"1.0"}}}]
    result = enrich_vex(sbom, findings, {})
    assert result["vulnerabilities"][0]["analysis"]["state"] == "affected"
test('enrich_vex graceful without EPSS', t7)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
