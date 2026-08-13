#!/usr/bin/env python3
"""tests/test_integration.py — end-to-end pipeline tests (+10, v0.36)."""
import sys, os, json
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_sca import Package
from gsc_sbom import generate_sbom, enrich_vex
from gsc_spdx import generate_spdx, cdx_to_spdx, sign_sbom, verify_sbom
from gsc_epss import extract_cve_id, compute_risk

_pkgs = [Package("log4j","2.14.0","Maven","pom.xml",10,"log4j 2.14.0"),
         Package("requests","2.19.0","PyPI","r.txt",1,"requests==2.19.0")]

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    sbom = generate_sbom(_pkgs)
    assert sbom["bomFormat"] == "CycloneDX"
    assert len(sbom["components"]) == 2
run_case('SCA → CycloneDX pipeline', t1)

def t2():
    sbom = generate_sbom(_pkgs)
    findings = [{"severity":"CRITICAL","metadata":{"sca":{"vuln_id":"CVE-2021-44228",
        "package":"log4j","ecosystem":"Maven","current_version":"2.14.0","fixed_version":"2.15.0"}}}]
    epss = {"CVE-2021-44228":{"epss":0.97,"percentile":0.999}}
    enriched = enrich_vex(sbom, findings, epss)
    assert enriched["vulnerabilities"][0]["id"] == "CVE-2021-44228"
    assert enriched["vulnerabilities"][0]["analysis"]["state"] == "affected"
run_case('SBOM + VEX enrichment', t2)

def t3():
    cdx = generate_sbom(_pkgs)
    spdx = cdx_to_spdx(cdx)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 2
run_case('CycloneDX → SPDX roundtrip', t3)

def t4():
    spdx = generate_spdx(_pkgs)
    sig = sign_sbom(spdx, b"stab-key")
    assert verify_sbom(spdx, sig, b"stab-key")
    spdx["packages"][0]["versionInfo"] = "9.9.9"
    assert not verify_sbom(spdx, sig, b"stab-key")
run_case('SPDX sign/verify + tamper', t4)

def t5():
    assert compute_risk("CRITICAL",0.95,1.0)["level"] == "critical"
    assert compute_risk("CRITICAL",0.001,1.0)["level"] == "low"
run_case('EPSS risk: HIGH epss > CRITICAL paper', t5)

def t6():
    assert extract_cve_id({"vuln_id":"GHSA-x","aliases":["CVE-2021-44228"]}) == "CVE-2021-44228"
run_case('CVE from SCA metadata', t6)

def t7():
    from gsc_detectors.gs031_iac import GS031IaCDetector
    det = GS031IaCDetector()
    assert any("DOCKER" in h["rule_id"] for h in det.detect("Dockerfile","FROM node:latest\nUSER root","auto"))
    assert any("TF" in h["rule_id"] for h in det.detect("main.tf",'acl = "public-read"',"auto"))
    assert det.detect("app.py","print(1)","python") == []
run_case('IaC detector type routing', t7)

def t8():
    from gsc_iac import detect_kubernetes
    hits = detect_kubernetes("pod.yaml","apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true")
    for f in ("finding_key","rule_id","severity","confidence","file","snippet"):
        assert f in hits[0], f"missing {f}"
run_case('IaC findings match common format', t8)

def t9():
    from gsc_compliance import compliance_for
    assert compliance_for("GS031-K8S-PRIVILEGED")["cwe"] == "CWE-250"
run_case('IaC compliance mapping', t9)

def t10():
    from gsc_federated import collect_local_metrics
    class MockDB:
        class conn:
            @staticmethod
            def execute(s,*a):
                class R:
                    @staticmethod
                    def fetchall(): return [{"rule_id":"GS005","tp":5,"fp":1}]
                return R()
    m = collect_local_metrics(MockDB(), min_verdicts=3)
    s = json.dumps(m)
    assert "snippet" not in s and "finding_key" not in s and "/" not in s
run_case('Federated privacy: no code leak', t10)

print(f'\n{"="*50}')
print(f'Integration: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
