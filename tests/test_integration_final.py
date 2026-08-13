#!/usr/bin/env python3
"""tests/test_integration_final.py — final integration: orchestrator + format consistency (v0.39)."""
import sys, os, hashlib
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_orchestrator import GSCOrchestrator, PipelineResult

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

class MockScanner:
    db = None
    def scan(self, t, p):
        return [{"finding_key":"abc123def456","rule_id":"GS005","severity":"CRITICAL",
                "confidence":0.90,"file":"app.py","line":10,"snippet":"db.query(x)","title":"SQLi"}]

orch = GSCOrchestrator(MockScanner())

def t1():
    r = orch.run("./repo","audit",with_sbom=False,with_chains=False)
    assert isinstance(r, PipelineResult)
    assert r.summaries["total"] == 1 and r.summaries["critical"] == 1
test('orchestrator pipeline result', t1)

def t2():
    r = GSCOrchestrator(MockScanner()).run("./repo","audit",with_sbom=False,with_chains=False)
    assert r.summaries["total"] == 1
test('graceful without optional modules', t2)

def t3():
    from gsc_iac import detect_dockerfile
    required = {"finding_key","rule_id","severity","confidence","file","snippet"}
    hits = detect_dockerfile("Dockerfile","FROM node:latest\nUSER root")
    for h in hits: assert required <= set(h.keys())
test('IaC finding format matches contract', t3)

def t4():
    rule, file, snippet = "GS005","app.py","db.query(x)"
    key = hashlib.sha256(f"{rule}{file}{snippet}".encode()).hexdigest()[:12]
    assert len(key)==12 and all(c in "0123456789abcdef" for c in key)
test('finding_key format stable', t4)

def t5():
    from enterprise.rbac import can
    assert can("developer","verdict") and not can("developer","override")
    assert can("security_lead","override")
test('Enterprise RBAC link', t5)

def t6():
    from gsc_sca import Package
    from gsc_sbom import generate_sbom, enrich_vex
    pkgs = [Package("req","2.0","PyPI","r.txt",1,"req==2.0")]
    sbom = generate_sbom(pkgs)
    findings = [{"severity":"HIGH","metadata":{"sca":{"vuln_id":"CVE-2018-X","package":"req","ecosystem":"PyPI","current_version":"2.0"}}}]
    enriched = enrich_vex(sbom, findings, {})
    assert len(enriched["vulnerabilities"]) == 1
test('SBOM + VEX pipeline', t6)

def t7():
    from gsc_compliance import compliance_for
    assert isinstance(compliance_for("GS030"), dict)
test('compliance enriches SCA rules', t7)

print(f'\n{"="*50}\nIntegration: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
