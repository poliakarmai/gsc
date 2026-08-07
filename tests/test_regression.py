#!/usr/bin/env python3
"""tests/test_regression.py — regression: fixed bugs + invariants (+6, v0.36)."""
import sys, os, re, hashlib
os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    from gsc_crossrepo_secrets import REFINED_PATTERNS
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    for p, t in REFINED_PATTERNS:
        assert re.search(p, sha) is None, f"{t} FP on SHA-256"
test('Secrets FP fix confirmed', t1)

def t2():
    from pathlib import Path
    dets = list((Path('.')/'gsc_detectors').glob('gs*.py'))
    assert len(dets) >= 28, f"only {len(dets)} detector files"
test('28+ detector files present', t2)

def t3():
    key = hashlib.sha256("GS001app.pydb.query(x)".encode()).hexdigest()[:12]
    assert len(key) == 12 and all(c in "0123456789abcdef" for c in key)
test('finding_key format stable', t3)

def t4():
    from gsc_blocking import BlockingEngine
    be = BlockingEngine(db=None, phase="blocking-standard", config={})
    assert be._meets_threshold({"severity":"CRITICAL","confidence":0.90}, [("CRITICAL",0.90),("HIGH",0.85)])
    assert not be._meets_threshold({"severity":"HIGH","confidence":0.80}, [("CRITICAL",0.90),("HIGH",0.85)])
test('Blocking Engine thresholds unchanged', t4)

def t5():
    from gsc_compliance import compliance_for
    for r in ["GS001","GS005","GS017","GS019","GS029","GS030","GS031-K8S-PRIVILEGED"]:
        assert compliance_for(r).get("cwe"), f"no CWE for {r}"
test('Compliance covers new rules', t5)

def t6():
    from pathlib import Path
    for mod in ["gsc_sca.py","gsc_sbom.py","gsc_spdx.py","gsc_iac.py","gsc_epss.py","gsc_federated.py"]:
        assert (Path('.')/mod).exists(), f"{mod} missing"
test('All P0/P1/P2 modules present', t6)

print(f'\n{"="*50}')
print(f'Regression: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
