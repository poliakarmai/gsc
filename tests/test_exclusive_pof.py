#!/usr/bin/env python3
"""tests/test_exclusive_pof.py — Proof-of-Fix + Self-Healing tests (+7)."""
import sys, os
os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

from gsc_poc_generator import SUCCESS_MARKERS
from gsc_selfhealing import ELIGIBLE_RULES, MAX_AUTOFIX_PER_FILE, MAX_AUTOFIX_PER_FINDING

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    assert len(SUCCESS_MARKERS) >= 3
    assert "VULNERABLE" in SUCCESS_MARKERS
test('SUCCESS_MARKERS contract', t1)

def t2():
    from gsc_proofoffix import _run_poc_sandboxed
    import tempfile, shutil
    d = tempfile.mkdtemp()
    # PoC that prints VULNERABLE and exits 0
    poc = 'print("VULNERABLE: exploit works")'
    r = _run_poc_sandboxed(poc, d)
    assert r["exploited"] is True
    assert "VULNERABLE" in r["output"].upper()
    shutil.rmtree(d, ignore_errors=True)
    # PoC that exits 0 but NO marker
    d2 = tempfile.mkdtemp()
    poc2 = 'print("all good")'
    r2 = _run_poc_sandboxed(poc2, d2)
    assert r2["exploited"] is False
    shutil.rmtree(d2, ignore_errors=True)
test('PoC marker contract: exit 0 + VULNERABLE = exploited', t2)

def t3():
    # exit 1 + marker = NOT exploited
    from gsc_proofoffix import _run_poc_sandboxed
    import tempfile, shutil
    d = tempfile.mkdtemp()
    poc = 'print("VULNERABLE")\nimport sys; sys.exit(1)'
    r = _run_poc_sandboxed(poc, d)
    assert r["exploited"] is False
    shutil.rmtree(d, ignore_errors=True)
test('exit 1 + marker = not exploited', t3)

def t4():
    # verify fix: vulnerable before, safe after
    from gsc_proofoffix import ProofOfFix
    assert ProofOfFix._classify(True, False, True, False) == "verified"
    assert ProofOfFix._classify(True, True, True, True) != "verified"
test('_classify: vulnerable before + safe after = verified', t4)

def t5():
    assert MAX_AUTOFIX_PER_FINDING == 1
    assert MAX_AUTOFIX_PER_FILE == 2
    assert ELIGIBLE_RULES == {"GS001","GS004","GS005","GS017","GS020","GS021"}
test('Self-Healing loop guard limits', t5)

def t6():
    from gsc_selfhealing import _eligible_for_autofix
    base = {"category":"CRITICAL","confidence":0.85,"rule_id":"GS005","revalidation_verdict":""}
    assert _eligible_for_autofix(base) is True
    assert _eligible_for_autofix({**base,"category":"LOW"}) is False
    assert _eligible_for_autofix({**base,"confidence":0.70}) is False
    assert _eligible_for_autofix({**base,"revalidation_verdict":"fp"}) is False
    assert _eligible_for_autofix({**base,"rule_id":"GS999"}) is False
test('_eligible_for_autofix rules', t6)

def t7():
    from gsc_selfhealing import _eligible_for_autofix
    assert _eligible_for_autofix({"category":"CRITICAL","confidence":0.85,"rule_id":"GS001","revalidation_verdict":"","source":"gsc-autofix"}) is False
test('gsc-autofix loop guard blocks re-processing', t7)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
