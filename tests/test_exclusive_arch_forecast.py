#!/usr/bin/env python3
"""tests/test_exclusive_arch_forecast.py — Archaeology + Forecasting (+5)."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_archaeology import content_fingerprint
from gsc_forecast import calc_risk_score, risk_level

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    a = "query = f'SELECT * FROM users'"
    b = "query  =   f'SELECT * FROM users'  "
    assert content_fingerprint(a) == content_fingerprint(b)
test('content_fingerprint survives whitespace', t1)

def t2():
    a = "query = 'SELECT * FROM users'"
    b = "cursor.execute(query, (uid,))"
    assert content_fingerprint(a) != content_fingerprint(b)
    assert len(content_fingerprint(a)) == 16
test('content_fingerprint changes with code', t2)

def t3():
    s = {"past_critical":3,"past_high":2,"churn_90d":42,"authors_90d":4,
         "lines":1200,"age_days":10,"module_critical_count":6}
    score = calc_risk_score(s)
    assert score >= 50
    assert risk_level(score) == "critical"
test('calc_risk_score: high density + churn → critical', t3)

def t4():
    s = {"past_critical":0,"past_high":0,"churn_90d":2,"authors_90d":1,
         "lines":50,"age_days":200,"module_critical_count":0}
    score = calc_risk_score(s)
    assert risk_level(score) == "low"
test('calc_risk_score: clean file → low', t4)

def t5():
    assert risk_level(50) == "critical"
    assert risk_level(49) == "high"
    assert risk_level(30) == "high"
    assert risk_level(29) == "medium"
    assert risk_level(15) == "medium"
    assert risk_level(14) == "low"
test('risk_level boundaries', t5)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
