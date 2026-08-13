#!/usr/bin/env python3
"""tests/test_pipeline_refactor.py — unified pipeline contract tests."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_detectors.base import make_finding, RegexDetector, BaseDetector

passed, failed = 0, 0
def t(n, f):
    global passed, failed
    try: f(); print(f'  ✅ {n}'); passed += 1
    except Exception as e: print(f'  ❌ {n}: {e}'); failed += 1

def t1():
    f1 = make_finding("GS005","SQLi","CRITICAL",0.9,"a.py",1,"s")
    f2 = make_finding("GS005","SQLi","CRITICAL",0.9,"a.py",1,"s")
    assert f1["finding_key"] == f2["finding_key"] and len(f1["finding_key"]) == 12
t('finding_key stable', t1)

def t2():
    det = RegexDetector("GS020","XSS",[(r'f"<div>\{',"f-string XSS")],"HIGH",0.65,("python",))
    hits = det.detect("app.py", 'x = f"<div>{name}</div>"\n', "python")
    assert len(hits) == 1 and hits[0]["rule_id"] == "GS020"
t('RegexDetector finds f-string XSS', t2)

def t3():
    det = RegexDetector("GS020","XSS",[(r'f"<div>\{',"f-string XSS")],"HIGH",0.65,("python",))
    hits = det.detect("main.go", 'x := fmt.Sprintf("<div>%s", n)\n', "go")
    assert len(hits) == 0  # language filter
t('language filter excludes Go files', t3)

def t4():
    # Dedup via make_finding — same inputs = same finding_key
    f1 = make_finding("GS005","SQLi","HIGH",0.9,"a.py",1,"x")
    f2 = make_finding("GS005","SQLi","HIGH",0.9,"a.py",1,"x")
    keys = {f1["finding_key"], f2["finding_key"]}
    assert len(keys) == 1
t('dedup via finding_key identity', t4)

def t5():
    f = make_finding("GS005","SQLi","HIGH",0.9,"a.py",1,"x"*500)
    assert len(f["snippet"]) <= 200
t('snippet truncated to 200 chars', t5)

def t6():
    assert hasattr(BaseDetector, "rule_id") and hasattr(BaseDetector, "detect")
    d = RegexDetector("X","T",[],"LOW",0.5); assert d.rule_id == "X" and hasattr(d,"detect")
t('BaseDetector contract implemented', t6)

print(f'\n{"="*50}\n{passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
