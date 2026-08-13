#!/usr/bin/env python3
"""tests/test_exclusive_policy_secrets.py — NL Policy + Cross-Repo Secrets (+5)."""
import sys, os, re
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_nlpolicy import compile_policy, PolicyError
from gsc_crossrepo_secrets import REFINED_PATTERNS, fingerprint_secret

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

class FakeLLM:
    def ask(self, prompt, max_tokens=None):
        return '{"rule_id": "GS028-custom", "severity": "HIGH", "pattern": "abc123"}'

class EvilLLM:
    def ask(self, prompt, max_tokens=None):
        return '{"rule_id": "x", "severity": "HIGH", "pattern": "(a+)+$"}'

def t1():
    pol = compile_policy("no secrets in logs", llm=FakeLLM())
    assert pol["rule_id"] == "GS028-custom"
    assert "abc123" in pol["pattern"]
test('NL policy: accepts safe pattern', t1)

def t2():
    try:
        compile_policy("x", llm=EvilLLM())
        assert False, "should have raised"
    except PolicyError as e:
        assert "ReDoS" in str(e) or "quantifier" in str(e).lower()
test('NL policy: rejects ReDoS pattern', t2)

def t3():
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    hits = [st for pat, st in REFINED_PATTERNS if re.search(pat, sha)]
    assert len(hits) == 0, f"REFINED_PATTERNS false-matched SHA: {hits}"
test('REFINED_PATTERNS do NOT false-positively match SHA-256', t3)

def t4():
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    for pat, st in REFINED_PATTERNS:
        assert re.search(pat, sha) is None, f"REFINED {st} gives FP on hash"
test('REFINED_PATTERNS: no FP on bare hash', t4)

def t5():
    fp = fingerprint_secret("AKIAIOSFODNN7EXAMPLE")
    assert len(fp) == 32
    assert "AKIA" not in fp
test('fingerprint_secret: irreversible hash', t5)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
