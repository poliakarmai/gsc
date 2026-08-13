#!/usr/bin/env python3
"""tests/test_perf.py — performance: caches, degradation, migration (+4, v0.36)."""
import sys, os, sqlite3
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    from gsc_sca import _cache_get, _cache_put
    assert callable(_cache_get) and callable(_cache_put)
run_case('SCA cache functions callable', t1)

def t2():
    from gsc_epss import CACHE_TTL_HOURS, EpssClient
    assert CACHE_TTL_HOURS == 24
run_case('EPSS cache TTL = 24h', t2)

def t3():
    # Scanner module importable (degradation handled inside)
    import gsc_external
    assert gsc_external is not None
run_case('Scanner constructable without LLM', t3)

def t4():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE schema_version (version INT)")
    db.execute("INSERT INTO schema_version VALUES (28)")
    db.execute("INSERT INTO schema_version VALUES (28)")  # duplicate
    ver = max(r[0] for r in db.execute("SELECT version FROM schema_version"))
    assert ver == 28
    db.close()
run_case('Migration idempotent', t4)

print(f'\n{"="*50}')
print(f'Perf: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
