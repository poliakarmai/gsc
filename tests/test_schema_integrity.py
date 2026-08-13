#!/usr/bin/env python3
"""tests/test_schema_integrity.py — schema version + table consistency (+3)."""
import sys, os, tempfile
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_db import GSCDatabase, TARGET_VERSION

EXPECTED_TABLES_V28 = {
    "findings","chains","mutation_alerts","finding_sightings",
    "overrides","published_comments","publication_events","comment_reactions",
    "audit_runs","file_state","secret_fingerprints","secret_sightings",
    "nuclei_templates","dast_findings","sca_cache",
    "federated_global_weights","federated_deactivated","federated_log",
    "epss_cache","schema_version",
}

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    from gsc_db import GSCDatabase
    with GSCDatabase() as db:
        assert db._schema_version() == TARGET_VERSION
run_case(f'schema version is {TARGET_VERSION}', t1)

def t2():
    from gsc_db import GSCDatabase
    with GSCDatabase() as db:
        rows = db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        actual = {r["name"] for r in rows}
    missing = EXPECTED_TABLES_V28 - actual
    assert not missing, f"Missing tables: {missing}"
run_case(f'all {len(EXPECTED_TABLES_V28)} expected tables present', t2)

def t3():
    from gsc_db import GSCDatabase
    with GSCDatabase() as db:
        # Migration idempotency: re-running doesn't crash
        db._migrate()
        v = db._schema_version()
        assert v == TARGET_VERSION
run_case('migration idempotent (re-run safe)', t3)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
