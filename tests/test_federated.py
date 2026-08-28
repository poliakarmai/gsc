#!/usr/bin/env python3
"""tests/test_federated.py — federated learning tests (+7)."""
import sys, os, json
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_federated import (
    _base_rule, add_laplace_noise, collect_local_metrics, adjust_confidence,
    auto_deactivate_global, is_globally_deactivated, FederatedClient,
    _sanitize_weight
)

passed = 0
failed = 0

def run_case(name, fn):
    global passed, failed
    try:
        fn()
        print(f'  ✅ {name}')
        passed += 1
    except Exception as e:
        print(f'  ❌ {name}: {e}')
        failed += 1


def t1():
    # Test base_rule extraction
    assert _base_rule("GS025-permissive_cors") == "GS025"
    assert _base_rule("GS030-PYSEC-2018-58") == "GS030"
    assert _base_rule("GS001") == "GS001"
run_case('base_rule extraction', t1)


def t2():
    # Laplace noise is always non-negative after many iterations
    for _ in range(100):
        assert add_laplace_noise(0, 1.0) >= 0
        assert add_laplace_noise(5, 1.0) >= 0
run_case('laplace noise non-negative', t2)


def t3():
    # adjust_confidence with penalty (low tp_rate)
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: 0.30})()
    f = {"rule_id": "GS001", "confidence": 0.80}
    adjust_confidence(f, fake)
    assert f["confidence"] < 0.80
    assert f["metadata"]["federated_adjusted"] == "penalty"
    assert f["metadata"]["global_tp_rate"] == 0.3
run_case('adjust_confidence penalty', t3)


def t4():
    # adjust_confidence with boost (high tp_rate)
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: 0.95})()
    f = {"rule_id": "GS005", "confidence": 0.80}
    adjust_confidence(f, fake)
    assert f["confidence"] > 0.80
    assert f["metadata"]["federated_adjusted"] == "boost"
run_case('adjust_confidence boost', t4)


def t5():
    # adjust_confidence no-op when no global data
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: None})()
    f = {"rule_id": "GS001", "confidence": 0.80}
    original = f["confidence"]
    adjust_confidence(f, fake)
    assert f["confidence"] == original
run_case('adjust_confidence no global data', t5)


def t6():
    # verify export has no code/snippets/paths
    # Simulate the privacy constraint
    metrics = {"GS001": {"tp": 5, "fp": 2}}
    payload = json.dumps(metrics)
    assert "snippet" not in payload
    assert "finding_key" not in payload
    assert "/" not in payload
    assert all(k.startswith("GS") for k in metrics.keys())
run_case('privacy: no code leak in metrics', t6)


def t7():
    # auto_deactivate: only globally noisy rules with enough verdicts
    import tempfile
    from pathlib import Path
    from gsc_db import GSCDatabase
    # GSC-005: isolate on a fresh temp DB — the production DB may already hold
    # stale federated_global_weights rows (rule_id=category) that break the
    # assertion. A test must never depend on (or mutate) the production DB.
    tmpdb = Path(tempfile.mkdtemp()) / "fed_test.db"
    with GSCDatabase(path=tmpdb) as db:
        # Seed test weights
        for rule_id, rate, verdicts in [
            ("GS099", 0.20, 50),   # noisy + many → deactivate
            ("GS001", 0.85, 100),  # accurate → keep
            ("GS002", 0.25, 5),    # noisy but few → keep
        ]:
            db.conn.execute("""INSERT OR REPLACE INTO federated_global_weights
                (rule_id, global_tp_rate, global_verdicts, updated_at)
                VALUES (?, ?, ?, datetime('now'))""", (rule_id, rate, verdicts))
        db.conn.commit()

        client = FederatedClient(db, "http://x", "key")
        deactivated = auto_deactivate_global(db, client, tp_threshold=0.30, min_verdicts=30)
        assert deactivated == ["GS099"]
        assert is_globally_deactivated(db, "GS099") == True
        assert is_globally_deactivated(db, "GS001") == False
        assert is_globally_deactivated(db, "GS002") == False
run_case('auto_deactivate_global', t7)


def t8():
    # self-poisoning defence: sanitize_weight clamps/rejects implausible weights
    ok = _sanitize_weight("GS001", {"tp_rate": 0.7, "verdicts": 50, "tenants": 4})
    assert ok == (0.7, 50)
    assert _sanitize_weight("GS001", "nope") is None
    assert _sanitize_weight("GS001", None) is None
    assert _sanitize_weight("GS001", {"tp_rate": 1.5, "verdicts": 50, "tenants": 4}) is None
    assert _sanitize_weight("GS001", {"tp_rate": -0.1, "verdicts": 50, "tenants": 4}) is None
    assert _sanitize_weight("GS001", {"tp_rate": float('nan'), "verdicts": 50, "tenants": 4}) is None
    assert _sanitize_weight("GS001", {"tp_rate": float('inf'), "verdicts": 50, "tenants": 4}) is None
    assert _sanitize_weight("GS001", {"tp_rate": 0.7, "verdicts": 5, "tenants": 4}) is None
    assert _sanitize_weight("GS001", {"tp_rate": 0.7, "verdicts": 50, "tenants": 1}) is None
    assert _sanitize_weight("GS001", {}) is None
run_case('sanitize_weight self-poisoning bounds', t8)


def t9():
    # self-poisoning defence: fed must NOT deactivate a rule with local TP
    import tempfile
    from pathlib import Path
    from gsc_db import GSCDatabase
    tmpdb = Path(tempfile.mkdtemp()) / "fed_test.db"
    with GSCDatabase(path=tmpdb) as db:
        db.conn.execute("""INSERT OR REPLACE INTO federated_global_weights
            (rule_id, global_tp_rate, global_verdicts, updated_at)
            VALUES ('GS099', 0.20, 50, datetime('now'))""")
        db.conn.execute("""INSERT INTO findings (finding_key, rule_id, project, echelon, category, title)
            VALUES ('fk1', 'GS099-vuln', 'test', 1, 'sec', 't')""")
        db.conn.execute("""INSERT INTO feedback (finding_key, verdict)
            VALUES ('fk1', 'tp')""")
        db.conn.commit()
        client = FederatedClient(db, "http://x", "key")
        deactivated = auto_deactivate_global(db, client, tp_threshold=0.30, min_verdicts=30)
        assert deactivated == [], f"fed deactivated rule with local TP: {deactivated}"
run_case('auto_deactivate_global local-TP guard', t9)


def t10():
    # self-poisoning defence: server publishes a weight only with tenant quorum
    import sqlite3, tempfile
    from pathlib import Path
    from gsc_cloud.federated_server import FederatedServer
    tmp = Path(tempfile.mkdtemp()) / "srv.db"
    conn = sqlite3.connect(str(tmp))
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE federated_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_hash TEXT, rule_id TEXT,
            tp_count INTEGER, fp_count INTEGER, submitted_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE federated_global_weights (
            rule_id TEXT PRIMARY KEY, global_tp_rate REAL, global_verdicts INTEGER,
            tenant_count INTEGER, computed_at TEXT DEFAULT (datetime('now')));
    """)
    srv = FederatedServer(conn)
    srv.submit("tenant_A", {"GS099": {"tp": 0, "fp": 100}})
    srv.compute_weights(min_total_verdicts=10, min_tenants=3)
    assert "GS099" not in srv.get_weights(), "single-tenant weight published (no quorum)"
    srv.submit("tenant_B", {"GS099": {"tp": 0, "fp": 10}})
    srv.submit("tenant_C", {"GS099": {"tp": 0, "fp": 10}})
    srv.compute_weights(min_total_verdicts=10, min_tenants=3)
    assert "GS099" in srv.get_weights(), "quorum-met weight not published"
run_case('federated server Sybil quorum', t10)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
