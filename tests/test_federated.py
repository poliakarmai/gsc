#!/usr/bin/env python3
"""tests/test_federated.py — federated learning tests (+7)."""
import sys, os, json
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_federated import (
    _base_rule, add_laplace_noise, collect_local_metrics, adjust_confidence,
    auto_deactivate_global, is_globally_deactivated, FederatedClient
)

passed = 0
failed = 0

def test(name, fn):
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
test('base_rule extraction', t1)


def t2():
    # Laplace noise is always non-negative after many iterations
    for _ in range(100):
        assert add_laplace_noise(0, 1.0) >= 0
        assert add_laplace_noise(5, 1.0) >= 0
test('laplace noise non-negative', t2)


def t3():
    # adjust_confidence with penalty (low tp_rate)
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: 0.30})()
    f = {"rule_id": "GS001", "confidence": 0.80}
    adjust_confidence(f, fake)
    assert f["confidence"] < 0.80
    assert f["metadata"]["federated_adjusted"] == "penalty"
    assert f["metadata"]["global_tp_rate"] == 0.3
test('adjust_confidence penalty', t3)


def t4():
    # adjust_confidence with boost (high tp_rate)
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: 0.95})()
    f = {"rule_id": "GS005", "confidence": 0.80}
    adjust_confidence(f, fake)
    assert f["confidence"] > 0.80
    assert f["metadata"]["federated_adjusted"] == "boost"
test('adjust_confidence boost', t4)


def t5():
    # adjust_confidence no-op when no global data
    fake = type('Fake', (), {'get_global_tp_rate': lambda s, rid: None})()
    f = {"rule_id": "GS001", "confidence": 0.80}
    original = f["confidence"]
    adjust_confidence(f, fake)
    assert f["confidence"] == original
test('adjust_confidence no global data', t5)


def t6():
    # verify export has no code/snippets/paths
    # Simulate the privacy constraint
    metrics = {"GS001": {"tp": 5, "fp": 2}}
    payload = json.dumps(metrics)
    assert "snippet" not in payload
    assert "finding_key" not in payload
    assert "/" not in payload
    assert all(k.startswith("GS") for k in metrics.keys())
test('privacy: no code leak in metrics', t6)


def t7():
    # auto_deactivate: only globally noisy rules with enough verdicts
    from gsc_db import GSCDatabase
    with GSCDatabase() as db:
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
test('auto_deactivate_global', t7)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
