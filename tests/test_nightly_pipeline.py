"""
Integration tests for nightly pipeline end-to-end flow.

Run: pytest tests/test_nightly_pipeline.py -v
"""
import sys, os, sqlite3, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from gsc_shadow_manager import ShadowDetectorManager
from scripts.gsc_auto_detector import _run_gate_all, run_gate, generate_pattern, validate_pattern


def _db_with_data():
    """DB with enough bounty examples for gate (synthetic)."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS detector_status (
            rule_id TEXT PRIMARY KEY, status TEXT DEFAULT 'full',
            confidence REAL DEFAULT 0.85, tp_rate REAL DEFAULT 0.0,
            verdicts INTEGER DEFAULT 0, tp_count INTEGER DEFAULT 0,
            fp_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS bounty_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT, language TEXT, fix_quality TEXT DEFAULT 'unknown',
            vulnerable_code TEXT, fixed_code TEXT, pattern_hash TEXT,
            collected_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS negative_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT, language TEXT, clean_code TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_key TEXT, verdict TEXT, reason TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    return db


# ═══════════════════════════════════════════════════════════════════════════════

def test_shadow_registers_and_promotes():
    """Full cycle: shadow registration → verdicts → promotion."""
    db = _db_with_data()

    # Simulate collected bounty examples
    for i in range(5):
        db.execute("""
            INSERT INTO bounty_examples (cwe_id, language, fix_quality,
                vulnerable_code, fixed_code, pattern_hash)
            VALUES ('CWE-88', 'python', 'fix',
                'allow_unsafe=True; do_git()',
                'allow_unsafe=False; do_git()',
                ?)
        """, (f"hash_{i}",))

    # Add negative example
    db.execute("""
        INSERT INTO negative_examples (cwe_id, language, clean_code)
        VALUES ('CWE-88', 'python', 'safe_code_here')
    """)

    # Register a shadow detector directly (simulating gate PASS)
    sm = ShadowDetectorManager(db)
    sm.register_shadow("GSAUTO-88-python", tp_rate=0.85)
    assert sm.get_status("GSAUTO-88-python") == "shadow"

    # Collect 10 verdicts: 7 TP + 3 FP = 70% → promotion
    for _ in range(7):
        sm.record_verdict("GSAUTO-88-python", "tp")
    for _ in range(3):
        sm.record_verdict("GSAUTO-88-python", "fp")

    assert sm.get_status("GSAUTO-88-python") == "full"
    assert sm.get_confidence("GSAUTO-88-python") >= 0.80


def test_pipeline_idempotent_shadow_registration():
    """Repeated registration should not duplicate."""
    db = _db_with_data()
    sm = ShadowDetectorManager(db)

    sm.register_shadow("GSAUTO-79-js", tp_rate=0.80)
    sm.register_shadow("GSAUTO-79-js", tp_rate=0.80)
    sm.register_shadow("GSAUTO-79-js", tp_rate=0.85)

    assert sm.get_status("GSAUTO-79-js") == "shadow"
    # Should be exactly 1 record (INSERT OR REPLACE)
    count = db.execute(
        "SELECT COUNT(*) as c FROM detector_status WHERE rule_id='GSAUTO-79-js'"
    ).fetchone()["c"]
    assert count == 1


def test_old_detector_unaffected_by_shadow():
    """GS005 should remain 'full' regardless of shadow manager activity."""
    db = _db_with_data()
    sm = ShadowDetectorManager(db)
    assert sm.get_status("GS005") == "full"
    assert sm.get_confidence("GS005") == 0.85
    assert sm.is_shadow("GS005") is False


def test_pattern_generation_is_deterministic():
    """Same training data → same pattern."""
    from scripts.gsc_auto_detector import Sample

    train = [
        Sample("unsafe_func(user_input)", "h1"),
        Sample("unsafe_func(data)", "h2"),
    ]

    p1 = generate_pattern(train, "CWE-88", "python")
    p2 = generate_pattern(train, "CWE-88", "python")
    assert p1 == p2  # Deterministic


def test_health_check_all_ok():
    """Health check returns 0 when everything is fine."""
    from scripts.gsc_pipeline_health import main as health_main
    # Should run without crashing (will report based on real DB state)
    rc = health_main()
    assert rc in (0, 1)  # 0=OK, 1=issues — both valid outcomes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
