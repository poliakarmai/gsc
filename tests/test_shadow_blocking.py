"""
Tests for ShadowDetectorManager + Blocking Engine integration.

Run: pytest tests/test_shadow_blocking.py -v
"""
import sys, os, sqlite3, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from gsc_shadow_manager import ShadowDetectorManager
from gsc_blocking import BlockingEngine


def _db():
    """In-memory SQLite DB for isolated tests."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS detector_status (
            rule_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'full',
            confidence REAL DEFAULT 0.85,
            tp_rate REAL DEFAULT 0.0,
            verdicts INTEGER DEFAULT 0,
            tp_count INTEGER DEFAULT 0,
            fp_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
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
# ShadowDetectorManager tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_old_detectors_are_full_by_default():
    m = ShadowDetectorManager(_db())
    assert m.get_status("GS005") == "full"


def test_register_shadow_sets_confidence_below_blocking():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-88-python", tp_rate=0.85)
    assert m.get_status("GSAUTO-88-python") == "shadow"
    conf = m.get_confidence("GSAUTO-88-python")
    assert conf == 0.75  # Below HIGH≥0.85 blocking threshold


def test_promotion_after_10_verdicts_tp70():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-79-js", tp_rate=0.80)
    for _ in range(7):
        m.record_verdict("GSAUTO-79-js", "tp")
    for _ in range(3):
        m.record_verdict("GSAUTO-79-js", "fp")
    # 7 tp + 3 fp = 10 verdicts, TP = 70% → promotion
    assert m.get_status("GSAUTO-79-js") == "full"


def test_deactivation_low_tp():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-22-py", tp_rate=0.50)
    for _ in range(2):
        m.record_verdict("GSAUTO-22-py", "tp")
    for _ in range(8):
        m.record_verdict("GSAUTO-22-py", "fp")
    # TP = 20% < 30% → deactivation
    assert m.get_status("GSAUTO-22-py") == "deactivated"


def test_no_transition_before_10_verdicts():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-89-py", tp_rate=0.90)
    for _ in range(9):
        m.record_verdict("GSAUTO-89-py", "tp")
    assert m.get_status("GSAUTO-89-py") == "shadow"  # 9 < 10


# ═══════════════════════════════════════════════════════════════════════════════
# Blocking Engine integration tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_shadow_does_not_block_even_at_high_confidence():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-88-python", tp_rate=0.85)

    be = BlockingEngine(db, "blocking-standard", {})
    finding = {"rule_id": "GSAUTO-88-python", "severity": "HIGH", "confidence": 0.90}
    assert be.detector_allowed("GSAUTO-88-python") == (True, "shadow (scan only, non-blocking)")


def test_old_full_detector_defaults_to_full():
    """GS005 has no detector_status entry → ShadowDetectorManager returns 'full'."""
    db = _db()
    m = ShadowDetectorManager(db)
    assert m.get_status("GS005") == "full"
    assert m.get_confidence("GS005") == 0.85  # default
    assert m.is_shadow("GS005") is False


def test_shadow_detector_allowed_but_non_blocking():
    """Shadow detector is allowed to scan but marked as shadow status."""
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-88-python", tp_rate=0.85)

    be = BlockingEngine(db, "blocking-standard", {})
    allowed, reason = be.detector_allowed("GSAUTO-88-python")
    assert allowed is True  # Allowed to scan
    assert "shadow" in reason  # But non-blocking


def test_deactivated_detector_not_allowed():
    db = _db()
    m = ShadowDetectorManager(db)
    m.register_shadow("GSAUTO-22-py", tp_rate=0.10)
    for _ in range(10):
        m.record_verdict("GSAUTO-22-py", "fp")
    be = BlockingEngine(db, "blocking-standard", {})
    allowed, reason = be.detector_allowed("GSAUTO-22-py")
    assert allowed is False
    assert "deactivated" in reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
