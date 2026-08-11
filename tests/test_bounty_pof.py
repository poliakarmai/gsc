"""
Tests for BountyLoader → Proof-of-Fix few-shot integration.

Run: pytest tests/test_bounty_pof.py -v
"""
import sys, os, sqlite3, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from gsc_bounty_loader import BountyLoader


def _db_with_bounty():
    """DB with fix-quality and workaround examples."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS bounty_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT, language TEXT, summary TEXT,
            fix_quality TEXT DEFAULT 'unknown',
            vulnerable_code TEXT, fixed_code TEXT,
            fix_context TEXT, hunk_relevance REAL DEFAULT 0.5,
            ghsa_id TEXT, cve_id TEXT,
            collected_at TEXT DEFAULT (datetime('now'))
        );
        -- Fix-quality example (should be used)
        INSERT INTO bounty_examples (cwe_id, language, fix_quality,
            vulnerable_code, fixed_code, fix_context, hunk_relevance, summary, ghsa_id)
        VALUES ('CWE-88', 'python', 'fix',
            'options = {\"--unsafe\": True}', 'allow_unsafe=False; options={}',
            'def run_git(allow_unsafe=False):', 0.9,
            'GitPython arg injection fix', 'GHSA-xxxx');
        -- Workaround (should NOT be used)
        INSERT INTO bounty_examples (cwe_id, language, fix_quality,
            vulnerable_code, fixed_code, hunk_relevance, summary, ghsa_id)
        VALUES ('CWE-88', 'python', 'workaround',
            'vuln', 'FIXME: temporary', 0.2,
            'GitPython workaround', 'GHSA-yyyy');
        -- Another fix
        INSERT INTO bounty_examples (cwe_id, language, fix_quality,
            vulnerable_code, fixed_code, fix_context, hunk_relevance, summary, ghsa_id)
        VALUES ('CWE-88', 'python', 'fix',
            'exec(unsafe)', 'subprocess.run([safe])',
            'def execute(cmd):', 0.7,
            'Command injection fix', 'GHSA-zzzz');
    """)
    db.commit()
    return db


def _empty_db():
    return sqlite3.connect(":memory:")


# ═══════════════════════════════════════════════════════════════════════════════

def test_few_shot_only_fix_quality():
    """get_few_shot_fixes must return ONLY fix_quality='fix', not workarounds."""
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _db_with_bounty()  # Override DB for test

    fixes = loader.get_few_shot_fixes("CWE-88", "python", k=5)
    assert len(fixes) == 2  # Only 2 fix-quality, not the workaround
    for f in fixes:
        assert f["fix_quality"] == "fix"
        assert "workaround" not in f.get("fixed_code", "").lower()


def test_build_pof_prompt_returns_none_without_examples():
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _empty_db()
    prompt = loader.build_pof_prompt("CWE-999", "python", "snippet")
    assert prompt is None  # Explicit fallback signal


def test_build_pof_prompt_includes_examples():
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _db_with_bounty()
    prompt = loader.build_pof_prompt("CWE-88", "python", "os.system(user_input)")
    assert prompt is not None
    assert "Real fix example" in prompt or "Few-Shot" in prompt
    assert "CWE-88" in prompt


def test_build_pof_prompt_sorted_by_relevance():
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _db_with_bounty()
    prompt = loader.build_pof_prompt("CWE-88", "python", "code")
    # First example should be the one with highest hunk_relevance (0.9)
    idx_09 = prompt.find("GHSA-xxxx")  # hunk_relevance 0.9
    idx_07 = prompt.find("GHSA-zzzz")  # hunk_relevance 0.7
    assert idx_09 < idx_07, "Higher relevance example should appear first"


def test_pof_prompt_no_workaround_leakage():
    """Workaround must NOT appear in prompt even if it has matching CWE."""
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _db_with_bounty()
    prompt = loader.build_pof_prompt("CWE-88", "python", "code")
    assert prompt is not None
    assert "workaround" not in prompt.lower()
    assert "GHSA-yyyy" not in prompt  # The workaround example
    assert "FIXME" not in prompt


def test_pof_prompt_has_before_after_structure():
    loader = BountyLoader(db_path=":memory:")
    loader._connect = lambda: _db_with_bounty()
    prompt = loader.build_pof_prompt("CWE-88", "python", "exec(user_input)")
    assert prompt is not None
    assert "VULNERABLE" in prompt or "BEFORE" in prompt
    assert "FIXED" in prompt or "AFTER" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
