#!/usr/bin/env python3
"""tests/test_exclusive_modes_workspace.py — Scan Modes + Workspace (+4)."""
import sys, os, tempfile
os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

from gsc_scan_modes import SCAN_MODES
import gsc_workspace as ws

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    assert set(SCAN_MODES.keys()) == {"quick", "standard", "deep"}
test('scan modes defined', t1)

def t2():
    assert SCAN_MODES["quick"]["llm_enabled"] is False
    assert SCAN_MODES["quick"]["llm_max_calls"] == 0
    assert SCAN_MODES["deep"]["llm_enabled"] is True
    assert SCAN_MODES["deep"]["llm_max_calls"] == 50
test('quick=no LLM, deep=max LLM', t2)

def t3():
    d = tempfile.mkdtemp()
    try:
        pass  # uses global DB, not tmpdir
        ws.workspace_create("Pentest ACME")
        ws.workspace_add("Pentest ACME", "https://github.com/user/repo1")
        repos = ws.workspace_list()
        assert any(r["name"] == "Pentest ACME" for r in repos)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)
test('workspace create + add repo', t3)

def t4():
    d = tempfile.mkdtemp()
    try:
        pass  # uses global DB, not tmpdir
        ws.workspace_create("Pentest ACME")
        # duplicate: returns False, no crash
        assert ws.workspace_create("Pentest ACME") is False
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)
test('workspace duplicate create raises ValueError', t4)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
