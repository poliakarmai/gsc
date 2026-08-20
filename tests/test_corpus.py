#!/usr/bin/env python3
"""GSC Corpus Tests — v2.1 (pytest-compatible)."""
import subprocess, sys, os, json, tempfile, shutil
from pathlib import Path

# F-01 (audit): resolve gsc.py relative to this file, not a hardcoded ~/gsc home
# path — a fresh checkout elsewhere previously ran a non-existent path and returned
# empty findings (7 false failures).
GSC = str(Path(__file__).resolve().parents[1] / "gsc.py")
PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  ✅ {name}")
    else:
        FAIL += 1; print(f"  ❌ {name}" + (f" — {detail}" if detail else ""))

def scan_file(code: str, filename: str = "test.py", chmod: str = None) -> list[dict]:
    d = tempfile.mkdtemp()
    try:
        fpath = Path(d) / filename
        fpath.write_text(code)
        if chmod:
            fpath.chmod(int(chmod, 8))
        subprocess.run(["git", "-C", d, "init", "-q"], capture_output=True)
        subprocess.run(["git", "-C", d, "add", "-A"], capture_output=True)
        subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], capture_output=True)
        # GSC_DB_PATH наследуется из окружения (см. conftest._isolate_gsc_db),
        # поэтому в чистой среде scan идёт self-contained (load_patterns fallback).
        r = subprocess.run(
            [sys.executable, GSC, "scan", d, "--ci", "--json"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            raise RuntimeError(f"gsc scan exited {r.returncode}:\n{r.stderr}")
        if not r.stdout.strip():
            raise RuntimeError(f"gsc scan returned empty stdout.\nstderr: {r.stderr}")
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)

def has_finding(findings, keyword, category=None):
    return any(keyword.lower() in f.get("title","").lower() and
               (category is None or f.get("category") == category) for f in findings)


# ── pytest-compatible test functions ──────────────────────────────────────

def test_sql_injection():
    findings = scan_file('query = f"SELECT * FROM users WHERE id={uid}"\n')
    assert has_finding(findings, "sql", "CRITICAL"), f"SQL injection not detected ({len(findings)} findings)"

def test_hardcoded_secret():
    findings = scan_file('password = "my-super-secret-password"\nAPI_TOKEN="ghp_abc...123"\n')
    assert len(findings) > 0, "Hardcoded secret not detected"

def test_unsafe_pickle():
    # pickle without a taint source → HIGH (potential, not confirmed RCE)
    findings = scan_file("import pickle\ndef load(x): return pickle.loads(x)\n")
    assert has_finding(findings, "pickle", "HIGH"), "pickle.loads not detected"

def test_pickle_rce_user_input():
    # pickle.loads(user_input) → CRITICAL (confirmed RCE sink)
    findings = scan_file("from flask import request\nimport pickle\npickle.loads(request.data)\n")
    assert has_finding(findings, "pickle", "CRITICAL"), "pickle.loads(user_input) not CRITICAL"

def test_bare_except():
    findings = scan_file("try:\n    risky()\nexcept:\n    pass\n")
    assert has_finding(findings, "bare except", "MEDIUM"), "Bare except not detected"

def test_eval():
    findings = scan_file("def exec(u): return eval(u)\n")
    assert has_finding(findings, "eval", "HIGH"), "eval() not detected"

def test_world_readable_env():
    findings = scan_file("SECRET=abc123\ndb://localhost\n", ".env", "644")
    assert has_finding(findings, "world-readable", "HIGH"), "World-readable .env not detected"

def test_clean_code():
    findings = scan_file("def add(a: int, b: int) -> int:\n    return a + b\n")
    assert not has_finding(findings, "", "CRITICAL"), f"False positive: {len(findings)} findings on clean code"

def test_assert_not_flagged():
    # "assert in production" is a code-quality pattern, deliberately removed from the
    # security scan (DETECTOR_BRIEF_GS000_LEGACY.md, Lead A) — assert must NOT fire.
    findings = scan_file("def validate(x):\n    assert x > 0\n    return x\n")
    assert not has_finding(findings, "assert", "MEDIUM"), "assert should not be flagged (quality, not security)"


# ── CLI mode (backward compatible) ────────────────────────────────────────

def run_corpus():
    global PASS, FAIL
    print("=" * 50)
    print("GSC Corpus Tests")
    print("=" * 50)

    tests = [
        ("SQL injection", lambda: has_finding(scan_file('query = f"SELECT * FROM users WHERE id={uid}"\n'), "sql", "CRITICAL")),
        ("Hardcoded secret", lambda: len(scan_file('password = "my-super-secret-password"\nAPI_TOKEN="ghp_abc...123"\n')) > 0),
        ("Unsafe pickle", lambda: has_finding(scan_file("import pickle\ndef load(x): return pickle.loads(x)\n"), "pickle", "HIGH")),
        ("Bare except", lambda: has_finding(scan_file("try:\n    risky()\nexcept:\n    pass\n"), "bare except", "MEDIUM")),
        ("eval()", lambda: has_finding(scan_file("def exec(u): return eval(u)\n"), "eval", "HIGH")),
        ("World-readable .env", lambda: has_finding(scan_file("SECRET=abc123\ndb://localhost\n", ".env", "644"), "world-readable", "HIGH")),
        ("Clean code", lambda: not has_finding(scan_file("def add(a: int, b: int) -> int:\n    return a + b\n"), "", "CRITICAL")),
        ("assert in prod", lambda: has_finding(scan_file("def validate(x):\n    assert x > 0\n    return x\n"), "assert", "MEDIUM")),
    ]

    for name, fn in tests:
        print(f"\n── {name} ──")
        try:
            check(name, fn(), "")
        except Exception as e:
            check(name, False, str(e))

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    print(f"{'='*50}")
    return FAIL == 0


if __name__ == "__main__":
    success = run_corpus()
    sys.exit(0 if success else 1)
