#!/usr/bin/env python3
"""GSC Corpus Tests — v2."""
import subprocess, sys, os, json, tempfile, shutil
from pathlib import Path

GSC = os.path.expanduser("~/gsc/gsc.py")
PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition: PASS += 1; print(f"  ✅ {name}")
    else: FAIL += 1; print(f"  ❌ {name}" + (f" — {detail}" if detail else ""))

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
        r = subprocess.run(
            [sys.executable, GSC, "scan", d, "--ci", "--json"],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(r.stdout) if r.stdout.strip() else []
    except Exception as e:
        print(f"  scan_file error: {e}")
        return []
    finally:
        shutil.rmtree(d, ignore_errors=True)

def has_finding(findings, keyword, category=None):
    return any(keyword.lower() in f.get("title","").lower() and 
               (category is None or f.get("category") == category) for f in findings)

print("=" * 50)
print("GSC Corpus Tests")
print("=" * 50)

# 1. SQL injection via f-string
print("\n── 1. SQL Injection ──")
findings = scan_file('query = f"SELECT * FROM users WHERE id={uid}"\n')
check("SQL injection detected", has_finding(findings, "sql", "CRITICAL"), f"{len(findings)} findings")

# 2. Hardcoded secret
print("\n── 2. Hardcoded Secret ──")
findings = scan_file('password = "my-super-secret"\nAPI_TOKEN = "ghp_abcdef12345678"\n')
check("Hardcoded secret detected", has_finding(findings, "hardcoded", "HIGH"), f"{len(findings)} findings")

# 3. pickle.loads
print("\n── 3. Unsafe pickle ──")
findings = scan_file("import pickle\ndef load(x): return pickle.loads(x)\n")
check("pickle.loads detected", has_finding(findings, "pickle", "CRITICAL"))

# 4. Bare except
print("\n── 4. Bare except ──")
findings = scan_file("try:\n    risky()\nexcept:\n    pass\n")
check("Bare except detected", has_finding(findings, "bare except", "MEDIUM"))

# 5. eval()
print("\n── 5. eval() ──")
findings = scan_file("def exec(u): return eval(u)\n")
check("eval() detected", has_finding(findings, "eval", "HIGH"))

# 6. World-readable .env
print("\n── 6. World-readable .env ──")
findings = scan_file("SECRET=abc123\ndb://localhost\n", ".env", "644")
check("World-readable .env detected", has_finding(findings, "world-readable", "HIGH"))

# 7. Clean code
print("\n── 7. Clean code ──")
findings = scan_file("def add(a: int, b: int) -> int:\n    return a + b\n")
check("No CRITICAL on clean", not has_finding(findings, "", "CRITICAL"))

# 8. assert in production
print("\n── 8. assert in production ──")
findings = scan_file("def validate(x):\n    assert x > 0\n    return x\n")
check("assert detected", has_finding(findings, "assert", "MEDIUM"))

print(f"\n{'='*50}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'='*50}")
sys.exit(0 if FAIL == 0 else 1)
