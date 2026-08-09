#!/usr/bin/env python3
"""gsc doctor — диагностика окружения GSC."""
import subprocess, sys, os

def check(label, ok, detail=""):
    status = "✅" if ok else "❌"
    print(f"  {status} {label}" + (f" — {detail}" if detail else ""))

print("🩺 GSC Doctor\n")

# Python
try:
    v = sys.version.split()[0]
    ok = sys.version_info >= (3, 10)
    check(f"Python {v}", ok)
except: check("Python", False)

# ripgrep
# ripgrep — check for actual rg binary, not Python wrapper
try:
    r = subprocess.run(["rg", "--version"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        check("ripgrep", True, r.stdout.split('\n')[0] if r.stdout else "installed")
    else:
        check("ripgrep", False, "rg found but returned error")
except FileNotFoundError:
    check("ripgrep", False, "not found — install: brew install ripgrep / apt install ripgrep / cargo install ripgrep")

# Git
try:
    r = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=5)
    check("Git", r.returncode == 0, r.stdout.strip())
except: check("Git", False)

# GSC DB
db = os.path.expanduser("~/.hermes/state/gsc_audit.db")
if os.path.exists(db):
    import sqlite3
    try:
        conn = sqlite3.connect(db)
        patterns = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        runs = conn.execute("SELECT COUNT(*) FROM audit_runs").fetchone()[0]
        conn.close()
        check("GSC Database", True, f"{patterns} patterns, {findings} findings, {runs} runs")
    except Exception as e:
        check("GSC Database", False, str(e))
else:
    check("GSC Database", False, "not found — run gsc patterns --seed 200")

# Seed patterns
seed_dir = os.path.expanduser("~/gsc/patterns")
if os.path.isdir(seed_dir):
    files = [f for f in os.listdir(seed_dir) if f.endswith('.json')]
    names = [f.replace('.json','') for f in files]
    check("Seed patterns", len(files) > 0, f"{len(files)} language packs ({', '.join(names)})" if files else "no seed files")
else:
    check("Seed patterns", False, "directory not found — git clone gsc")

# Obsidian
vault = os.path.expanduser("~/obsidian-vault/audits")
check("Obsidian vault", os.path.isdir(vault), vault if os.path.isdir(vault) else "not found (optional)")

# GSC scripts
for s in ["gsc_load_patterns.py", "gsc_save_findings.py"]:
    path = os.path.expanduser(f"~/.hermes/scripts/{s}")
    check(s, os.path.exists(path))

# Permissions
for f in [db]:
    if os.path.exists(f):
        perms = oct(os.stat(f).st_mode)[-3:]
        check(f"Permissions: {os.path.basename(f)}", perms == "600", perms)

print("\n💡 Run 'gsc init' to set up a new project, 'gsc scan <project>' for first audit.")
