#!/usr/bin/env python3
"""
GSC Framework-Aware Filter — reduce false positives by understanding imports.

Example: `pickle.loads()` is flagged as CRITICAL, but if the file imports `torch`,
it's likely ML model serialization — safe context, downgrade to MEDIUM or skip.

Whitelist: pattern → {safe_imports: [list of modules that make this pattern acceptable]}
"""
import ast, os
from pathlib import Path

# Pattern → safe import contexts
FRAMEWORK_WHITELIST = {
    "pickle.load() — unsafe deserialization": {
        "safe_imports": ["torch", "tensorflow", "keras", "sklearn", "joblib",
                        "xgboost", "lightgbm", "catboost", "transformers", "diffusers"],
        "action": "downgrade",  # downgrade CRITICAL→LOW, not skip entirely
        "reason": "ML model persistence — acceptable in ML context"
    },
    "eval() usage": {
        "safe_imports": ["ast", "json", "literal_eval"],
        "action": "downgrade",
        "reason": "AST evaluation or JSON parsing context"
    },
    "Hardcoded encryption key": {
        "safe_imports": ["hashlib", "hmac", "base64", "secrets", "os"],
        "action": "skip",  # Skip entirely — key generation utilities
        "reason": "Key derivation/generation code — likely not a hardcoded secret"
    },
    "Bare except:": {
        "safe_imports": ["logging", "traceback", "sys"],
        "action": "downgrade",  # CRITICAL→MEDIUM
        "reason": "Logging/tracing context — bare except may be intentional"
    },
    "print() instead of logging": {
        "safe_imports": ["sys", "argparse", "click", "typer", "fire"],
        "action": "skip",
        "reason": "CLI tools intentionally use print()"
    },
    "f-string in query (SQL injection)": {
        "safe_imports": ["sqlalchemy", "peewee", "tortoise", "pony", "prisma"],
        "action": "downgrade",
        "reason": "ORM-wrapped queries — ORM may handle parameterization internally"
    },
}

# File extension patterns that should be skipped entirely
SKIP_FILE_PATTERNS = [
    "test_*.py", "*_test.py", "conftest.py", "__init__.py",
    "setup.py", "migrations/*.py", "*.md", "*.rst", "*.txt",
    "docs_src/**", "docs/**", "tests/**", "examples/**",
    ".github/**", "node_modules/**", "vendor/**"
]

# Categories that are always skipped in framework context
FRAMEWORK_SAFE_DIRS = {"vendor", "node_modules", ".venv", "venv", "__pycache__",
                        ".git", "dist", "build", "eggs", "*.egg-info"}


def get_imports(file_path: str) -> set:
    """Extract all imported modules from a Python file using AST."""
    try:
        tree = ast.parse(Path(file_path).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        return imports
    except Exception:
        return set()


def should_skip_file(file_path: str) -> bool:
    """Check if file should be skipped: tests, docs, examples, etc."""
    fname = os.path.basename(file_path)
    # Check by glob pattern
    for pattern in SKIP_FILE_PATTERNS:
        try:
            if Path(file_path).match(pattern):
                return True
        except Exception:
            pass
    # Check by substring (catch docs_src/, docs/, tests/ anywhere in path)
    for skip_dir in ["docs_src/", "docs/", "tests/", "examples/", "node_modules/", "vendor/", ".github/"]:
        if skip_dir in file_path:
            return True
    return False


def framework_filter(finding: dict) -> dict | None:
    """
    Apply framework-aware filtering to a finding.
    Returns None if finding should be skipped, or modified finding.
    """
    file_path = finding.get("file_path", "")
    title = finding.get("title", "")

    # Skip test files, docs, etc.
    if should_skip_file(file_path):
        return None

    # Check framework whitelist
    for pattern_key, rule in FRAMEWORK_WHITELIST.items():
        if pattern_key.lower() not in title.lower():
            continue

        if not file_path.endswith(".py"):
            continue

        imports = get_imports(file_path)
        if not imports:
            continue

        for safe_import in rule["safe_imports"]:
            if safe_import in imports:
                if rule["action"] == "skip":
                    return None  # Skip entirely
                elif rule["action"] == "downgrade":
                    finding = dict(finding)  # Don't mutate original
                    if finding.get("category") in ("CRITICAL", "HIGH"):
                        finding["category"] = "LOW"
                    finding["detail"] = (finding.get("detail", "") +
                        f" [framework: {rule['reason']} — detected {safe_import}]")
                    return finding
                break

    return finding


def filter_findings(findings: list[dict]) -> list[dict]:
    """Apply framework filter to all findings. Returns filtered list."""
    filtered = []
    skipped = 0
    downgraded = 0

    for f in findings:
        result = framework_filter(f)
        if result is None:
            skipped += 1
        else:
            if result.get("category") != f.get("category"):
                downgraded += 1
            filtered.append(result)

    if skipped or downgraded:
        import sys as _sys
        if "--ci" not in _sys.argv and "--json" not in _sys.argv and "--sarif" not in _sys.argv:
            print(f"  🔍 Framework filter: {skipped} skipped, {downgraded} downgraded")

    return filtered


if __name__ == "__main__":
    # Test: show framework filter in action
    test_findings = [
        {"title": "pickle.load() — unsafe deserialization", "category": "CRITICAL",
         "file_path": "lstm_regime.py", "line_number": 617, "detail": ""},
        {"title": "Hardcoded encryption key", "category": "CRITICAL",
         "file_path": "rpc.py", "line_number": 180, "detail": ""},
        {"title": "Bare except:", "category": "MEDIUM",
         "file_path": "main_async.py", "line_number": 50, "detail": ""},
        {"title": "eval() usage", "category": "HIGH",
         "file_path": "test_smoke.py", "line_number": 10, "detail": ""},
    ]
    for f in test_findings:
        result = framework_filter(f)
        status = "✅ kept" if result else "❌ skipped"
        cat = f"→ {result['category']}" if result else ""
        print(f"  {status} {f['title'][:50]} {cat}")
