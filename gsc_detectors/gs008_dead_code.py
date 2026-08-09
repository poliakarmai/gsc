# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""
GS008 — Dead code: declared but never used.

Detects:
- Module-level UPPER_CASE constants referenced only once (declaration)
- Feature flags assigned but never read (VAR = os.environ.get('FLAG') → VAR unused)

Inspired by ATR_TP_LEVELS bug (2026-06-28): constants declared, never used,
causing ATR-based TP to never fire.
"""

import ast
import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS008"
ECHELON = 1

# Files to skip for dead-code analysis (test files, __init__ with exports)
_SKIP_PATTERNS = [
    "test_", "_test.", "conftest.py",
    "__init__.py",  # __init__ constants are exports, not dead code
]

# Minimum constant name length to consider
_MIN_CONSTANT_LEN = 4

# Known patterns that are never dead code
_ALWAYS_USED = {
    "__all__", "__version__", "__author__", "__doc__", "__file__",
}


def _extract_constants(source: str) -> list[tuple[str, str, int]]:
    """Extract module-level UPPER_CASE assignments with line numbers."""
    constants = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return constants

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if not name.isupper() or len(name) < _MIN_CONSTANT_LEN:
                continue
            if name in _ALWAYS_USED or name.startswith("__"):
                continue
            line = node.lineno
            line_text = source.split("\n")[line - 1].strip() if source else ""
            constants.append((name, line_text[:120], line))
    return constants


def _count_occurrences(name: str, source: str) -> int:
    """Count whole-word occurrences of name in source."""
    return len(re.findall(r"\b" + re.escape(name) + r"\b", source))


def _is_library_module(filepath: Path, content: str) -> tuple[bool, bool]:
    """Check if file is a library module (not application code).
    Returns (is_library, is_main_app).
    Library modules export constants for consumers — dead constant
    detection is noisy here. Feature flags still checked."""
    is_library = (filepath.parent / "__init__.py").exists()
    is_main = bool(re.search(
        r'if\s+__name__\s*==\s*["\']__main__["\']\s*:', content
    ))
    return is_library, is_main


def detect(ctx: AuditContext) -> list[Finding]:
    """Find dead code in Python source files."""
    if "GS008" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []

    for fp in ctx.get_files(extensions=(".py",)):
        # Skip test/init files
        fname = fp.name
        if any(fname.startswith(p) or p in fname for p in _SKIP_PATTERNS):
            continue
        if ctx.is_test_file(fp) or ctx.is_non_code_file(fp):
            continue

        content = ctx.read_file(fp)
        if not content:
            continue

        # Library modules: skip constant detection (exports = legitimate),
        # but still check feature flags (they're application concerns)
        is_library, is_main = _is_library_module(fp, content)

        # ── Check 1: Dead UPPER_CASE constants ──
        # Skip for library modules without a main guard — exported
        # constants are used by consumers, not within the same file.
        if not is_library or is_main:
            for name, line_text, line_no in _extract_constants(content):
                occurrences = _count_occurrences(name, content)
                if occurrences == 1:
                    if any(x in name for x in (
                        "FILE", "PATH", "DIR", "_KEY", "_SECRET",
                        "_URL", "_TOKEN", "_PASSWORD"
                    )):
                        continue

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="LOW",
                        title=f"Dead constant: {name} — declared but never read",
                        file_path=str(fp),
                        line_number=line_no,
                        detail=f"Line {line_no}: {line_text}",
                        fix_suggestion=(
                            f"Remove '{name}' or reference it in the code. "
                            f"If this is an exported constant, move it to __init__.py."
                        ),
                        references=[
                            "dead-code-audit skill",
                        ],
                    ))

        # ── Check 2: Feature flags assigned but never read ──
        for m in re.finditer(
            r"^(\w+)\s*=\s*os\.environ\.get\(['\"](\w+)['\"]",
            content, re.MULTILINE,
        ):
            var_name = m.group(1)
            flag_name = m.group(2)
            if flag_name.startswith("BYBIT_") or flag_name.startswith("HERMES_"):
                count = _count_occurrences(var_name, content)
                if count == 1:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="MEDIUM",
                        title=f"Dead feature flag: {var_name} = os.environ.get('{flag_name}') — never read",
                        file_path=str(fp),
                        line_number=content[:m.start()].count("\n") + 1,
                        detail=f"Feature flag '{flag_name}' assigned but never used",
                        fix_suggestion=(
                            f"Either use {var_name} in a condition, or remove the flag."
                        ),
                        references=[
                            "dead-code-audit skill",
                            "ATR_TP_ENABLED precedent (auto_tp.py)",
                        ],
                    ))

    return findings


description = "Dead code: constants and feature flags declared but never used"
