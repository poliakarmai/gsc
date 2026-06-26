"""
GS003 — Debug / diagnostic code left in production.

Detects print(), console.log, dump(), and other debug statements.
Inspired by CVE Lite OA005-nested-ineffective pattern.
"""

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS003"
ECHELON = 1

# Per-language patterns
_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "python": [
        (r'^\s*print\s*\(', "Python print() — debug leftover"),
        (r'^\s*pprint\s*\(', "Python pprint() — debug leftover"),
        (r'^\s*import\s+pdb\b', "Python debugger import (pdb)"),
        (r'^\s*breakpoint\s*\(\s*\)', "Python breakpoint()"),
        (r'^\s*import\s+ipdb\b', "Python ipdb import"),
    ],
    "javascript": [
        (r'console\.(?:log|debug|trace|dir)\s*\(', "JS console.log / debug"),
        (r'debugger\s*;?', "JS debugger statement"),
    ],
    "go": [
        (r'fmt\.(?:Println|Printf|Print)\s*\(', "Go fmt.Println / Printf — debug leftover"),
    ],
    "rust": [
        (r'dbg!\s*\(', "Rust dbg!() — debug leftover"),
        (r'println!\s*\(', "Rust println! — debug leftover"),
    ],
}

# Extensions mapping for languages
_LANG_EXTS = {
    "python": (".py", ".pyx", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "go": (".go",),
    "rust": (".rs",),
}


def _is_test_file(filepath: Path, ctx: AuditContext) -> bool:
    """Delegate to AuditContext's file classification."""
    return ctx.is_test_file(filepath)


def detect(ctx: AuditContext) -> list[Finding]:
    """Find debug/diagnostic statements in production code."""
    if "GS003" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for lang, patterns in _PATTERNS.items():
        exts = _LANG_EXTS.get(lang, ())
        for fp in ctx.get_files(extensions=exts):
            if _is_test_file(fp, ctx):
                continue
            content = ctx.read_file(fp)
            for pattern, label in patterns:
                for m in re.finditer(pattern, content, re.MULTILINE):
                    line_no = content[:m.start()].count("\n") + 1
                    # Skip if line has gsc:ignore
                    line_text = content.split("\n")[line_no - 1].strip()
                    if "gsc:ignore" in line_text:
                        continue
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="LOW",
                        title=label,
                        file_path=str(fp),
                        line_number=line_no,
                        detail=f"Line {line_no}: {line_text[:80]}",
                        fix_suggestion=(
                            "Replace with proper logging (logging.debug / logger.debug / slog). "
                            "Or add `# gsc:ignore` if intentional."
                        ),
                        references=[
                            "https://docs.python.org/3/howto/logging.html",
                        ],
                    ))

    return findings


description = "Debug / diagnostic statements left in production code"
