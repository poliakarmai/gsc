# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS004 — Dangerous subprocess usage (command injection risk).

Detects:
- shell=True without input sanitization (shlex.quote)
- os.system() / os.popen() with formatted strings
- subprocess with user-controlled strings

Inspired by OWASP A03:2021 — Injection.
"""

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS004"
ECHELON = 2

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, title, fix hint)

    # Python: shell=True without shlex.quote
    (
        r'subprocess\.\w+\([^)]*shell\s*=\s*True',
        "subprocess with shell=True",
        "Use shell=False with list arguments, or wrap input with shlex.quote()",
    ),
    # Python: os.system() with formatted string
    (
        r'os\.system\s*\(\s*f["\']',
        "os.system() with f-string — command injection risk",
        "Replace with subprocess.run([...], shell=False)",
    ),
    (
        r'os\.system\s*\(\s*["\'][^"\']*%[sd]',
        "os.system() with %-formatting",
        "Replace with subprocess.run([...], shell=False)",
    ),
    (
        r'os\.system\s*\(\s*["\'][^"\']*\.format\(',
        "os.system() with .format() — command injection risk",
        "Replace with subprocess.run([...], shell=False)",
    ),
    # os.popen() — always uses shell
    (
        r'os\.popen\s*\(',
        "os.popen() — deprecated, uses shell",
        "Replace with subprocess.Popen([...], shell=False)",
    ),
    # commands.getoutput() — Python 2 legacy
    (
        r'commands\.(getoutput|getstatusoutput)\s*\(',
        "commands.getoutput() — deprecated shell wrapper",
        "Replace with subprocess.run([...], capture_output=True)",
    ),
    # subprocess with string (not list) — implicit shell on Windows
    (
        r'subprocess\.(call|run|Popen)\s*\(\s*["\'][^"\']+\$',
        "subprocess with string arg containing $variable",
        "Use list arguments to avoid shell expansion",
    ),
    # eval() on command strings
    (
        r'eval\s*\(\s*(?:input\(|.*f["\']|.*\.format\()',
        "eval() with dynamic input — code injection",
        "Never use eval() on user input. Use ast.literal_eval() or a parser.",
    ),
    # exec() on dynamic strings
    (
        r'exec\s*\(\s*(?!["\']{3})\w',
        "exec() on variable — code injection risk",
        "Avoid exec(); use explicit function calls or importlib",
    ),
]


def detect(ctx: AuditContext) -> list[Finding]:
    """Find dangerous subprocess/shell usage in source code."""
    if "GS004" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files(extensions=(".py",)):
        content = ctx.read_file(fp)
        for pattern, title, fix in _PATTERNS:
            for m in re.finditer(pattern, content, re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID,
                    category="HIGH",
                    title=title,
                    file_path=str(fp),
                    line_number=line_no,
                    detail=f"Line {line_no}: {line_text[:100]}",
                    fix_suggestion=fix,
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                        "https://docs.python.org/3/library/subprocess.html#security-considerations",
                    ],
                ))

    return findings


description = "Dangerous subprocess/shell usage (command injection, shell=True, os.system, eval)"
