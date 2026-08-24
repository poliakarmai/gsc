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

# Static-literal command passed to shell=True / os.popen (no interpolation,
# concat, format, or $-var) is bad practice, not user-controlled injection.
_STATIC_SHELL = re.compile(
    r'(?:subprocess\.\w+\(\s*["\']|os\.popen\s*\(\s*["\'])'
    r'(?![\s\S]*(\$\{|["\']\s*\+|\{[a-zA-Z_]\w*\}|\.format\s*\(|%\s*\(|%[sd]))'
)

# Taint sources for command injection / eval / exec context analysis.
# Without untrusted input reaching the sink, os.system()/eval()/exec() on
# internal data is code smell, not a confirmed injection → downgrade to MEDIUM.
_TAINT_SOURCE_RE = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE|headers)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data|params)\s*\()',
    re.IGNORECASE,
)


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
                severity = "HIGH"
                # shell=True / os.popen with a static literal command is bad
                # practice, not user-controlled command injection → downgrade.
                if ("shell" in pattern or "popen" in pattern) and _STATIC_SHELL.search(line_text):
                    severity = "MEDIUM"
                # "$variable" in a string arg is shell-env expansion, not user
                # input → MEDIUM.
                if r"\$" in pattern:
                    severity = "MEDIUM"
                # os.system with f-string/format but no taint source in the
                # surrounding context → MEDIUM (internal command wrapper, not a
                # confirmed injection). eval/exec stay HIGH: bare code-exec sinks
                # are higher risk and guarded as HIGH "potential" by test_corpus.
                if "system" in pattern:
                    ctx_start = max(0, m.start() - 800)
                    ctx_end = min(len(content), m.end() + 200)
                    if not _TAINT_SOURCE_RE.search(content[ctx_start:ctx_end]):
                        severity = "MEDIUM"
                # shell=True / os.popen with a variable command and no taint in
                # the surrounding context → MEDIUM (internal command wrapper).
                if "shell" in pattern or "popen" in pattern:
                    ctx_start = max(0, m.start() - 800)
                    ctx_end = min(len(content), m.end() + 200)
                    if not _TAINT_SOURCE_RE.search(content[ctx_start:ctx_end]):
                        severity = "MEDIUM"
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity=severity,
                    title=title,
                    file_path=str(fp),
                    line=line_no,
                    detail=f"Line {line_no}: {line_text[:100]}",
                    fix_suggestion=fix,
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                        "https://docs.python.org/3/library/subprocess.html#security-considerations",
                    ],
                ))

    return findings


description = "Dangerous subprocess/shell usage (command injection, shell=True, os.system, eval)"
