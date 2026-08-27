#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS046 — C/C++ Vulnerability Detector.

Detects classic memory-safety / unsafe-function / format-string / command-injection
patterns in C and C++ source files. Closes the managed-language coverage gap
(GS035-042 cover Python/JS/Go/Java/Rust/PHP/Ruby/Solidity, but not C/C++).

Surface-flag: any unsafe function matched produces a finding. The actual bounds
check (e.g. "does the destination buffer actually overflow?") requires manual
review — the detector reports the unsafe site, not the verdict.

CWE coverage:
  - CWE-119 (Improper Restriction of Operations within Bounds of a Memory Buffer)
  - CWE-120 (Buffer Copy without Checking Size of Input — strcpy/strcat/sprintf)
  - CWE-134 (Use of Externally-Controlled Format String)
  - CWE-242 (Use of Inherently Dangerous Function — gets)
  - CWE-78  (OS Command Injection — system/popen)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

CPP_RULES: list[tuple[str, str, str, float]] = [
    # --- CWE-120: bounded-buffer overflow (str* family) ---
    ("strcpy_buffer_overflow",
     r'(?<![A-Za-z0-9_])strcpy\s*\(',
     "CRITICAL", 0.85),
    ("strcat_buffer_overflow",
     r'(?<![A-Za-z0-9_])strcat\s*\(',
     "HIGH", 0.80),

    # --- CWE-242: inherently dangerous (always unsafe) ---
    ("gets_unsafe",
     r'\bgets\s*\(',
     "CRITICAL", 0.95),

    # --- CWE-120: printf family without bounds ---
    ("sprintf_overflow",
     r'(?<![A-Za-z0-9_])sprintf\s*\(',
     "HIGH", 0.80),
    ("vsprintf_overflow",
     r'(?<![A-Za-z0-9_])vsprintf\s*\(',
     "HIGH", 0.80),

    # --- CWE-120: scanf with %s and no width specifier (allow %49s etc.) ---
    # The negative lookbehind forbids an ASCII digit directly before %s, so
    # bounded variants like "%49s" / "%255s" do NOT match. Bare "%s" does match.
    ("scanf_no_bounds",
     r'(?<![A-Za-z0-9_])scanf\s*\([^)]*%(?!\d+)s',
     "HIGH", 0.75),

    # --- CWE-134: format string attack ---
    # printf(IDENT) with no string literal first arg lets attacker-controlled
    # data become the format spec. Negative lookbehind forbids f/sn/_/my-
    # prefixes so fprintf / snprintf / user-defined wrappers do not match.
    # Negative lookahead forbids a leading " on the first arg (a literal
    # format string is safe).
    ("printf_format_string",
     r'(?<![A-Za-z0-9_])printf\s*\(\s*(?!")',
     "HIGH", 0.60),

    # --- CWE-78: command injection ---
    ("system_command_injection",
     r'(?<![A-Za-z0-9_])system\s*\(',
     "CRITICAL", 0.85),
    ("popen_command_injection",
     r'(?<![A-Za-z0-9_])popen\s*\(',
     "HIGH", 0.75),
]


# C/C++ source extensions recognised by this detector. Mirrors how gs038
# gates on `.go`: only the target language is scanned, so a `.py` file in the
# same tree is left to GS037.
CPP_EXTS: frozenset[str] = frozenset({
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
})


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|third_party|extern|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
    r'(?:/|$)', re.IGNORECASE)


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key, "rule_id": rule_id, "title": title,
        "severity": severity, "confidence": confidence,
        "file_path": file_path, "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS046", "pattern_id": rule_id.replace("GS046-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


def _is_cpp_path(file_path: str) -> bool:
    """True iff ``file_path`` is a C/C++ source file this detector owns.

    Excludes GoogleTest-style ``*_test.c`` / ``*_test.cpp`` fixtures so
    that test inputs do not flood the report. Mirrors gs038's handling
    of ``*_test.go``.
    """
    ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
    if ext not in CPP_EXTS:
        return False
    name = file_path.rsplit('/', 1)[-1]
    if name.endswith('_test.c') or name.endswith('_test.cpp'):
        return False
    return True


class GS046CppDetector:
    rule_id = "GS046"
    name = "C/C++ Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        if not _is_cpp_path(file_path):
            return findings
        for pattern_id, regex, severity, base_conf in CPP_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS046-{pattern_id}", severity,
                    f"C/C++ security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
        return findings


RULE_ID = "GS046"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS046: C/C++ Vulnerability Detection — strcpy/strcat/gets/sprintf overflow, format-string, system/popen injection"


def detect(ctx) -> list[dict]:
    det = GS046CppDetector()
    findings: list[dict] = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        if not _is_cpp_path(fp.name):
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings
