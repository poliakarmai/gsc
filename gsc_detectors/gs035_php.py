#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS035 — PHP Vulnerability Detector.

Detects common PHP security issues:
  - SQL injection (unsanitized $_GET/$_POST in queries)
  - XSS (echo/print without htmlspecialchars)
  - File inclusion (include/require with user input)
  - Command injection (exec/system/passthru with user input)
  - Deserialization (unserialize with user input)
  - LFI/RFI (include with $_GET in path)
  - Hardcoded credentials in PHP config
  - eval() with dynamic input
  - Disabled error reporting in production
  - Weak password hashing (MD5/SHA1 for passwords)

Patterns derived from OWASP Top 10 + PHP Security Cheat Sheet.
"""

from __future__ import annotations

import re
import hashlib
from typing import Any


# ── PATTERNS ───────────────────────────────────────────────────────────

PHP_RULES: list[tuple[str, str, str, float]] = [
    # --- SQL Injection ---
    ("sql_injection_get",
     r'(?i)(?:mysql_query|mysqli_query|pg_query|sqlite_query|odbc_exec|'
     r'PDO::query|->query|->exec)\s*\(\s*[^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
     "CRITICAL", 0.95),
    ("sql_injection_concat",
     r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\.\s*\$(?:_GET|_POST|_REQUEST)',
     "CRITICAL", 0.90),
    ("sql_injection_like",
     r'(?i)(?:mysql_query|mysqli_query|->query)\s*\(\s*[\'"`].*\$[a-zA-Z_]+.*[\'"`]\s*\)',
     "CRITICAL", 0.85),

    # --- XSS ---
    ("xss_echo",
     r'(?i)echo\s+\$(?:_GET|_POST|_REQUEST|_SERVER\[)',
     "HIGH", 0.80),
    ("xss_print",
     r'(?i)print\s+\$(?:_GET|_POST|_REQUEST)\b(?!.*htmlspecialchars)',
     "HIGH", 0.80),
    ("xss_no_escape",
     r'(?i)<\?(?:php|=)\s*\$(?:_GET|_POST|_REQUEST)\s*\?>',
     "HIGH", 0.85),

    # --- File Inclusion ---
    ("lfi_include",
     r'(?i)(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST)',
     "CRITICAL", 0.95),
    ("lfi_include_file",
     r'(?i)(?:include|require)\s*\(?\s*[\'"`].*\.\s*\$',
     "HIGH", 0.80),

    # --- Command Injection ---
    ("command_injection_exec",
     r'(?i)(?:exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(.*\$_(?:GET|POST|REQUEST)',
     "CRITICAL", 0.95),
    ("command_injection_backtick",
     r'`.*\$_(?:GET|POST|REQUEST)[^`]*`',
     "CRITICAL", 0.90),

    # --- Deserialization ---
    ("unserialize_user_input",
     r'(?i)unserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
     "CRITICAL", 0.95),

    # --- eval() ---
    ("eval_user_input",
     r'(?i)eval\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)',
     "CRITICAL", 0.98),
    ("eval_dynamic",
     r'(?i)eval\s*\(\s*[\'"`].*\.[\'"`]?\s*\.\s*\$',
     "HIGH", 0.85),

    # --- Hardcoded Credentials ---
    ("hardcoded_password",
     r'(?i)\$(?:db_pass(?:word)?|passwd|password|secret|api_key|token)\s*=\s*[\'"][^\'"]{4,}[\'"]',
     "CRITICAL", 0.90),
    ("hardcoded_dsn",
     r'(?i)(?:mysql:|pgsql:|mongodb:).{0,30}://[^:]+:[^@]+@',
     "HIGH", 0.85),

    # --- Session/Cookie Weaknesses ---
    ("session_fixation",
     r'(?i)session_start\s*\(\s*\)\s*;(?!.*session_regenerate_id)',
     "MEDIUM", 0.60),
    ("cookie_no_httponly",
     r'(?i)setcookie\s*\([^)]*(?!.*httponly.*true)',
     "LOW", 0.50),

    # --- Error Reporting ---
    ("error_reporting_prod",
     r'(?i)(?:error_reporting\s*\(\s*(?:E_ALL|0\b)\)|'
     r'ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?(?:On|1|true)[\'"]?\s*\))',
     "MEDIUM", 0.60),

    # --- Weak Crypto ---
    ("weak_hash_password",
     r'(?i)(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd|passwd)',
     "HIGH", 0.80),
    ("weak_hash",
     r'(?i)(?:md5|sha1)\s*\(\s*\$',
     "LOW", 0.30),

    # --- Open Redirect ---
    ("open_redirect",
     r'(?i)header\s*\(\s*[\'"]Location:\s*[\'"]\s*\.\s*\$(?:_GET|_POST|_REQUEST)',
     "HIGH", 0.80),

    # --- SSRF ---
    ("ssrf_curl",
     r'(?i)(?:curl_setopt|curl_exec)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
     "HIGH", 0.75),
    ("ssrf_file_get_contents",
     r'(?i)file_get_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
     "HIGH", 0.80),

    # --- Disabled Functions Bypass ---
    ("disable_functions_bypass",
     r'(?i)(?:dl\s*\(|ini_restore\s*\(|putenv\s*\(\s*[\'"]LD_PRELOAD)',
     "MEDIUM", 0.55),
]


# ── EXCLUSIONS ────────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build|'
    r'wp-content/(?:plugins|themes)/[^/]+/(?:tests?|vendor))'
    r'(?:/|$)', re.IGNORECASE)


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS035", "pattern_id": rule_id.replace("GS035-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS035PHPDetector:
    rule_id = "GS035"
    name = "PHP Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content:
            return findings

        # Only scan PHP files
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext not in ('.php', '.phtml', '.php3', '.php4', '.php5', '.pht', '.phps', '.inc'):
            return findings

        if EXCLUDE_PATH_RE.search(file_path):
            return findings

        pattern_hits = 0

        for pattern_id, regex, severity, base_conf in PHP_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = _snippet(content, line_no)
                findings.append(_finding(
                    f"GS035-{pattern_id}", severity,
                    f"PHP security: {pattern_id}",
                    file_path, line_no, snippet, base_conf,
                ))
                pattern_hits += 1

        if pattern_hits >= 5:
            findings.append(_finding(
                "GS035-high_risk_file", "CRITICAL",
                f"PHP file has {pattern_hits} security issues — critical review required",
                file_path, 1, f"({pattern_hits} patterns matched)", 0.95,
            ))

        return findings


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS035"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS035: PHP Vulnerability Detection — SQLi, XSS, LFI, command injection, deserialization"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS035PHPDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext not in ('.php', '.phtml', '.php3', '.php4', '.php5', '.pht', '.phps', '.inc'):
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
