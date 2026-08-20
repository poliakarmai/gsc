# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS021 — CSRF / SSRF Detection.

Real-World Bug Hunting + Web Hacking 101:
- CSRF: missing CSRF tokens, same-site cookies, form without token
- SSRF: URL params accepting internal hosts, AWS metadata, localhost bypass

ECHELON: 2 (needs context, broader patterns)
"""

from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Detector, Finding

RULE_ID = "GS021"
ECHELON = 2
NOISE_TIER = "normal"
description = "CSRF / SSRF — missing tokens, internal URL fetches (Bug Hunting)"

# ── CSRF Patterns ─────────────────────────────────────────────────────────────

CSRF_PATTERNS: list[tuple[str, str, str]] = [
    # Missing CSRF protection
    (r'@csrf_exempt', "CSRF: Django @csrf_exempt decorator — disabled CSRF protection", "HIGH"),
    (r'skip_before_action\s*:verify_authenticity_token', "CSRF: Rails skip_before_action for CSRF token", "HIGH"),
    (r'protect_from_forgery\s+with:\s+:null_session', "CSRF: Rails null_session forgery protection (weak)", "MEDIUM"),
    (r'csrf_protect\s*=\s*False', "CSRF: Flask-WTF CSRF protection disabled", "HIGH"),
    (r'WTF_CSRF_ENABLED\s*=\s*False', "CSRF: Flask CSRF disabled globally", "HIGH"),
    (r'csrf\.exempt', "CSRF: Django REST framework CSRF exempt", "HIGH"),
    # Removed: "@app.route(...methods=['POST'])" matches any POST route, not a
    # CSRF signal — JWT/JSON APIs have no CSRF surface. Real CSRF TPs are caught
    # by @csrf_exempt / csrf_protect=False / skip_before_action above.
    # Cookie flags
    (r'SESSION_COOKIE_HTTPONLY\s*=\s*False', "CSRF: Django session cookie HttpOnly=False", "MEDIUM"),
    (r'SESSION_COOKIE_SAMESITE\s*=\s*[\"\']None[\"\']', "CSRF: SameSite=None without Secure flag", "HIGH"),
    (r'httponly\s*=\s*false', "CSRF: cookie httpOnly=false — vulnerable to XSS→CSRF", "MEDIUM"),
    (r'samesite\s*=\s*[\"\']none[\"\']', "CSRF: SameSite=None — CSRF protection disabled", "HIGH"),
]

# ── SSRF Patterns ─────────────────────────────────────────────────────────────

SSRF_PATTERNS: list[tuple[str, str, str]] = [
    # URL fetching with user input
    (r'(?:urllib|requests|http\.client|axios|fetch|got|node-fetch)\.(?:get|post|request|fetch)\s*\(.*(?:request\.|params\[|req\.(?:query|body|params)|user_input|input\()',
     "SSRF: HTTP request with user-controlled URL", "CRITICAL"),
    # Indirect taint — request to a variable (likely a user-supplied URL)
    (r'(?:requests|urllib\.request|httpx)\.(?:get|post|head|put|request)\s*\(\s*[a-zA-Z_]\w*\s*\)',
     "SSRF review: HTTP request to a variable — taint not established", "INFO"),
    (r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)', "SSRF: PHP file_get_contents with user input", "CRITICAL"),
    (r'curl_exec\s*\(.*\$_(?:GET|POST|REQUEST)', "SSRF: PHP curl_exec with user-controlled URL", "CRITICAL"),
    # Internal host references
    (r'169\.254\.169\.254', "SSRF: AWS metadata endpoint in code", "CRITICAL"),
    (r'metadata\.google\.internal', "SSRF: GCP metadata endpoint in code", "CRITICAL"),
    (r'/var/run/docker\.sock', "SSRF/LFI: Docker socket reference in code", "HIGH"),
    # URL construction with user input
    (r'url\s*=\s*[\"\']https?://.*\{\{', "SSRF: URL template with variable interpolation", "HIGH"),
    (r'f[\"\']https?://[^\"\']*\{[^}]*(?:request\.|params\[|req\.(?:query|body|params)|user_input|input\(|args\.get|form\.get|\$_GET|\$_POST)[^}]*\}', "SSRF: f-string URL with user variable", "HIGH"),
]

# Ruby-only SSRF — `open()`/`open-uri` открывают HTTP в Ruby, но `open()` в Python читает файл
RUBY_SSRF_PATTERNS: list[tuple[str, str, str]] = [
    (r'open-uri|URI\.open|open\s*\(\s*params\[', "SSRF: Ruby open-uri with user input", "HIGH"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.go', '.java', '.cs'}

EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__'}

EXCLUDE_PATTERNS = ['test_', 'test/', '.test.', '.spec.', '__test__']


def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    files = _collect_files(ctx.path)

    for file_path in files:
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue

        rel_path = str(file_path.relative_to(ctx.path))

        for pattern, message, severity in CSRF_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category=severity,
                    title=message, file_path=rel_path, line=line_no,
                    detail=snippet.strip()[:200], cwe="CWE-352",
                    cvss={"HIGH":"7.5","MEDIUM":"5.3","INFO":"0.0"}.get(severity,"5.0"),
                ))

        for pattern, message, severity in SSRF_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category=severity,
                    title=message, file_path=rel_path, line=line_no,
                    detail=snippet.strip()[:200], cwe="CWE-918",
                    cvss={"CRITICAL":"9.1","HIGH":"7.5","INFO":"0.0"}.get(severity,"5.0"),
                ))

        if file_path.suffix == '.rb':
            for pattern, message, severity in RUBY_SSRF_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_no = content[:match.start()].count('\n') + 1
                    snippet = _extract_line(content, line_no)
                    if _is_false_positive(snippet):
                        continue
                    findings.append(Finding(
                        rule_id=RULE_ID, severity=severity, category=severity,
                        title=message, file_path=rel_path, line=line_no,
                        detail=snippet.strip()[:200], cwe="CWE-918",
                        cvss={"CRITICAL":"9.1","HIGH":"7.5","INFO":"0.0"}.get(severity,"5.0"),
                    ))

    return findings


def _collect_files(root: Path) -> list[Path]:
    files = []
    for ext in FILE_EXTENSIONS:
        for f in root.rglob(f'*{ext}'):
            if any(d in f.parts for d in EXCLUDE_DIRS):
                continue
            if any(p in f.name for p in EXCLUDE_PATTERNS):
                continue
            files.append(f)
    return files


def _extract_line(content: str, line_no: int) -> str:
    lines = content.split('\n')
    return lines[line_no - 1] if 0 < line_no <= len(lines) else ''


def _is_false_positive(snippet: str) -> bool:
    s = snippet.strip()
    return s.startswith('//') or s.startswith('#') or s.startswith('/*') or s.startswith('*')
