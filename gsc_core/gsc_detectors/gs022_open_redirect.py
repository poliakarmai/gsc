# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS022 — Open Redirect / URL Manipulation.

Web Hacking 101 + Real-World Bug Hunting:
- Open redirect via url/redirect/next/callback params
- URL validation bypass (//evil.com, \\evil.com, @evil.com)
- Path traversal in redirects

ECHELON: 2 (broader patterns, needs context)
"""

from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS022"
ECHELON = 2
NOISE_TIER = "normal"
description = "Open Redirect / URL Manipulation — redirect params, validation bypass (Web Hacking 101)"

OPEN_REDIRECT_PATTERNS: list[tuple[str, str, str]] = [
    # Redirect with user-controlled URL
    (r'redirect\s*\(\s*(?:request\.(?:args|form|query|params)|params\[|req\.(?:query|body))',
     "Open Redirect: redirect() with user-controlled URL", "HIGH"),
    (r'redirect\(.*\$_(?:GET|POST|REQUEST)', "Open Redirect: PHP redirect with user input", "CRITICAL"),
    # ASP.NET: только user-controlled источники (индексаторы), НЕ Request.Url.AbsoluteUri/UrlReferrer
    (r'(?-i:Redirect\s*\(\s*Request(?:\[[\'"]|\.QueryString\[[\'"]|\.Form\[[\'"]|\.Params\[[\'"]))',
     "Open Redirect: ASP.NET Redirect with user input", "CRITICAL"),
    (r'redirect_to\s+.*(?:params|request)', "Open Redirect: Rails redirect_to with params", "HIGH"),
    (r'window\.location\s*=\s*.*(?:url|redirect|next|callback|return)', "Open Redirect: JS window.location with redirect param", "MEDIUM"),
    (r'window\.location\.(?:href|replace)\s*=\s*.*(?:url|redirect|next|callback)', "Open Redirect: JS location change with redirect param", "MEDIUM"),
    (r'HttpResponseRedirect\s*\(.*request', "Open Redirect: Django redirect with request data", "HIGH"),
    (r'request\.(?:args|form|query|params)\.get\s*\(\s*[\"\'](?:redirect|url|next|return|callback|goto|redir|continue|target)[\"\']',
     "Open Redirect: redirect/url/next param extracted from request", "HIGH"),
    (r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\"\'](?:redirect|url|next|return|callback|goto|redir)[\"\']',
     "Open Redirect: PHP redirect param from user input", "CRITICAL"),
    (r'url\.startswith\s*\(\s*[\"\']/', "Weak URL validation: only checks for leading /", "MEDIUM"),
    (r'urlparse|url\.parse|URL\(', "URL parsing present — verify whitelist, not blacklist", "INFO"),
    (r'\.replace\s*\(\s*[\"\']https?://[\"\']\s*,\s*[\"\']', "Weak URL validation: simple string replace", "MEDIUM"),
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

        for pattern, message, severity in OPEN_REDIRECT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet, content, line_no):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category=severity,
                    title=message, file_path=rel_path, line=line_no,
                    detail=snippet.strip()[:200], cwe="CWE-601",
                    cvss={"CRITICAL":"8.1","HIGH":"6.1","MEDIUM":"4.3","INFO":"0.0"}.get(severity,"4.3"),
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


def _context(content: str, line_no: int, before: int, after: int) -> str:
    lines = content.split('\n')
    lo = max(0, line_no - 1 - before)
    hi = min(len(lines), line_no - 1 + after + 1)
    return '\n'.join(lines[lo:hi])


def _is_false_positive(snippet: str, content: str, line_no: int) -> bool:
    s = snippet.strip()
    if s.startswith('//') or s.startswith('#') or s.startswith('/*') or s.startswith('*'):
        return True
    # Skip HTML comments
    if s.startswith('<!--'):
        return True
    # Django redirect(request.path / get_full_path) — редирект на тот же путь,
    # не на user-controlled URL (url_has_allowed_host_and_scheme не нужен)
    if re.search(r'redirect\s*\(\s*request\.(?:path|get_full_path|path_info)', s, re.I):
        return True
    # INFO urlparse/URL( без redirect-контекста — легитимный парсинг, не open redirect
    if re.search(r'urlparse|url\.parse|URL\(', s, re.I):
        ctx = _context(content, line_no, 4, 3)
        if not re.search(r'redirect|window\.location|HttpResponseRedirect|redirect_to', ctx, re.I):
            return True
    # request.args.get('next') с Django safe-валидацией — не open redirect
    if re.search(r'request\.(?:args|form|query|params)\.get\s*\(\s*[\'\"](?:redirect|url|next|return|callback|goto|redir|continue|target)[\'\"]', s, re.I):
        ctx = _context(content, line_no, 1, 4)
        if re.search(r'url_has_allowed_host_and_scheme|is_safe_url|allowed_hosts', ctx, re.I):
            return True
    return False
