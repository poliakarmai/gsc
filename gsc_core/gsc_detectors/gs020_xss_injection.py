# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS020 — XSS / HTML Injection / Template Injection.

Web Hacking 101 + Real-World Bug Hunting:
- Reflected/stored/DOM XSS
- HTML injection (innerHTML, dangerouslySetInnerHTML)
- Template injection (SSTI — Jinja2, Django, ERB, Blade)
- CSP bypass patterns

ECHELON: 1 (precise patterns, high signal)
"""

from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Detector, Finding

RULE_ID = "GS020"
ECHELON = 1
NOISE_TIER = "normal"
description = "XSS / HTML / Template Injection — reflected, stored, DOM, SSTI (Web Hacking 101)"

# ── XSS Patterns ──────────────────────────────────────────────────────────────

XSS_PATTERNS: list[tuple[str, str, str]] = [
    # DOM XSS — dangerous sinks
    (r'\.innerHTML\s*=', "DOM XSS: .innerHTML assignment — use .textContent instead", "HIGH"),
    (r'dangerouslySetInnerHTML', "DOM XSS: dangerouslySetInnerHTML in React", "HIGH"),
    (r'\.outerHTML\s*=', "DOM XSS: .outerHTML assignment", "HIGH"),
    (r'document\.write\s*\(', "DOM XSS: document.write() with user input", "HIGH"),
    (r'\.insertAdjacentHTML\s*\(', "DOM XSS: insertAdjacentHTML()", "HIGH"),
    (r'eval\s*\(\s*[\"\'\`]', "DOM XSS: eval() with string input", "CRITICAL"),
    (r'setTimeout\s*\(\s*[\"\'\`]', "Potential DOM XSS: setTimeout with string argument", "MEDIUM"),
    (r'setInterval\s*\(\s*[\"\'\`]', "Potential DOM XSS: setInterval with string argument", "MEDIUM"),

    # Reflected XSS — unsanitized output
    (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[', "Reflected XSS: direct output of user input in PHP", "CRITICAL"),
    (r'print\s*\(\s*request\.(?:args|form|values|json)\[', "Reflected XSS: Flask request parameter in output", "HIGH"),
    (r'<%=.*(?:params|request\.(?:params|query)|@request)', "Reflected XSS: ERB/Rails raw output of request params", "CRITICAL"),
    (r'Response\.Write\s*\(\s*Request', "Reflected XSS: Response.Write with Request in ASP.NET", "CRITICAL"),
    (r'<\?=\s*\$_(?:_GET|_POST|_REQUEST)', "Reflected XSS: PHP short echo of user input", "CRITICAL"),
    (r'<%=.*(?:request\.getParameter|request\.getAttribute|param\.|params\.)', "Reflected XSS: JSP raw output of user input", "CRITICAL"),
    (r'<c:out\s+value\s*=\s*["\'].*escapeXml\s*=\s*["\']false["\']', "Reflected XSS: JSTL c:out with escapeXml=false", "HIGH"),

    # Stored XSS
    (r'\.innerHTML\s*=\s*.*\.(?:value|innerText|textContent)', "Stored XSS: innerHTML from stored content", "MEDIUM"),

    # Template Injection (SSTI)
    (r'render_template_string\s*\(', "SSTI: Flask render_template_string with user input", "CRITICAL"),
    (r'env\.from_string\s*\(', "SSTI: Jinja2 env.from_string with user input", "CRITICAL"),
    (r'Template\s*\(\s*.*\+', "SSTI: Go html/template with string concatenation", "HIGH"),
    (r'ERB\.new\s*\(', "SSTI: ERB.new with user input in Ruby", "CRITICAL"),
    (r'\{\s*\{\s*.*request\.', "SSTI: Django/Jinja2 template with request object", "MEDIUM"),

    # Python f-string / format HTML injection (Reflected XSS)
    (r'f[\"\']<\s*\w+[^\"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string HTML interpolation — user input in tag", "HIGH"),
    (r'[\"\']<[^\"\']*\{[^}]*\}[^\"\']*>[\"\']\s*\.format\s*\(', "Reflected XSS: .format() HTML interpolation", "HIGH"),
    (r'[\"\']<[^\"\']*%s[^\"\']*>[\"\']\s*%\s*', "Reflected XSS: %-formatting HTML interpolation", "MEDIUM"),
    (r'f[\"\']<\s*script[^\"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string script tag with variable", "CRITICAL"),

    # Template literals with user input (JS)
    (r'`<\w+[^`]*\$\{[a-zA-Z_]\w*\}', "Reflected XSS: template literal HTML with variable", "HIGH"),
]

# ── HTML Injection Patterns ───────────────────────────────────────────────────

HTML_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (r'v-html\s*=', "HTML Injection: Vue v-html directive — use v-text", "MEDIUM"),
    (r'ng-bind-html\s*=', "HTML Injection: Angular ng-bind-html", "MEDIUM"),
    (r'RichText|rich.?text|WYSIWYG', "Potential HTML Injection: rich text editor output", "INFO"),
]

# ── Files to scan ─────────────────────────────────────────────────────────────

FILE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.erb',
    '.html', '.htm', '.vue', '.svelte', '.go', '.java', '.cs',
    '.aspx', '.jsp',
}

EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__', 'bower_components'}

EXCLUDE_PATTERNS = ['test_', 'test/', 'spec_', 'spec/', '.test.', '.spec.', '__test__']


# ── Detector ─────────────────────────────────────────────────────────────────

def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    files = _collect_files(ctx.path)

    for file_path in files:
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue

        rel_path = str(file_path.relative_to(ctx.path))

        for pattern, message, severity in XSS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)

                if _is_false_positive(snippet, pattern):
                    continue

                # Context-aware severity adjustment (Precision First)
                context_start = max(0, line_no - 3)
                context_end = min(len(lines := content.split('\n')), line_no + 2)
                context = '\n'.join(lines[context_start:context_end])
                adjusted_severity = _adjust_xss_severity(severity, pattern, context)

                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity=adjusted_severity,
                    category=adjusted_severity,
                    title=message,
                    file_path=rel_path,
                    line=line_no,
                    detail=snippet.strip()[:200],
                    cwe="CWE-79" if "XSS" in message else "CWE-94" if "SSTI" in message else "CWE-80",
                    cvss=_cvss_for_severity(adjusted_severity),
                ))

        for pattern, message, severity in HTML_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                snippet = _extract_line(content, line_no)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity=severity,
                    category=severity,
                    title=message,
                    file_path=rel_path,
                    line=line_no,
                    detail=snippet.strip()[:200],
                    cwe="CWE-80",
                    cvss="5.3",
                ))

    return findings


def _collect_files(root: Path) -> list[Path]:
    files = []
    for ext in FILE_EXTENSIONS:
        for f in root.rglob(f'*{ext}'):
            parts = f.parts
            if any(d in EXCLUDE_DIRS for d in parts):
                continue
            if any(p in f.name for p in EXCLUDE_PATTERNS):
                continue
            files.append(f)
    return files


def _extract_line(content: str, line_no: int) -> str:
    lines = content.split('\n')
    if 0 < line_no <= len(lines):
        return lines[line_no - 1]
    return ''


def _is_false_positive(snippet: str, pattern: str) -> bool:
    snippet_lower = snippet.lower()
    # Skip comments
    if snippet.strip().startswith('//') or snippet.strip().startswith('#'):
        return True
    if snippet.strip().startswith('<!--'):
        return True
    if snippet.strip().startswith('/*') or snippet.strip().startswith('*'):
        return True
    # Skip test/demo files
    if 'test' in snippet_lower or 'demo' in snippet_lower or 'example' in snippet_lower:
        if 'innerhtml' in pattern or 'document.write' in pattern:
            return True
    # Static innerHTML/outerHTML assignment without interpolation/concat is a
    # hardcoded template, not user-controlled markup — FP.
    if re.search(r'(?:innerHTML|outerHTML)\s*=\s*["\'\`](?![\s\S]*(\$\{|["\'\`]\s*\+))', snippet):
        return True
    # Static eval/setTimeout/setInterval string (no ${}, concat, or {var})
    # is legacy/minified code, not user-controlled — FP.
    if re.search(r'(?:eval|setTimeout|setInterval)\s*\(\s*["\'\`](?![\s\S]*(\$\{|["\'\`]\s*\+|\{\s*[a-zA-Z_]\w*\s*\}))', snippet):
        return True
    # dangerouslySetInnerHTML with a static literal is hardcoded markup, not user input — FP.
    if re.search(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*["\'`]', snippet):
        return True
    # render_template_string(<CONSTANT>) / from_string(<CONSTANT>) — a static
    # module template, not user input — FP. SSTI needs user input reaching the
    # template *string* (DETECTOR_BRIEF_GS020.md, v6 precision pass).
    if 'render_template_string' in pattern or 'from_string' in pattern:
        m = re.search(r'(?:render_template_string|from_string)\s*\(\s*([^,)]+)', snippet)
        if m:
            arg = m.group(1).strip()
            # module-level UPPER_SNAKE constant — static template
            if re.fullmatch(r'[A-Z_][A-Z0-9_]*', arg):
                return True
            # plain string literal without interpolation/concat — static
            if re.fullmatch(r'["\'`][^"\'`{}$+]*["\'`]', arg):
                return True
    return False


# ── XSS context-aware analysis (Precision First) ──────────────────────────

_XSS_SANITIZERS = re.compile(
    r'(?:DOMPurify\.sanitize|escapeHtml|sanitizeHtml|encodeURIComponent|'
    r'html\.escape|bleach\.clean|xss-filters|\.textContent\s*=|'
    r'markupsafe\.escape|escape\s*\(|cgi\.escape|'
    r'jinja2\.escape|\{\{\s*\w+\s*\|\s*e(?:scape)?\s*\}\}|'
    r'esapi\.encoder|HtmlUtils\.htmlEscape)',
    re.IGNORECASE,
)

_XSS_TAINT_SOURCES = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE)|'
    r'input\s*\(|params\[|location\.(?:search|hash|href)|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:value|innerText|textContent)\b)',
    re.IGNORECASE,
)

# Patterns where context analysis applies (all DOM + reflected XSS)
_CONTEXT_AWARE_PATTERNS = frozenset({
    '.innerHTML', 'dangerouslySetInnerHTML', '.outerHTML',
    'insertAdjacentHTML', 'document.write',
    # Python reflected XSS — sanitizer check applies
    'f-string HTML', '.format() HTML', '%-formatting HTML',
    'f-string script', 'template literal HTML',
})


def _has_xss_sanitizer(context: str) -> bool:
    """Check if surrounding code has XSS sanitizer calls."""
    return bool(_XSS_SANITIZERS.search(context))


def _has_tainted_source(context: str) -> bool:
    """Check if variable originates from user input."""
    return bool(_XSS_TAINT_SOURCES.search(context))


# Reflected-XSS patterns are HTML interpolation where a taint source must be
# present to justify HIGH/CRITICAL. Without taint they are a weak signal.
_REFLECTED_PATTERN_MARKERS = ('.format(', '%s', '${', 'f"', "f'")


def _adjust_xss_severity(
    severity: str, pattern: str, context: str
) -> str:
    """Adjust XSS severity based on sanitizer/taint context analysis."""
    has_sanitizer = _has_xss_sanitizer(context)
    has_taint = _has_tainted_source(context)

    if has_sanitizer:
        return "LOW"          # sanitizer present — downgrade significantly
    if has_taint:
        if severity not in ("CRITICAL", "HIGH"):
            return "HIGH"     # tainted source, no sanitizer — escalate
        return severity
    # No taint, no sanitizer: HTML interpolation without confirmed user input
    # is a weak signal — downgrade reflected-XSS patterns one level.
    if any(m in pattern for m in _REFLECTED_PATTERN_MARKERS):
        return {"CRITICAL": "HIGH", "HIGH": "MEDIUM"}.get(severity, severity)
    return severity


def _cvss_for_severity(severity: str) -> str:
    return {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1", "INFO": "0.0"}.get(severity, "5.0")
