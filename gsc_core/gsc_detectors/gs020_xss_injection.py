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

                # Multiline DOM-XSS assignment (`.innerHTML =\n"static"`) puts
                # the RHS on the next line; fold it in so the static-string
                # FP suppression below can see it.
                if pattern in (r'\.innerHTML\s*=', r'\.outerHTML\s*=') and snippet.rstrip().endswith('='):
                    _next = _extract_line(content, line_no + 1)
                    if _next:
                        snippet = snippet + '\n' + _next

                if _is_false_positive(snippet, pattern):
                    continue

                # Context-aware severity adjustment (Precision First)
                context_start = max(0, line_no - 3)
                context_end = min(len(lines := content.split('\n')), line_no + 2)
                context = '\n'.join(lines[context_start:context_end])
                adjusted_severity = _adjust_xss_severity(severity, pattern, context)

                # Suppress reflected-XSS with no taint and no sanitizer —
                # framework-internal rendering (error pages, debuggers, test apps).
                # BUT preserve TP: if the interpolated var is a function parameter,
                # it may be user-controlled upstream — downgrade instead of suppress.
                if adjusted_severity == "_SUPPRESS":
                    var = _interpolated_var(snippet, pattern)
                    if var and _is_function_parameter(content, line_no, var):
                        adjusted_severity = {"CRITICAL": "HIGH", "HIGH": "MEDIUM"}.get(severity, severity)
                    else:
                        continue

                # SSTI: env.from_string(<bare_lowercase_id>) with no taint is a
                # library-internal API call (jinja's own from_string), not user
                # input. render_template_string is NOT suppressed — a bare id
                # there (e.g. render_template_string(user_input)) is a TP.
                if pattern == r'env\.from_string\s*\(':
                    m = re.search(r'from_string\s*\(\s*([a-z_]\w*)', snippet)
                    if m and not _has_tainted_source(context) and not _has_xss_sanitizer(context):
                        continue

                # DOM XSS: .innerHTML/.outerHTML = <variable> is ambiguous — the
                # variable may be attacker-controlled (e.g. pygoat a9.js
                # `li.innerHTML = data.logs[i]`). Static string literals are
                # already suppressed in _is_false_positive; a variable is NOT
                # suppressed (it is a potential TP, kept as-is).
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
# NOTE: f-string patterns are `f["']...`, so the marker is `f[` (not `f"`/`f'`).
_REFLECTED_PATTERN_MARKERS = ('.format(', '%s', '${', 'f[')


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
    # is framework-internal rendering (error pages, debuggers, test apps), not an
    # XSS sink — suppress. Real reflected XSS requires attacker-controlled input
    # reaching the sink. Sentinel "_SUPPRESS" is handled by detect().
    if any(m in pattern for m in _REFLECTED_PATTERN_MARKERS):
        return "_SUPPRESS"
    return severity


def _interpolated_var(snippet: str, pattern: str) -> str:
    """Return the interpolated identifier from an f-string/format HTML snippet."""
    m = re.search(r'\{([a-zA-Z_]\w*)\}', snippet)
    return m.group(1) if m else ""


def _is_function_parameter(content: str, line_no: int, var: str) -> bool:
    """True if `var` is a parameter of the nearest enclosing `def` above line_no.

    Preserves TP for reflected XSS where the interpolated value arrives as a
    function argument (e.g. `def render(name): return f"<div>{name}</div>"`) —
    the taint source lives in the caller, outside this file's context window.
    """
    lines = content.split("\n")
    # line_no is 1-indexed; lines[] is 0-indexed, so the line above is
    # lines[line_no-2]. Walk upward from there (up to 60 lines).
    start = max(0, line_no - 2)
    stop = max(-1, line_no - 62)
    for i in range(start, stop, -1):
        m = re.search(r'def\s+\w+\s*\(([^)]*)\)', lines[i])
        if m:
            params = re.findall(r'[a-zA-Z_]\w*', m.group(1))
            return var in params
    return False


def _cvss_for_severity(severity: str) -> str:
    return {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1", "INFO": "0.0"}.get(severity, "5.0")
