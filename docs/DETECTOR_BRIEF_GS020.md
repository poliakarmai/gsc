# Brief: GS020 (XSS/HTML/SSTI) precision pass — kill the `RichText` INFO noise

> For an external AI agent (Claude Code / Codex / ChatGPT). **Self-contained** — the full
> detector source and its contract are embedded below. No repo access is needed.
>
> **This brief exists because a previous agent hallucinated.** Read §6 (Anti-hallucination
> rules) before writing a single line. If the code you need is NOT shown in this brief,
> do not invent it — mark it `UNKNOWN` and ask.

---

## 1. Context

GSC is a self-learning SAST platform (Python). Detectors are structured modules
`gsc_core/gsc_detectors/gsXXX_*.py` implementing `detect(ctx) -> list[Finding]`.

Fresh precision measurement (2026-08-19) on 13 calibration projects (9 clean + 4
deliberately-vulnerable), after GS000-LEGACY was fixed:

| Layer | FP on clean projects | Share |
|-------|---------------------|-------|
| GS021 (CSRF/SSRF) | 39 | ~7% (brief issued) |
| **GS020 (XSS/HTML/SSTI)** | **31** | **~6%** |
| GS037 (path traversal) | 21 | 4% |
| GS003 / GS022 | 14 / 14 | 3% each |

GS020 breakdown by title across **clean** projects:

| Pattern (title) | Severity | Clean FP | Share | Source project |
|---|---|---|---|---|
| `Potential HTML Injection: rich text editor output` | INFO | **19** | 61% | rich (all 19) |
| `Reflected XSS: f-string HTML interpolation — user input in tag` | HIGH | **9** | 29% | werkzeug 8, httpx 1 |
| `DOM XSS: .innerHTML assignment` | HIGH | 2 | 6% | werkzeug (debugger.js) |
| `SSTI: Jinja2 env.from_string with user input` | CRITICAL | 1 | 3% | jinja (environment.py) |

The top offender — `RichText|rich.?text|WYSIWYG` — fires 19× on the **`rich` terminal
formatting library itself**, because its source is *literally* full of the words "rich
text" (`rich.text` module, `RichText` type, docstrings). Zero real findings.

---

## 2. Full detector source (the ONLY file you may change)

`gsc_core/gsc_detectors/gs020_xss_injection.py` — reproduced in full. Proposals must be
diffs against THIS exact text.

```python
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
    (r'eval\s*\(\s*["\'`]', "DOM XSS: eval() with string input", "CRITICAL"),
    (r'setTimeout\s*\(\s*["\'`]', "Potential DOM XSS: setTimeout with string argument", "MEDIUM"),
    (r'setInterval\s*\(\s*["\'`]', "Potential DOM XSS: setInterval with string argument", "MEDIUM"),

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
    (r'f["\']<\s*\w+[^"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string HTML interpolation — user input in tag", "HIGH"),
    (r'["\']<[^"\']*\{[^}]*\}[^"\']*>["\']\s*\.format\s*\(', "Reflected XSS: .format() HTML interpolation", "HIGH"),
    (r'["\']<[^"\']*%s[^"\']*>["\']\s*%\s*', "Reflected XSS: %-formatting HTML interpolation", "MEDIUM"),
    (r'f["\']<\s*script[^"\']*\{[a-zA-Z_]\w*\}', "Reflected XSS: f-string script tag with variable", "CRITICAL"),

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
    if re.search(r'(?:innerHTML|outerHTML)\s*=\s*["\'`](?![\s\S]*(\$\{|["\'`]\s*\+))', snippet):
        return True
    # Static eval/setTimeout/setInterval string (no ${}, concat, or {var})
    # is legacy/minified code, not user-controlled — FP.
    if re.search(r'(?:eval|setTimeout|setInterval)\s*\(\s*["\'`](?![\s\S]*(\$\{|["\'`]\s*\+|\{\s*[a-zA-Z_]\w*\s*\}))', snippet):
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
```

### 2.1 The contract (do NOT change, do NOT invent fields)

`Finding` is a `dict` subclass. Constructor signature (verbatim):

```python
class Finding(dict):
    def __init__(
        self,
        rule_id: str,
        severity: str = "MEDIUM",
        title: str = "",
        file_path: str = "",
        line: int = 0,
        detail: str = "",
        fix_suggestion: str = "",
        references: list[str] | None = None,
        noise_tier: str = "normal",
        **kwargs,   # accepts category=, line_number=, cwe=, cvss=, etc.
    ): ...
```

`AuditContext` (dataclass) carries `project: str`, `path: Path`, plus helpers
`get_files`, `get_source_files`, `read_file`, `is_test_file`, `is_non_code_file`.

**There is no `patterns` table / DB interaction in this detector.** Do NOT propose SQL,
`load_patterns`, `rule_id` columns, or any other DB work — none of it applies here.

---

## 3. Exact FP evidence (from the real measurement)

**Lead-1 evidence — `RichText|rich.?text|WYSIWYG` (INFO), 19 FP, all on `rich`:**

| File:line | Snippet (actual) | Why NOT an XSS sink |
|---|---|---|
| `rich/abc.py:22` | `from rich.text import Text` | import of the `rich.text` module |
| `rich/palette.py:23` | `from rich.text import Text` | same import |
| `rich/__main__.py:15` | `from rich.text import Text` | same import |
| `rich/text.py:527` | `>>> from rich.text import Text` | doctest |
| `rich/text.py:1069` | `"""Split rich text in to lines, preserving styles."""` | docstring |
| `rich/text.py:1077` | `List[RichText]: A list of rich text, one per line...` | docstring type annotation |
| `rich/highlighter.py:68` | `"""Highlight :class:`rich.text.Text` using regex..."""` | docstring |

`rich` is a terminal-formatting library; its source is *about* rich text. The pattern
matches the module name, not a "rich text editor output" sink. **0 real TP.**

**Lead-2 evidence — `f-string HTML interpolation` (HIGH→MEDIUM), 9 FP:**

| File:line | Snippet (actual) | Why FP |
|---|---|---|
| `werkzeug/testapp.py:153` | `wsgi_env.append(f"<tr><th>{escape(key)}<td><code>{value}</code>")` | test/debug app, already partially escaped |
| `werkzeug/testapp.py:163` | `sys_path.append(f"<li{class_str}>{escape(item)}")` | test/debug app |
| `werkzeug/exceptions.py:110` | `return f"<p>{description}</p>"` | `description` is an exception, not request input |
| `werkzeug/debug/tbtools.py:322` | `"title": f"<h3>{title}</h3>"` | `title` is an exception property |

These are framework-internal HTML rendering (error pages, debugger, test app). The
interpolated vars are NOT request params. Current `_adjust_xss_severity` only *downgrades*
them HIGH→MEDIUM (no taint), it does not drop them — so they still surface as findings.

**Lead-3 evidence — `.innerHTML` (HIGH), 2 FP on `werkzeug/debug/shared/debugger.js`:**

| File:line | Snippet | Why FP |
|---|---|---|
| `debugger.js:157` | `elements[i].innerHTML =` | debugger UI, local variable |
| `debugger.js:273` | `tmp.innerHTML = data;` | `data` is a fetched debug trace, not user input |

**Lead-4 evidence — `env.from_string` (CRITICAL), 1 FP on jinja:**

| File:line | Snippet | Why FP |
|---|---|---|
| `jinja2/environment.py:1211` | `return env.from_string(source, template_class=cls)` | jinja's own `from_string` API — `source` is an API arg, not request taint |

---

## 4. Root cause

Four patterns fire without proof of attacker-controlled input:

1. `RichText|rich.?text|WYSIWYG` has **no sink semantics at all** — it matches a *name*.
2. `f-string HTML interpolation` matches any `f"<tag>{var}"`; the taint check only
   *downgrades* severity, it never *suppresses* — so framework-internal rendering still
   becomes a MEDIUM finding.
3. `.innerHTML` static-filter already exists, but it only catches string literals
   (`innerHTML = "..."`); `innerHTML = <variable>` (no taint) slips through.
4. `env.from_string` const-skip already exists, but only for `UPPER_SNAKE` / string-literal
   args; `from_string(source)` with an API parameter slips through.

---

## 5. Constraints

- **Change only** `XSS_PATTERNS` / `HTML_INJECTION_PATTERNS` entries and the local
  `_is_false_positive` / `_adjust_xss_severity` helpers (or add small pure helpers beside them).
- **Do NOT change** `RULE_ID`, `ECHELON`, `NOISE_TIER`, `description`, `cwe`/`cvss` mapping
  semantics, or `_collect_files`/`_extract_line`.
- **Do NOT add new detection categories** — this is a *precision* pass, not recall.
- **Do NOT weaken** the real TP-producing markers:
  - `@csrf_exempt`-style CSRF — N/A here (that's GS021), but within GS020 keep:
  - `echo $_GET[...]`, `<?= $_GET[...]`, `<%= request.getParameter(...)`, `v-html`,
    `ng-bind-html`, `dangerouslySetInnerHTML`, `document.write`, `render_template_string`
  - The `rich text editor output` INFO pattern is the ONLY candidate for outright removal.
- `_adjust_xss_severity` is shared by multiple patterns — if you change its return
  semantics, state the effect on EVERY caller pattern, not just the one you're fixing.
- `_CONTEXT_AWARE_PATTERNS` is currently defined but **unused** in `detect()` — note this;
  if you propose wiring it in, that is a structural change and must be flagged as such.

---

## 6. ANTI-HALLUCINATION RULES (read first — the last agent violated all of these)

The previous brief (GS000-LEGACY) produced proposals that were **partly invented**.
These specific failure modes must not recur:

1. **Do not invent function signatures.** The last agent rewrote `load_patterns()` with a
   made-up `cursor.execute(...)` + `ORDER BY priority`. Neither existed. **Only diff code
   shown in §2.**
2. **Do not invent DB columns.** The last agent wrote `WHERE rule_id='GS000-LEGACY'` — the
   `patterns` table has no `rule_id` column. (Irrelevant here anyway: this detector has no DB.)
3. **Do not attack the wrong source.** The last agent "fixed" OWASP `chmod` for a FP that
   actually came from a file-permission check elsewhere. Trace the FP to the exact pattern
   (§3 gives you file:line:snippet) before proposing a change.
4. **Do not miss mirrored copies.** There is exactly **one** file (§2) — no mirrors.
5. **If you need a symbol not shown in §2, say `UNKNOWN: <name>` and ask.** Never invent it.
6. **Verify every regex you write.** Give a 3-line reasoning for what it matches and what it
   no longer matches, with 2 example inputs each (should-fire / should-not-fire).
7. **No vague "add a filter".** Give the exact regex or helper code, with the exact insertion
   point (the surrounding lines from §2 it sits between).
8. **The old RU brief (v6) is superseded.** Some of its "зацепки" (static innerHTML, static
   eval) are *already implemented* in §2's `_is_false_positive`. Do not re-propose them.

---

## 7. Required output format

For each change, emit one block:

```
### Lead N — <title>
- Type: pattern_removal | pattern_narrow | helper_filter | severity_handling
- File: gsc_core/gsc_detectors/gs020_xss_injection.py
- Before: <exact lines from §2 being changed>
- After:  <exact replacement lines>
- Rationale: <1–2 sentences>
- FP removed: <count / which examples from §3>
- TP impact: <which §5 markers are affected, and why not>
- Verification: <expected result of: python3 gsc.py scan /tmp/gsc-calibration/rich --ci --json | grep GS020 → should drop 19 → 0>
```

Targets, in priority order:

- **Lead 1 (61% of FP):** remove the `RichText|rich.?text|WYSIWYG` INFO pattern from
  `HTML_INJECTION_PATTERNS`. Justify removal vs. narrowing — the measurement shows it fires
  only on the `rich` library's own name/imports/docstrings (0 real TP), so **removal is the
  defensible default**. If you narrow, the new regex MUST anchor to an actual sink context
  (`innerHTML|v-html|dangerouslySetInnerHTML|document.write`) co-occurring with `RichText`.
- **Lead 2 (29%):** for the `f-string HTML interpolation` family (`f-string HTML`,
  `.format() HTML`, `%-formatting HTML`, `f-string script`, `template literal HTML`), the
  current behavior downgrades but does not suppress. Propose: suppress (skip) the finding
  when `_has_tainted_source(context)` is False AND `_has_xss_sanitizer(context)` is False,
  OR narrow the regex to require a taint token on the same line. State the TP risk — the
  `xss-demo` project must still fire (it has real reflected XSS).
- **Lead 3 (6%):** `.innerHTML = <variable>` where the variable is not a taint source →
  FP. Propose a filter in `_is_false_positive` for `.innerHTML\s*=\s*[a-zA-Z_]\w*\s*;?$`
  with no taint token on the line.
- **Lead 4 (3%):** `env.from_string(source, ...)` inside jinja's own API → FP. Propose
  widening the const-skip so a `from_string`/`render_template_string` arg that is a bare
  identifier *and* appears inside a `def` whose name is `from_string`/`render_template_string`
  (or a library-internal path) is skipped — or state plainly if this is not safely detectable
  and should be left.

---

## 8. Verification (run by the repo owner, not by you)

After applying proposals, the owner runs:

```bash
python3 gsc.py scan /tmp/gsc-calibration/rich     --ci --json  # GS020 19 → expected 0
python3 gsc.py scan /tmp/gsc-calibration/werkzeug --ci --json  # GS020 10 → expected 0–1
python3 gsc.py scan /tmp/gsc-calibration/xss-demo --ci --json  # GS020 TP MUST still fire
python3 -m pytest tests/ -q
```

State the **expected** delta for each, so the owner can confirm no TP loss. If you cannot
predict a delta from §2 alone, say so rather than guessing.
