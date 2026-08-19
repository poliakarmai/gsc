# Brief: GS021 (CSRF/SSRF) precision pass — kill the `localhost` INFO noise

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
deliberately-vulnerable):

| Layer | FP on clean projects | Share |
|-------|---------------------|-------|
| GS000-LEGACY (fixed) | 0 (was 330) | — |
| **GS021 (CSRF/SSRF)** | **39** | **~7%** |
| GS020 (XSS) | 33 | 6% |
| GS037 (path traversal) | 21 | 4% |

GS021 breakdown by title across **clean** projects:

| Pattern (title) | Severity | Clean FP | Notes |
|---|---|---|---|
| `SSRF candidate: reference to localhost` | INFO | **38** | 97% of all GS021 noise |
| `SSRF: f-string URL with user variable` | HIGH | 1 | |
| everything else | — | 0 | see §5 |

The `localhost` pattern fires **38× on clean code** and, crucially, **~13× on the
deliberately-vulnerable `pygoat` project too — but those are also false positives**
(default args like `HOST="localhost"`, string comparisons like `if ip != '127.0.0.1'`,
docstrings). It produces **zero real SSRF findings anywhere**.

---

## 2. Full detector source (the ONLY file you may change)

`gsc_core/gsc_detectors/gs021_csrf_ssrf.py` — reproduced in full. Proposals must be
diffs against THIS exact text.

```python
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
    (r'@app\.route.*methods\s*=\s*\[.*POST', "Potential CSRF: POST route without token check", "MEDIUM"),
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
     "SSRF: HTTP request to a variable (verify URL is not user-controlled)", "HIGH"),
    (r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)', "SSRF: PHP file_get_contents with user input", "CRITICAL"),
    (r'curl_exec\s*\(.*\$_(?:GET|POST|REQUEST)', "SSRF: PHP curl_exec with user-controlled URL", "CRITICAL"),
    # Internal host references
    (r'localhost|127\.0\.0\.1|0\.0\.0\.0', "SSRF candidate: reference to localhost", "INFO"),
    (r'169\.254\.169\.254', "SSRF: AWS metadata endpoint in code", "CRITICAL"),
    (r'metadata\.google\.internal', "SSRF: GCP metadata endpoint in code", "CRITICAL"),
    (r'/var/run/docker\.sock', "SSRF/LFI: Docker socket reference in code", "HIGH"),
    # URL construction with user input
    (r'url\s*=\s*[\"\']https?://.*\{\{', "SSRF: URL template with variable interpolation", "HIGH"),
    (r'f[\"\']https?://\{', "SSRF: f-string URL with user variable", "HIGH"),
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

**There is no `patterns` table / DB interaction in this detector.** GS021 is a pure
structured detector. Do NOT propose SQL. Do NOT propose `load_patterns`, `rule_id`
columns, or any other DB work — none of it applies here.

---

## 3. Exact FP evidence (from the real measurement)

All from the `localhost` INFO pattern `r'localhost|127\.0\.0\.1|0\.0\.0\.0'`:

| Project | File:line | Snippet (actual) | Why it is NOT SSRF |
|---|---|---|---|
| werkzeug | `src/werkzeug/test.py:437` | `netloc = "localhost"` | variable assignment |
| werkzeug | `src/werkzeug/test.py:833` | `self, key: str, domain: str = "localhost"` | default parameter |
| werkzeug | `src/werkzeug/test.py:889` | `The ``domain`` parameter defaults to ``localhost``.` | docstring text |
| werkzeug | `src/werkzeug/serving.py:691` | `return "::1" if family == socket.AF_INET6 else "127.0.0.1"` | loopback-for-display |
| werkzeug | `src/werkzeug/serving.py:844` | `if self.host in {"0.0.0.0", "::"}:` | bind-address check |
| werkzeug | `src/werkzeug/middleware/http_proxy.py:43` | `"target": "http://127.0.0.1:5001/"` | config example |
| uvicorn | (8 occurrences) | `localhost` bind config / docstrings | server bind |
| rich | `rich/…` | `localhost` in text | non-request context |
| pygoat | `challenge/utility.py:3` | `def get_free_port(START_PORT, END_PORT, HOST="localhost")` | default arg |
| pygoat | `introduction/views.py:667` | `if ip != '127.0.0.1':` | loopback comparison |

Plus the `f-string URL` pattern `r'f["\']https?://\{'` → 1 clean FP on `httpx`:
a config-derived base URL, not user input.

---

## 4. Root cause

The `localhost` pattern has **no HTTP-client context**. It matches any occurrence of
`localhost`, `127.0.0.1`, or `0.0.0.0` — bind addresses, default args, docstrings,
string comparisons, config dicts. SSRF requires an *outbound HTTP request* whose URL
is attacker-influenced. A bare `localhost` token is not evidence of that.

The same weakness affects `f-string URL` (`f"https://{...}"` — no taint check on `{...}`)
and `HTTP request to a variable` (`requests.get(url)` — no proof `url` is tainted).

---

## 5. Constraints

- **Change only `CSRF_PATTERNS` / `SSRF_PATTERNS` entries and the local `_is_false_positive`
  helper** (or add small pure helper functions next to it). Do not restructure `detect()`.
- **Do NOT change** `RULE_ID`, `ECHELON`, `NOISE_TIER`, `description`.
- **Do NOT add new detection categories** — this is a *precision* pass (reduce FP), not a
  recall pass (add coverage).
- **Do NOT weaken** the real SSRF/CSRF markers that produce TP:
  - `@csrf_exempt`, `csrf_protect=False`, `WTF_CSRF_ENABLED=False`, `csrf.exempt` (CSRF TP — pygoat 25)
  - `169\.254\.169\.254`, `metadata\.google\.internal`, `/var/run/docker\.sock` (SSRF markers)
  - `file_get_contents($_...)`, `curl_exec(...$_...)` (PHP SSRF TP)
  - `POST route without token check` (fires 7 TP on Vulnerable-Flask-App, 5 on pygoat — keep, it is currently 0 FP on clean)
- Preserve `detect()`'s `cwe` mapping: CSRF → `CWE-352`, SSRF → `CWE-918`.
- If you remove the INFO `localhost` pattern, note that `INFO` severity disappears from the
  SSRF cvss map — that is fine and expected; do not "fix" the map unless a pattern still
  emits INFO.

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
   before proposing a change.
4. **Do not miss mirrored copies.** The last agent edited 1 of 3 files carrying the same
   pattern map. Here there is exactly **one** file (§2) — there are no mirrors.
5. **If you need a symbol not shown in §2, say `UNKNOWN: <name>` and ask.** Never invent it.
6. **Verify every regex you write.** Write a 3-line reasoning for what it matches and what it
   no longer matches, with 2 example inputs each (should-fire / should-not-fire).
7. **No vague "add a filter".** Give the exact regex or helper code, with the exact insertion
   point (the surrounding lines from §2 it sits between).

---

## 7. Required output format

For each change, emit one block:

```
### Lead N — <title>
- Type: pattern_removal | pattern_narrow | helper_filter
- File: gsc_core/gsc_detectors/gs021_csrf_ssrf.py
- Before: <exact lines from §2 being changed>
- After:  <exact replacement lines>
- Rationale: <1–2 sentences>
- FP removed: <count / which examples from §3>
- TP impact: <which §5 markers are affected, and why not>
- Verification: <expected result of: python3 gsc.py scan /tmp/gsc-calibration/werkzeug --ci --json | grep GS021 → should drop 25 → 0>
```

Targets, in priority order:

- **Lead 1 (97% of FP):** remove or narrowly re-scope the `localhost` INFO pattern.
  If you narrow it, the new regex MUST include an HTTP-client token
  (`requests|urllib|httpx|axios|fetch|got|curl|http\.client`) AND the localhost token, on the
  same logical line. Justify removal vs. narrowing — note the measurement shows 0 real TP
  even on pygoat, so **removal is the defensible default**; if you keep a narrowed form,
  state why.
- **Lead 2:** narrow the `f-string URL` pattern so `{...}` must contain a taint token
  (`request.`, `params[`, `req.query`, `req.body`, `req.params`, `user_input`, `input(`,
  `args.get`, `form.get`, `$_GET`, `$_POST`).
- **Lead 3 (optional, justify):** assess the `HTTP request to a variable` pattern — it fires
  on `requests.get(url)` for *any* variable. Propose a taint check or leave it; explain the
  TP risk (it fires 3× on pygoat SSRF lab).

---

## 8. Verification (run by the repo owner, not by you)

After applying proposals, the owner runs:

```bash
python3 gsc.py scan /tmp/gsc-calibration/werkzeug --ci --json   # GS021 25 → expected 0
python3 gsc.py scan /tmp/gsc-calibration/uvicorn   --ci --json  # GS021 8  → expected 0
python3 gsc.py scan /tmp/gsc-calibration/pygoat    --ci --json  # GS021 CSRF markers (@csrf_exempt etc.) MUST still fire
python3 -m pytest tests/ -q
```

State the **expected** delta for each, so the owner can confirm no TP loss. If you cannot
predict a delta from §2 alone, say so rather than guessing.
