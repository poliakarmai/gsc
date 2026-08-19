# Brief: Kill GS000-LEGACY noise (61% of all FP) in GSC

> For an external AI agent (Claude Code / Codex / ChatGPT). **Self-contained** — the full
> relevant source is embedded below, no repo access needed. Return only proposals in the
> format from §6.

---

## 1. Context

GSC is a self-learning SAST platform (Python, 42 detectors). Detectors are a mix of
structured modules (`gsc_core/gsc_detectors/gsXXX_*.py`) and a **legacy pattern layer**
(grep-style patterns stored in SQLite `~/.hermes/state/gsc_audit.db`). The structured
detectors are mostly clean; **the legacy layer is the dominant noise source.**

Fresh precision measurement (13 calibration projects — 4 vulnerable + 9 clean, plus 2
fresh zero-star projects), run 2026-08-19:

| Layer | Findings on clean projects | Share |
|-------|---------------------------|-------|
| **GS000-LEGACY** | **330** | **61%** |
| GS021 (CSRF/SSRF) | 39 | 7% |
| GS020 (XSS) | 33 | 6% |
| GS037 (path-traversal variants) | 21 | 4% |
| everything else | 116 | 22% |
| **Total FP** | **539** | 100% |

`GS000-LEGACY` is **not a single detector** — it is the catch-all bucket that
`_derive_rule_id()` returns when a legacy pattern's title matches no known rule. On a
clean project every one of its 330 hits is a false positive by construction. Breaking
down those 330 hits by title (starlette + rich, two clean repos):

- `Python: assert in production` — **144** (96 in starlette, 48 in rich)
- `Generic code smell #NN` — ~30 (auto-generated, one per code-smell archetype)
- `CVE-2026-XXXXX: Path traversal / Buffer overflow / …` — ~5 (NVD collector patterns with an empty detector)
- `Хардкод IP адреса` (hardcoded IP) — ~3
- `World-readable file: <name> (664)` — ~4 (echelon-2 file-permission check)

The goal of this brief is **precision only**: remove / reclassify the quality-pattern and
over-broad NVD-CVE noise in the legacy layer **without** losing the legitimate security
patterns that also live there (`pickle.load`, `eval/exec`, `os.system`, SQLi f-strings,
hardcoded credentials).

## 2. Current code (change only patterns/filters, not the contract)

### 2.1 `_derive_rule_id()` — the fall-through that produces `GS000-LEGACY`

```python
# gsc_cli/main.py
def _derive_rule_id(pattern: dict) -> str:
    """Derive rule_id for legacy pattern-based findings."""
    title = (pattern.get("title") or "").lower()
    if "sql" in title: return "GS005"
    if "xss" in title: return "GS020"
    if "secret" in title or "credential" in title or "token" in title or "encrypt" in title or "exposed" in title or "hardcoded" in title: return "GS029"
    if "eval" in title: return "GS008"
    if "pickle" in title or "deserial" in title: return "GS037"
    if "except" in title: return "GS010"
    # NB: "assert" is a generic Python anti-pattern, NOT payment abuse — let it
    # fall through to GS000-LEGACY rather than polluting GS018 (DETECTOR_BRIEF_GS018.md, Лид 1).
    if "docker" in title or "container" in title: return "GS031"
    # NB: "permission"/"world-readable"/"writable" (file-perm) and "cve" (SCA/CVE)
    # are NOT AI-provenance — let them fall through to GS000-LEGACY rather than
    # polluting GS025 (DETECTOR_BRIEF_GS025.md, Лид 1).
    return "GS000-LEGACY"
```

### 2.2 Seed patterns that feed the legacy layer

```python
# gsc_cli/main.py — generate_seed_patterns()
# OWASP Top 10 (2021)
owasp = [
    ("Broken Access Control", "A01", 2, "CRITICAL", "chmod: World-readable configs", "regex", r"chmod.*[0-7][4-7][4-7]"),
    ("Cryptographic Failures", "A02", 2, "CRITICAL", "Hardcoded encryption key", "regex", r"\b(?:key|secret|password|token)\b\s*=\s*['\"][^'\"]{8,}['\"]"),
    ("Injection", "A03", 1, "CRITICAL", "SQL injection risk: f-string in query", "regex", r"""f['"].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*(?:\*\s*FROM|=\s*[{\'\"$]|\b(?:WHERE|SET|INTO|VALUES|JOIN)\b)"""),
    ("Insecure Design", "A04", 3, "HIGH", "Missing rate limiting", "semantic", r"def (handler|endpoint|route).*:.*\n(?!.*rate)"),
    ("Security Misconfiguration", "A05", 2, "HIGH", "Debug mode enabled", "regex", r"DEBUG\s*=\s*True|debug\s*=\s*true"),
    ("Vulnerable Components", "A06", 2, "MEDIUM", "Outdated dependency pattern", "regex", r"(requirements\.txt|pyproject\.toml|package\.json)"),
    ("Auth Failures", "A07", 2, "CRITICAL", "Weak password validation", "regex", r"min_length\s*=\s*[0-7]"),
    ("Software/Data Integrity", "A08", 3, "HIGH", "Missing signature verification", "semantic", r"json\.loads\(.*\)(?!.*verify|.*validate)"),
    ("SSRF", "A10", 2, "HIGH", "User-controlled URL in request", "regex", r"requests\.(get|post)\(.*format\(|requests\.(get|post)\(.*f['\"]"),
]

# Python-specific patterns  (← THE QUALITY NOISE LIVES HERE)
python_patterns = [
    (1, "HIGH",   "Unused import", "regex", r"^import \w+\s*$.*(?!.*\b\w+\b)"),
    (1, "MEDIUM", "Missing docstring", "regex", r"^def \w+\(.*\):\s*$\n\s+(?!\"\"\"|''')"),
    (1, "MEDIUM", "Bare except:", "regex", r"except\s*:"),
    (1, "MEDIUM", "Python: assert in production", "regex", r"\bassert\s"),          # ← 144 FP
    (2, "HIGH",   "eval() or exec() usage", "regex", r"\beval\(|\bexec\("),
    (2, "CRITICAL", "pickle.load() — unsafe deserialization", "regex", r"pickle\.(load|loads)\("),
    (2, "HIGH",   "os.system() without sanitization", "regex", r"os\.system\(.*format\(|os\.system\(.*f['\"]"),
    (2, "MEDIUM", "Hardcoded IP address", "regex", r"\b(?!127\.)(\d{1,3}\.){3}\d{1,3}\b"),  # ← quality
    (2, "HIGH",   "API key in git history", "semantic", r"(ghp_|sk-|xai-|eyJ).{10,}"),
    (3, "HIGH",   "Race condition: check-then-act", "semantic", r"if.*exists\(\):.*\n.*(open|read|write|remove)"),
    (3, "MEDIUM", "No timeout on network call", "regex", r"requests\.(get|post|put|delete)\((?!.*timeout)"),
    (3, "MEDIUM", "Missing fcntl/flock on file write", "semantic", r"with open\(.*w.*\)(?!.*flock|.*fcntl)"),
    (3, "LOW",    "float division without zero-check", "regex", r"/ (?!.*== 0|.*!= 0|.*> 0|.*else)"),
]
```

### 2.3 NVD/CVE collector — over-broad CVE patterns with empty detector

```python
# _cron_collect.py — CVE_PATTERN_MAP  (also mirrored in _cron_nvd.py, gsc_cli/gsc_collect_light.py)
# Tuple: (match_re, title, slug, detector, pattern_regex)
CVE_PATTERN_MAP = [
    (re.compile(r"hard[\s-]?coded\s+(password|secret|key|token|credential)", re.I),
     "Hardcoded credential", "hardcoded-secret", "GS001", r"(?:password|secret|key|token)\s*=\s*[\"']"),
    (re.compile(r"SQL\s+injection", re.I),
     "SQL injection", "sql-injection", "GS005", r"f[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b"),
    (re.compile(r"(?:command|OS\s+command)\s+injection", re.I),
     "Command injection", "command-injection", "GS004", r"(?:os\.system|subprocess\.\w+\s*\(\s*[^)]*shell\s*=\s*True)"),
    (re.compile(r"(?:path|directory)\s+traversal", re.I),
     "Path traversal", "path-traversal", "", r"(?:\.\./|\.\.\\)"),          # ← empty detector → GS000-LEGACY
    (re.compile(r"(?:deserialization|deseriali[sz]e|pickle|unserialize)", re.I),
     "Insecure deserialization", "deserialization", "GS004", r"(?:pickle\.loads?|yaml\.load\s*\()"),
    (re.compile(r"cross[\s-]?site\s+scripting|XSS", re.I),
     "Cross-site scripting (XSS)", "xss", "", r"(?:innerHTML|document\.write\s*\()"),   # ← empty
    (re.compile(r"SSRF|server[\s-]?side\s+request\s+forgery", re.I),
     "Server-side request forgery (SSRF)", "ssrf", "", r"(?:requests\.\w+\s*\(\s*(?:url|f[\"']))"),  # ← empty
    (re.compile(r"authentication\s+bypass|auth\s+bypass", re.I),
     "Authentication bypass", "auth-bypass", "GS011", r"(?:verify\s*=\s*False|alg\s*:\s*[\"']none[\"'])"),
    (re.compile(r"buffer\s+overflow|buffer\s+overrun", re.I),
     "Buffer overflow", "buffer-overflow", "", r"(?:strcpy|strcat|sprintf|gets\s*\()"),  # ← empty
    (re.compile(r"use[\s-]?after[\s-]?free|UAF", re.I),
     "Use-after-free", "use-after-free", "", ""),
    (re.compile(r"(?:privilege|privesc)\s+escalation", re.I),
     "Privilege escalation", "privilege-escalation", "GS014", r"(?:sudo|NOPASSWD|chmod\+s)"),
    (re.compile(r"(?:information|data)\s+(?:disclosure|exposure|leak)", re.I),
     "Information disclosure", "info-disclosure", "GS014", r"(?:SECRET_KEY|password|token)\s*=\s*[\"']"),
]
```

These run on a cron, take a real CVE id from NVD, and write a pattern whose `title` is
`"CVE-2026-56233: Path traversal"` with `pattern_regex = r"\.\./|\.\.\\"`. Because the
`detector` field is empty, `_derive_rule_id()` maps it to `GS000-LEGACY`. The regex is so
broad it flags *any* `../` in source (relative imports, os.path joins, doc examples).

### 2.4 Where legacy patterns are applied

```python
# gsc_cli/main.py — check_source_driven() (echelon 1)
def check_source_driven(project: str, path: Path) -> list[dict]:
    findings = []
    patterns = load_patterns(project, echelon=1)
    for p in patterns:
        if p.get("pattern_type", "regex") not in ("grep", "regex"):
            continue
        search_pattern = p.get("search_pattern", "")
        if not search_pattern:
            continue
        p_lang = p.get("language", "") or infer_lang_from_title(p.get("title", ""))
        file_types = lang_to_rg_types(p_lang) if p_lang else None
        for fpath, line_no, matched in _pattern_search(search_pattern, path, file_types):
            rule_id = _derive_rule_id(p)
            snippet = matched[:200]
            finding_key = hashlib.sha256(f"{rule_id}{fpath}{snippet}".encode()).hexdigest()[:12]
            category = p.get("category", "MEDIUM")
            findings.append({
                "finding_key": finding_key, "rule_id": rule_id, "category": category,
                "echelon": 1, "title": p["title"], "file_path": fpath,
                "line_number": line_no, "detail": p.get("description", ""),
                "pattern_title": p["title"],
            })
    return findings
```

`load_patterns()` reads from the `patterns` table first (project-scoped or `project='*'`),
falling back to seed files + `generate_seed_patterns(200)` when the table is empty. **It
does NOT filter on the `active` / `noise_tier` columns** — those exist in the schema
(`active INTEGER DEFAULT 1`, `noise_tier TEXT DEFAULT 'normal'`, `deactivated_at TEXT`)
but are only surfaced by `cmd_patterns_review()`, never applied during scanning.

## 3. Metric — what counts as "better"

- **Primary: precision.** Reduce `GS000-LEGACY` findings on the 9 clean calibration
  projects from **330** to **< 50**, ideally < 30. (By construction every hit on a clean
  project is FP, so the count *is* the FP count.)
- **Guard:** the security patterns in the legacy layer must still fire — verify these TPs
  remain after any change: `pickle.load(`, `eval(`/`exec(`, `os.system(` with f-string,
  SQLi f-string (`f"SELECT … {x}"`), `Hardcoded encryption key`, `Weak password
  validation`, `Debug mode enabled`.
- **Recall is out of scope** — this is a precision pass only. Do not add new detections.

## 4. Known FP candidates (leads — verify and confirm/refute each)

Ordered by observed impact. Examples are real (from the 2026-08-19 measurement).

### A. `Python: assert in production` (144 FP — the single biggest one)
`r"\bassert\s"` (main.py `python_patterns`) matches **any** `assert` statement.
`assert` is a standard, ubiquitous Python idiom (invariants, contract checks, type
narrowing in libraries like starlette/rich). It is a *code-style* opinion, not a security
vulnerability — and it is already deliberately excluded from GS018 (see comment in
`_derive_rule_id`). It belongs in a `noise_tier='quality'` bucket (or removed), not in
security output.
- Real examples: `starlette/routing.py` (96 hits), `rich/_console.py` (48 hits).
- Fix direction: drop the pattern from `python_patterns` **and** delete/reclassify it in
  the DB (`patterns` table), OR keep it but emit with `noise_tier='quality'` and filter
  that tier out of the security report.

### B. `Generic code smell #NN` (~30 FP)
Auto-generated one-off patterns (likely from a self-learning/LLM pass). Each fires on a
single arbitrary snippet and adds no security value. These are pure noise.
- Fix direction: identify the generator and stop it from seeding these into `patterns`;
  for existing rows, deactivate (`active=0`) or delete.

### C. NVD-CVE patterns with an empty detector (~5 FP, high blast radius)
`CVE-2026-56233: Path traversal` (`r"\.\./|\.\.\\"`), `CVE-2026-54696: Buffer overflow`
(`strcpy|strcat|sprintf|gets`), and the XSS/SSRF/UAF entries in `CVE_PATTERN_MAP` whose
`detector` is `""`. Attaching a real CVE id to a 2-char regex is misleading and produces
`GS000-LEGACY` hits on almost any repo with C code or relative paths.
- Fix direction: give these a proper `detector` (GS037 / GS020 / GS021) so they land in a
  structured, context-aware detector **or** drop the over-broad ones entirely. A CVE id
  must not be emitted without real CWE/mitigation context.

### D. `Hardcoded IP address` (~3 FP)
`r"\b(?!127\.)(\d{1,3}\.){3}\d{1,3}\b"` matches any IPv4 literal in strings, comments,
fixtures, doc examples — not only real hardcoded endpoints. Low volume but a genuine
quality-vs-security blur.
- Fix direction: require assignment/connect context (e.g. `host\s*=\s*['"]\d{1,3}(\.\d{1,3}){3}`)
  or move to `noise_tier='quality'`.

### E. `World-readable file: <name> (664)` (~4 FP)
`_perm_finding()` (echelon-2) flags any `data/` / `.local/share` file with world-readable
bits. On clean repos it hits `faq.yml`, `.pre-commit-config.yaml`, `.readthedocs.yml`,
`asv.conf.json` — config/docs files that legitimately live world-readable.
- Fix direction: restrict the sensitive-suffix set (drop `.yml`/`.yaml`/`.json` config
  files; keep `.env`, `.key`, `.pem`, `.db`) or drop the severity below report threshold.

## 5. Your task

Analyze the code above. For each candidate in §4 (and any other FP you notice) propose a
concrete fix. Three allowed tools (in order of preference):

1. **Pattern removal / deactivation** — drop a seed pattern from `generate_seed_patterns`
   (and mirror the DB via `DELETE` / `active=0`), or stop a generator from seeding it.
2. **Regex narrowing** — require more context in the pattern itself (e.g. assignment
   context for IP, taint for path traversal).
3. **Tier filtering** — use the existing `noise_tier` column: emit `noise_tier='quality'`
   on quality patterns and add a filter in `check_source_driven`/`check_security` so that
   `quality`-tier findings are dropped (or downgraded to INFO) from security reports.

## 6. Response format (strict)

For each proposal, one block:

```
### GS000-LEGACY: <name>
- Type: pattern_removal | regex_narrowing | tier_filtering
- Pattern/code: <concrete regex or diff>
- Rationale: why it's an FP (file/line example)
- FP it removes: <real code line>
- TP impact: which security patterns are NOT affected
```

## 7. Do NOT do

- ❌ Do not change `_derive_rule_id()`'s mapping for the security titles (SQL/XSS/secret/
  eval/pickle/except/docker) — only the quality fall-through behaviour.
- ❌ Do not disable the whole legacy layer — only the noise patterns.
- ❌ Do not "clean up" code beyond the task (scope discipline).
- ❌ Do not propose without FP examples (can't assess risk/benefit).
- ❌ Do not add new detection patterns (recall) — this is a precision pass only.
- ❌ Do not touch structured detectors in `gsc_core/gsc_detectors/gsXXX_*.py`.

## 8. Verification procedure (run before claiming a fix)

```bash
cd ~/gsc
# Fresh FP slice on clean repos — do NOT trust the historical DB for "is it still firing"
python3 - <<'PY'
import sys, subprocess, json
from collections import Counter
for name, d in [('starlette','/tmp/gsc-calibration/starlette'),
                ('rich','/tmp/gsc-calibration/rich')]:
    r = subprocess.run([sys.executable,'gsc.py','scan',d,'--ci','--json'],
                       capture_output=True, text=True)
    items = json.loads(r.stdout)
    items = items.get('findings', items) if isinstance(items, dict) else items
    leg = [f for f in items if f.get('rule_id')=='GS000-LEGACY']
    c = Counter(f.get('title','?') for f in leg)
    print(name, '->', len(leg), 'GS000-LEGACY')
    for t,n in c.most_common(8): print('  ', n, t)
PY

# Guard: security patterns still fire (must stay non-zero)
python3 - <<'PY'
import sys, subprocess, json
r = subprocess.run([sys.executable,'gsc.py','scan','/tmp/gsc-calibration/pygoat','--ci','--json'],
                   capture_output=True, text=True)
items = json.loads(r.stdout)
items = items.get('findings', items) if isinstance(items, dict) else items
need = {'GS005','GS020','GS007','GS004','GS029','GS001','GS037'}
present = {f.get('rule_id') for f in items}
print('security rules still firing:', sorted(need & present))
PY

# full suite + standalone regression/compliance
python3 -m pytest -q
python3 tests/test_regression.py
python3 tests/test_compliance_secrets.py
```

Pitfalls:
- `Finding` is dict-like: `severity=`/`category=` (same), `file_path`/`line_number`/`detail`
  (NOT `file=`/`message=`).
- `load_patterns()` reads the DB **first** — editing `generate_seed_patterns` alone has no
  effect until the DB row is also removed/reclassified (`DELETE` or `UPDATE … SET active=0`),
  and note `load_patterns()` does **not** filter `active=0` today.
- `test_regression.py` / `test_compliance_secrets.py` are standalone — run with
  `python3 tests/…`, not `pytest`.
- **Commit only on explicit instruction** — the repo owner gates all commits.
