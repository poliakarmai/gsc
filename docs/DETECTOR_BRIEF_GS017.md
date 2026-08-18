# Brief: Improve GS017 (Weak & Default Passwords) precision in GSC

> For an external AI agent (Claude Code / Codex / ChatGPT). **Self-contained** — the full
> detector source is embedded below, no repo access needed. Return only proposals in the
> format from §6.

---

## 1. Context

GSC is a self-learning SAST platform (Python, 42 detectors). Detectors are regex patterns +
context filters. **The current pain is precision, not recall**: on 10 real-world projects
(160–132K ⭐) the scan yields 2695 findings, precision CRITICAL ~8–12%. The goal is to remove
false positives (FP) **without losing** true positives (TP).

Detector GS017 flags Weak & Default Passwords (CWE-521): hardcoded default credentials,
weak password policies, short passwords in `.env`, weak DB connection strings, commented
passwords, weak hash algorithms (MD5/SHA1/crypt).

**Current state in the findings DB** (`~/.hermes/state/gsc_audit.db`): GS017 has **859
findings (852 HIGH, 6 CRITICAL, 1 LOW)** — it is the single noisiest detector after GS001.
The DB is *cumulative* (history across many scans), so many of these titles reflect bugs
already patched. A fresh self-scan on the GSC repo itself yields only **7 findings**, of
which **5 are the same FP** (`SECRET = "SECRET"` self-reference). Your job is to find what
*still* fires wrongly on real code and kill it.

## 2. Current detector code (change only patterns/filters, not the contract)

```python
# gs017_weak_passwords.py
# SPDX-License-Identifier: Apache-2.0
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS017"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Weak & default passwords — admin:admin, default creds, "
    "weak password policies, hardcoded DB passwords"
)

# ── Default credential pairs ─────────────────────────────────────────────────
DEFAULT_CREDS = re.compile(
    r'(?:^|\n)\s*'
    r'(?:'
    r'(?:admin|administrator|root|sa|postgres|mysql|guest|test|user|operator|manager|supervisor|support)'
    r')\s*[:=]\s*'
    r'[\'"](?:admin|password|passw0rd|123456|12345678|qwerty|root|test|guest|changeme|P@ssw0rd|'
    r'secret|default|temp|temp123|Welcome1|Summer202[0-9]|Winter202[0-9])[\'"]\s*',
    re.IGNORECASE,
)

# Connection strings with weak passwords
WEAK_DB_PASSWORDS = re.compile(
    r'(?:mongodb|mysql|postgres(?:ql)?|sqlite|oracle|mssql|redis)://'
    r'[^:]*:'
    r'(?:admin|password|root|123456|qwerty|test|guest|changeme|secret|passw0rd)'
    r'@',
    re.IGNORECASE,
)

# Docker ENV with weak password defaults
DOCKER_DEFAULT_PASSWORDS = re.compile(
    r'^\s*(?:ENV|ARG)\s+'
    r'(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|SA_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|'
    r'REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|ADMIN_PASSWORD|DEFAULT_PASSWORD)\s+'
    r'(?:admin|password|root|123456|qwerty|changeme|secret)\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Hardcoded passwords in variable assignments
HARDCODED_PASSWORD_VARS = re.compile(
    r'^\s*(?:PASSWORD|PASSWD|PASS|PWD|SECRET|ADMIN_PASS|DB_PASS|DB_PASSWORD|API_SECRET)'
    r'\s*[:=]\s*[\'"]([^\'"]{1,20})[\'"]\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Weak password policy (min length < 8, no complexity)
WEAK_PASSWORD_POLICY = re.compile(
    r'(?:min(?:imum)?[_\s]*(?:password|pwd)[_\s]*(?:length|len|size))\s*[:=]\s*([0-7])\b',
    re.IGNORECASE,
)

# .env files with short passwords (< 8 chars)
SHORT_ENV_PASSWORDS = re.compile(
    r'^\s*(?P<k>PASSWORD|PASS|PWD|SECRET|KEY)\s*=\s*[\'"]?(?P<v>[A-Za-z0-9_@#.\-]{1,7})[\'"]?\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Known weak password hashes (unsalted MD5, SHA1)
WEAK_HASH_ALGORITHMS = re.compile(
    r'\b(?:md5|sha1|crypt)\s*\(\s*[\'"]\$password[\'"]',
    re.IGNORECASE,
)

# Password in comments/documentation
COMMENTED_PASSWORDS = re.compile(
    r'^\s*(?:#|//|<!--|;)\s*'
    r'(?:password|пароль)\s*[:=]\s*\S+\s*$',
    re.IGNORECASE | re.MULTILINE,
)


def _is_placeholder(value: str) -> bool:
    """Filter out placeholder/example values."""
    return any(skip in value.lower() for skip in (
        '***', 'your-', 'changeme', 'placeholder', 'example',
        'test', 'xxxx', 'secrethere', 'put_your', 'replace',
        'ваш_', 'пример',
    ))


ENV_SENTINELS = frozenset({
    "none", "null", "nil", "true", "false", "undefined", "nan", "inf",
})


WEAK_VALUE_WORDS = frozenset({
    "admin", "admin123", "administrator", "root", "root123", "toor",
    "password", "password1", "password123", "pass", "passwd", "pwd",
    "passw0rd", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "secret", "secret123", "changeme", "default",
    "temp", "test", "test123", "guest", "demo", "demopassword",
    "letmein", "welcome", "welcome1", "iloveyou", "monkey", "dragon",
    "p@ssw0rd", "pa55word", "p@ssword",
    "master", "login", "abc123", "000000", "111111", "123123", "654321",
    "football", "baseball", "superman", "batman", "sunshine", "princess",
})


def _is_weak_value(value: str) -> bool:
    """True if `value` plausibly looks like a WEAK/default password."""
    v = value.strip()
    if not v:
        return False
    low = v.lower()
    if low in ENV_SENTINELS:
        return False
    if low in WEAK_VALUE_WORDS:
        return True
    if v.isdigit():
        return True
    if len(v) > 12:
        return False
    if len(v) < 8:
        return True
    if v.isalpha() and (v.islower() or v.isupper()):
        return True
    if re.fullmatch(r"[a-z]+[0-9]{1,4}", low):
        return True
    return False


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS017" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
                       ".env", ".toml", ".yaml", ".yml", ".json", ".cfg",
                       ".ini", ".conf", ".cnf", ".xml", ".sh", ".bash",
                       ".sql", "Dockerfile", ".dockerfile")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Default credential pairs
        for match in DEFAULT_CREDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Default credentials: {match.group(0).strip()[:80]}",
                detail="Hardcoded default credential pair detected. Common in pentests.",
                fix_suggestion="Remove hardcoded credentials. Use secrets manager or env vars with strong unique passwords.",
                noise_tier="precise",
            ))

        # 2. Weak DB connection strings
        for match in WEAK_DB_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title="Database connection string with weak password",
                detail=f"Weak DB password in connection string: {match.group(0)[:100]}",
                fix_suggestion="Use strong randomly-generated passwords for all DB connections. Store in secure vault.",
                noise_tier="precise",
            ))

        # 3. Docker default passwords
        for match in DOCKER_DEFAULT_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Docker default password in ENV/ARG",
                detail=match.group(0).strip(),
                fix_suggestion="Use build-time secrets or docker secrets instead of hardcoded defaults.",
                noise_tier="precise",
            ))

        # 4. Hardcoded password variables (short + weak values only)
        for match in HARDCODED_PASSWORD_VARS.finditer(content):
            password_value = match.group(1)
            if _is_placeholder(password_value):
                continue
            if len(password_value) >= 20:
                continue
            if password_value.startswith("$"):
                continue
            if not _is_weak_value(password_value):
                continue
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Hardcoded password variable: {match.group(0).strip()[:100]}",
                detail=f"Password variable with short value ({len(password_value)} chars).",
                fix_suggestion="Move to secure secrets manager. Use env vars with fallback to generated secrets.",
                noise_tier="normal",
            ))

        # 5. Weak password policy
        for match in WEAK_PASSWORD_POLICY.finditer(content):
            min_len = int(match.group(1))
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Weak password policy: min length = {min_len}",
                detail=f"Password minimum length set to {min_len} (PCI-DSS requires 8+, ASVS 12+).",
                fix_suggestion="Enforce minimum 12 characters with complexity requirements per ASVS V2.1.",
                noise_tier="normal",
            ))

        # 6. Short .env passwords — only for .env-named files
        if ".env" in fp.name.lower():
            for match in SHORT_ENV_PASSWORDS.finditer(content):
                env_value = match.group("v")
                env_key = match.group("k").lower()
                if len(env_value) < 5:
                    if env_value.lower() in ENV_SENTINELS:
                        continue
                    if env_value.lower() == env_key:
                        continue
                    findings.append(Finding(
                        rule_id=RULE_ID, file_path=rel_path,
                        line=_lineno(content, match.start()),
                        severity="HIGH",
                        title=f"Very short password in .env: {match.group(0).strip()[:80]}",
                        detail=f"Password length = {len(env_value)} chars.",
                        fix_suggestion="Use minimum 20+ character random passwords for all secrets.",
                        noise_tier="precise",
                    ))

        # 7. Commented passwords
        for match in COMMENTED_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="LOW",
                title="Password visible in comment",
                detail=match.group(0).strip(),
                fix_suggestion="Remove passwords from comments. Use references to secrets manager.",
                noise_tier="normal",
            ))

        # 8. Weak hash algorithms for passwords
        for match in WEAK_HASH_ALGORITHMS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Weak password hashing algorithm (MD5/SHA1/CRYPT)",
                detail=match.group(0).strip(),
                fix_suggestion="Use bcrypt, argon2id, or scrypt for password hashing.",
                noise_tier="precise",
            ))

    return findings
```

## 3. Metric — what counts as "better"

- **Primary: precision** = TP/(TP+FP). Remove FP **without losing TP**.
- **Guard:** any narrowing/disabling of a pattern is acceptable only if TP cases still fire.
- Recall (new patterns) is secondary, and only after precision is stable.

## 4. Known FP candidates (leads — verify and confirm/refute each)

These are ordered by observed impact. Examples are real.

### A. Self-reference placeholder `SECRET = "SECRET"` (highest confirmed FP rate)
`HARDCODED_PASSWORD_VARS` fires on `SECRET = "SECRET"`, `PASSWORD = "password"`,
`API_SECRET = "api_secret"`, etc. — a value that equals its own key is a placeholder/stub,
not a real credential. Note `SHORT_ENV_PASSWORDS` *already* has a self-reference filter
(`if env_value.lower() == env_key: continue`), but `HARDCODED_PASSWORD_VARS` does **not**.
- Real FP example (5 identical hits in one self-scan):
  `benchmark/real_world/fastapi-users/examples/sqlalchemy/app/users.py` → `SECRET = "SECRET"`
- Fix direction: add `if password_value.lower() == matched_key.lower(): continue`. Requires
  capturing the key (currently only group(1) = value is captured).

### B. Test/demo/fixture corpora are not excluded
GS017 scans `benchmark/real_world/*`, `calibration/repos/*` (which contains a deliberately
vulnerable `secrets-demo`), and `examples/*`. `get_source_files()` excludes `tests`/`fixtures`
via `TEST_GLOBS`, but **not** `benchmark`, `calibration`, `examples`. Sibling detectors
(e.g. GS037) carry an `EXCLUDE_PATH_RE` with `benchmark|tests?|fixtures?|examples?`.
- Real examples: `calibration/repos/secrets-demo/config.py` (CRITICAL, intentional vuln),
  `benchmark/real_world/piccolo-api/e2e/pages.py` (`PASSWORD = "piccolo123"`).
- Fix direction: add a path-exclusion for `benchmark`, `calibration`, `examples` (mirror GS037).

### C. `SHORT_ENV_PASSWORDS` — the historical mass-producer of HIGH
The DB shows these top titles (note: some already fixed, verify against a *fresh* run):
- `key=key` (39) — self-reference (filter exists, but `key=s,`, `key = (`, `key="("` variants slip)
- `key = (` (14) — empty/paren value
- `password = None` (8), `key = None` (7), `pwd = None` (6) — sentinels (filter exists)
- `key="$1"` (6) — shell positional param; `HARDCODED_PASSWORD_VARS` rejects `startswith("$")`
  but `SHORT_ENV_PASSWORDS` does **not**
- The key token `KEY` is too generic: `key=…`, `monkey=…`, `turkey=…` all match `KEY`.

### D. `HARDCODED_PASSWORD_VARS` long/mixed values
`SuperSecret500!`, `SuperSecret3000!` etc. appear in DB history. `_is_weak_value` already
rejects `len>12` mixed-case — confirm these no longer fire; if any slip (e.g. exactly 12 chars
mixed-case), tighten the boundary.

### E. `COMMENTED_PASSWORDS` (LOW, minor)
Matches `# password: xxx` and the Russian `# пароль: xxx`. In README/docs this is noise, but
severity is LOW and volume is tiny — deprioritize unless trivial.

## 5. Your task

Analyze the code above. For each candidate in §4 (and any OTHER FP you notice) propose a
concrete fix. Three allowed tools (in order of preference):

1. **Path exclusion** — add to a path/glob exclusion (tests, samples, benchmark, vendor).
2. **Regex narrowing** — require more context in the pattern itself.
3. **Context analysis** — extend a `_is_false_positive`-style filter (±3 lines / key capture).

## 6. Response format (strict)

For each proposal, one block:

```
### GS017: <name>
- Type: path_exclusion | regex_narrowing | context_analysis
- Pattern/code: <concrete regex or diff>
- Rationale: why it's an FP (file/line example)
- FP it removes: <real code line>
- TP impact: which TP cases are NOT affected
```

## 7. Do NOT do

- ❌ Do not change `RULE_ID`, the severity scale, the `detect()` signature, or `Finding` keys.
- ❌ Do not disable the detector wholesale — only filters.
- ❌ Do not "clean up" code beyond the task (scope discipline).
- ❌ Do not propose without FP examples (can't assess risk/benefit).
- ❌ Do not add new weak-password *detection* (recall) — this is a precision pass only.

## 8. Verification procedure (run before claiming a fix)

```bash
cd ~/gsc
# Fresh FP slice — do NOT trust the historical DB for "is it still firing"
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from pathlib import Path
from gsc_detectors import AuditContext
from gsc_detectors import gs017_weak_passwords as g17
for root in ('.', str(Path.home()/'bybit-ws')):
    ctx = AuditContext(project='x', path=Path(root)); ctx.files = ctx.get_files()
    fs = g17.detect(ctx)
    print(root, '->', len(fs), 'findings')
    for f in fs[:20]:
        print('  ', f.get('severity'), f.get('file_path'), f.get('title'))
PY

# smoke
python3 /tmp/gs017_smoke.py

# full suite (306) + standalone regression/compliance
python3 -m pytest -q
python3 tests/test_regression.py
python3 tests/test_compliance_secrets.py
```

Pitfalls:
- `Finding` is dict-like: `severity=`/`category=` (same), `file_path`/`line_number`/`detail`
  (NOT `file=`/`message=`). Emit both where a bridge expects one.
- `get_files()` filters non-code + dotfiles; `get_source_files()` further drops tests/fixtures.
- `test_regression.py` / `test_compliance_secrets.py` are standalone — run with `python3 tests/…`,
  not `pytest`.
- **Commit only on explicit instruction** — the repo owner gates all commits.
