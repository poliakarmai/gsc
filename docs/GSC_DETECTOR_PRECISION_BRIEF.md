# GSC Detector Precision Brief — self-contained (no repo access required)

> **Goal:** find and fix false-positive (FP) noise in GSC detectors. You must
> return precise, reviewable edits (diff blocks) that reduce FP **without losing
> true positives (recall)**. This brief embeds the full source of every detector,
> the exact `Finding`/`AuditContext` contract, the FP evidence already measured,
> and hard anti-hallucination rules.

---

## 0. What you must deliver

For each noisy detector, produce a self-contained edit proposal with:

- **Which file** and **which pattern/loop** is producing the FP (trace it, don't guess).
- **Before / After** code (exact diff).
- **Rationale** — why the match is NOT a vulnerability.
- **FP-removed** — expected delta on the clean projects (concrete numbers).
- **TP-impact** — proof the real vulnerability cases still match.
- **Verification** — the exact scan command and the expected result.

**You do NOT have repo access.** Everything you need is in this file. If you need
a symbol or file that is not in §3, write `UNKNOWN:<name>` and ask for it — do not
invent it.

---

## 1. Context — precision already measured

Fresh scan (2026-08-20) of 10 real open-source projects, `--ci` (regex-only):

| Metric | Value |
|---|---|
| Total findings | 506 |
| CRITICAL | ~27 |
| HIGH | ~218 |

Manual verification of every CRITICAL found **~0 real vulnerabilities** — nearly
all are FP. The measured FP causes (your hunting map):

| # | FP cause | Example (project / file:line) |
|---|---|---|
| 1 | **Docstring example** matched as code | loguru `_logger.py:1607` `>>> record = pickle.loads(pipe.read())` |
| 2 | **Public test keys** flagged as secrets | piccolo-api `captcha.py:57` hCaptcha `0x0000…` / `10000000-…` |
| 3 | **Parameterized query** seen as SQLi | piccolo-api `crud/endpoints.py:491` `.raw(sql, f"%{search_term}%")` |
| 4 | **Fixed subprocess args** as cmd-injection | youtube-dl `YoutubeDL.py:429` `['bidiv'] + width_args` |
| 5 | **JS operator** as SQL keyword | youtube-dl `openload.py:86` `delete window._phantom` |
| 6 | **Bare word `key`** as crypto secret | pendulum `formatter.py:351` `key = "translations.day_periods"` |
| 7 | **Abstract method / aggregate marker** | piccolo-api `mfa/provider.py:40` `@abstractmethod send_code` |
| 8 | **Fake CVE / extractor API token** | httpie `man_pages.py:21` `os.system == 'nt'` (comparison) |

Some of these are already patched (see §5 "already fixed"). Your job is to find
the **remaining** noise, including patterns not yet listed here, across all
detectors and all severity levels (CRITICAL / HIGH / MEDIUM / LOW / INFO).

**Critical rule:** a finding that is real code matching an insecure-API name
(e.g. `pickle.loads`, `os.system`, `.execute(`) is **NOT** automatically a
vulnerability. It is only a vulnerability when **user-controlled / untrusted
input** reaches the sink. Regex detectors that match the sink without a taint
source are the #1 FP generator — treat "no taint ⇒ downgrade or suppress" as the
default fix, not "keep the pattern".

---

## 2. Contract (verbatim)

### Finding

```python
class Finding(dict):
    def __init__(self, rule_id, severity="MEDIUM", title="", file_path="",
                 line=0, detail="", fix_suggestion="", references=None,
                 noise_tier="normal", **kwargs):
        sev = kwargs.pop("category", severity)
        line_no = kwargs.pop("line_number", line)
        super().__init__(
            rule_id=rule_id, severity=sev, category=sev, title=title,
            file_path=file_path, line=line_no, line_number=line_no,
            detail=detail, fix_suggestion=fix_suggestion,
            references=references or [], noise_tier=noise_tier or "normal",
            **kwargs)
```

Supported extra keys (via `**kwargs`): `confidence`, `cwe`, `cvss`, `metadata`,
`snippet`, `secret_value`, `pattern_ids`, `finding_key`.

### AuditContext (key fields/methods detectors use)

```python
@dataclass
class AuditContext:
    project: str
    path: Path                       # absolute project root
    files: list[Path]
    file_contents: dict[str, str]
    skipped_detectors: set[str]
    MAX_SCAN_FILE_SIZE: int = 1_000_000
    def get_files(self, extensions=None) -> list[Path]
    def get_source_files(self, extensions=None) -> list[Path]  # excludes tests/non-code
    def read_file(self, filepath: Path) -> str
    def get_disabled_patterns(self, rule_id: str) -> set[str]
    def is_test_file(self, filepath: Path) -> bool
```

Most detectors iterate `ctx.get_source_files(...)` and call `ctx.read_file(fp)`.
A detector returns `list[Finding]`; returning `None` elements is allowed and the
registry filters them out.

---

## 3. Detectors — full embedded source
Each detector is a single module exporting `RULE_ID`, `ECHELON`, `NOISE_TIER`, `description`, and `detect(ctx) -> list[Finding]`.
**The code below is the ONLY source of truth. Do not invent signatures, DB columns, or helper functions not shown here.**

---

### GS001 — `gs001_hardcoded_secret.py` (echelon 1, noise_tier `normal`, 244 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS001 — Hardcoded secrets in source code.

Detects common patterns: API keys, tokens, passwords in string literals.
Inspired by OWASP CVE Lite OA001-orphaned-target pattern.

v1.1 — 26.06.2026: new patterns (GitHub, JWT, connection strings),
                  uses AuditContext.get_source_files() for test/non-code filtering.
"""

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS001"
ECHELON = 1

# ── Patterns ─────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, str]] = [
    # (regex, label)

    # API keys
    (r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Hardcoded API key"),
    (r'(?:access[_-]?key|ACCESS_KEY)\s*[:=]\s*["\'][A-Za-z0-9_\-]{10,}["\']', "Hardcoded access key"),

    # Secrets / tokens
    (r'(?:secret|SECRET)\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']', "Hardcoded secret"),
    (r'(?:token|TOKEN)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Hardcoded token"),
    (r'(?:private[_-]?key|PRIVATE_KEY)\s*[:=]\s*["\'][A-Za-z0-9+/=]{32,}["\']', "Hardcoded private key"),

    # Passwords
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),

    # Cloud / AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?:sk-[A-Za-z0-9]{32,})', "Stripe / OpenAI-style secret key"),

    # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', "GitHub personal access token"),
    (r'github[_-]?token\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "GitHub token in config"),

    # JWT tokens (eyJ... base64url-encoded header)
    (r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}', "Hardcoded JWT token"),

    # Connection strings
    (r'(?:mongodb|mysql|postgres(?:ql)?|redis|sqlite)://[^"\'\\s]{10,}', "Hardcoded connection string"),
    (r'(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*[:=]\s*["\'][^"\']{10,}["\']', "Hardcoded database URL"),

    # Generic credential prefixes in strings
    (r'"\s*(?:sk|pk|api|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\s*"', "Hardcoded credential prefix"),

    # Bearer / auth tokens in source
    (r'Bearer\s+[A-Za-z0-9_\-]{20,}', "Hardcoded Bearer token"),
    (r'Authorization\s*[:=]\s*["\']\s*Bearer\s+[A-Za-z0-9_\-]{10,}', "Hardcoded Authorization header"),

    # ── PCI-DSS: Card data patterns (2026 Fintech Pentest) ─────────────────
    # PAN — Primary Account Number (13-19 digits with Luhn-checkable structure)
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
     "Potential PAN (Primary Account Number) — PCI-DSS violation"),

    # CVV/CVC — 3-4 digit security code
    (r'(?:cvv|cvc|cid|cvv2|cvc2|cvn)[\s:=-]*["\']?\s*(\d{3,4})',
     "Potential CVV/CVC code — PCI-DSS violation"),

    # Track data (magnetic stripe) — %B...^...^...?... format
    (r'%[BDE][0-9]{1,19}\^[^^]{1,30}\^[0-9]{4}',
     "Potential Track 1/2 magnetic stripe data — PCI-DSS violation"),

    # Full card dump pattern (PAN|EXP|CVV in one block)
    (r'["\'][0-9]{13,19}\|[0-9]{2}/[0-9]{2}\|[0-9]{3,4}["\']',
     "Full card dump (PAN|EXP|CVV) — CRITICAL PCI-DSS violation"),

    # IBAN / bank account numbers in plain text
    (r'["\'][A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}["\']',
     "Potential IBAN/bank account number — financial data exposure"),
]


# ── False positive filters ──────────────────────────────────────────────────

def _is_placeholder(value: str) -> bool:
    """Filter out obvious placeholder values."""
    placeholders = ("***", "your-", "xxxx", "changeme", "replace_me", "TODO",
                    "{}{}", "%s%s", "__yt_dlp_token__",
                    "getpass.getpass",  # prompts user, not hardcoded
                    "min_length=", "max_length=",  # form/validator fields
                    "ImageField", "FileField",  # Django fields, not upload handlers
                    # Vendor test/integration keys (hCaptcha docs, Stripe test mode, etc.)
                    "00000000-", "aaaa-bbbb", "ffff-ffff",  # zero-padded / placeholder UUIDs
                    "0x0000000000000000000000000000000000000000",  # hCaptcha test secret
                    # Очевидные демо/тестовые пароли (не секреты)
                    "example-password", "test-password", "dummy-password",
                    "demo-password", "sample-password", "fake-password",
                    )
    if "{" in value and "}" in value:
        # f-string / template placeholder: password='{password}', token='{token}'
        return True
    return any(p in value.lower() for p in placeholders)


def _luhn_valid(number: str) -> bool:
    """Luhn checksum — mandatory on every real PAN (ISO/IEC 7812).

    Rejects 13-16 digit numeric identifiers (Brightcove player IDs, order IDs,
    timestamps) that start with 4/5/3/6 but are not payment card numbers.
    """
    digits = [d for d in number if d.isdigit()]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * 2 if i % 2 == 1 else int(d)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


# A value that is a pure UPPER_WITH_UNDERSCORES identifier is an enum/error-code
# constant, not a secret — e.g. TOKEN = "RESET_PASSWORD_BAD_TOKEN",
# PASSWORD = "REGISTER_INVALID_PASSWORD" (fastapi-users ErrorCode enum).
_SYMBOLIC_VALUE_RE = re.compile(r'[:=]\s*["\'][A-Z][A-Z0-9_]{3,}["\']')


def _is_symbolic_constant(matched: str) -> bool:
    """True when the secret value is an identifier-shaped symbolic constant."""
    return bool(_SYMBOLIC_VALUE_RE.search(matched))


# A UUID-shaped value is an identifier (hCaptcha/Stripe test tokens), not a secret.
_UUID_RE = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    re.IGNORECASE,
)


def _is_uuid(value: str) -> bool:
    """True when the matched value is a UUID-shaped identifier."""
    return bool(_UUID_RE.search(value))


# Valid ISO 3166-1 alpha-2 country codes that issue IBANs
_IBAN_COUNTRIES = frozenset({
    "AL", "AD", "AT", "AZ", "BH", "BY", "BE", "BA", "BR", "BG",
    "CR", "HR", "CY", "CZ", "DK", "DO", "EG", "SV", "EE", "FO",
    "FI", "FR", "GE", "DE", "GI", "GR", "GL", "GT", "HU", "IS",
    "IQ", "IE", "IL", "IT", "JO", "KZ", "XK", "KW", "LV", "LB",
    "LY", "LI", "LT", "LU", "MK", "MT", "MR", "MU", "MD", "MC",
    "ME", "NL", "NO", "PK", "PS", "PL", "PT", "QA", "RO", "RU",
    "LC", "SM", "ST", "SA", "RS", "SC", "SK", "SI", "ES", "SE",
    "CH", "TL", "TN", "TR", "UA", "AE", "GB", "VA", "VG",
})

_IBAN_MIN_LEN = 15
_IBAN_MAX_LEN = 34


def _is_valid_iban(candidate: str) -> bool:
    """Validate IBAN: country code + length + mod-97 checksum."""
    s = candidate.strip('"').strip("'").replace(" ", "").upper()
    if len(s) < _IBAN_MIN_LEN or len(s) > _IBAN_MAX_LEN:
        return False
    if s[:2] not in _IBAN_COUNTRIES:
        return False
    # mod-97: move first 4 chars to end, convert letters A=10..Z=35
    rearranged = s[4:] + s[:4]
    digits = "".join(
        str(ord(c) - 55) if "A" <= c <= "Z" else c
        for c in rearranged
    )
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


# ── Main detector ───────────────────────────────────────────────────────────

_EXCLUDE_PATHS_GS001 = re.compile(
    r'(?:/|^)(?:tests?|fixtures?|examples?|samples?|tutorials?|devscripts?|'
    r'docs?|demo|mock|e2e|extractors?|spiders?|crawlers?|'
    r'migrations?|__pycache__|node_modules|generated|dist|build)(?:/|$)', re.IGNORECASE)

_EXCLUDE_FILES_GS001 = re.compile(
    r'(?:^test_|_test\.|conftest\.|setup\.cfg|\.ini$)', re.IGNORECASE)


def detect(ctx: AuditContext) -> list[Finding]:
    """Scan all source files for hardcoded secrets."""
    if "GS001" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files():
        fpath = str(fp)
        if _EXCLUDE_PATHS_GS001.search(fpath):
            continue
        fname = fp.name
        if _EXCLUDE_FILES_GS001.search(fname):
            continue
        content = ctx.read_file(fp)
        for pattern, label in _SECRET_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched = m.group(0)
                if _is_placeholder(matched):
                    continue
                # IBAN validation: require valid country code + mod-97 checksum
                if "IBAN" in label and not _is_valid_iban(matched):
                    continue
                # PAN validation: require Luhn checksum (rejects numeric IDs)
                if "PAN" in label and not _luhn_valid(matched):
                    continue
                # Symbolic constants: enum/error-code values are not secrets
                if _is_symbolic_constant(matched):
                    continue
                # UUID-shaped identifiers are not secrets
                if _is_uuid(matched):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID,
                    category="CRITICAL",
                    title=label,
                    file_path=str(fp),
                    line_number=content[:m.start()].count("\n") + 1,
                    detail=f"Found: {matched[:80]}",
                    fix_suggestion=(
                        "Move this value to environment variables or a secret manager. "
                        "Use `os.getenv('KEY_NAME')` to read at runtime."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                    ],
                ))

    return findings


# ── Detector descriptor ─────────────────────────────────────────────────────

description = "Hardcoded secrets in source code (API keys, tokens, passwords, JWT, connection strings)"

```

---

### GS002 — `gs002_world_readable.py` (echelon 2, noise_tier `normal`, 91 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS002 — World-readable sensitive files.

Detects sensitive files (private keys, certs, credential stores) with
world-readable permissions. Public data (authorized_keys, known_hosts,
generic *.conf/*.config) and code modules (credentials.py) are NOT sensitive.
Inspired by CVE Lite OA002-floating-tag pattern.
"""

import stat
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS002"
ECHELON = 2

# Sensitive files whose content is a SECRET (not public config/code).
_SENSITIVE_PATTERNS = [
    # Private keys & certificates
    "*.pem", "*.key", "*.crt", "*.cer",
    "*.pkcs12", "*.pfx", "*.p12",
    # Environment / secret stores
    ".env", ".env.*",
    # SSH private keys (exact name — *.pub is public, not sensitive)
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    # Credential/secret DATA files (NOT code: credentials.py is a module)
    "credentials.json", "credentials.txt", "credentials.yml", "credentials.yaml",
    "credentials.env", "credentials.ini", "credentials.cfg",
    "secrets.json", "secrets.txt", "secrets.yml", "secrets.yaml",
    "secrets.env", "secrets.ini",
    # Config files that hold credentials by convention
    ".netrc", ".npmrc", ".pypirc", ".pgpass",
]

# Directories that hold test/demo/sample material (vectors, dummy servers, etc.)
_DEMO_DIRS = frozenset({
    "vectors", "dummyserver", "testdata", "dummy", "demo",
    "examples", "sample", "samples",
})


def _is_sensitive(filepath: Path) -> bool:
    """Check if file matches sensitive patterns."""
    for p in _SENSITIVE_PATTERNS:
        if filepath.match(p):
            return True
    return False


def detect(ctx: AuditContext) -> list[Finding]:
    """Check file permissions for sensitive files."""
    if "GS002" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_files():
        # Skip test/demo/vector directories — their certs/keys are expected readable
        if any(d in _DEMO_DIRS for d in fp.parts):
            continue
        if not _is_sensitive(fp):
            continue
        if ctx.is_test_file(fp):
            continue
        try:
            mode = fp.stat().st_mode
            # Check if world-readable (others have read)
            if mode & stat.S_IROTH:
                perms = stat.filemode(mode)
                findings.append(Finding(
                    rule_id=RULE_ID,
                    category="HIGH",
                    title="World-readable sensitive file",
                    file_path=str(fp),
                    detail=f"File {fp.name} has permissions {perms.strip()} — readable by any user.",
                    fix_suggestion=f"Run: chmod 600 {fp.name}  (or 640 for group access)",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/File_System_Security.html",
                    ],
                ))
        except OSError:
            pass

    return findings


description = "World-readable sensitive files (keys, certs, env files)"

```

---

### GS003 — `gs003_debug_prints.py` (echelon 1, noise_tier `normal`, 108 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS003 — Debug / diagnostic code left in production.

Detects print(), console.log, dump(), and other debug statements.
Inspired by CVE Lite OA005-nested-ineffective pattern.
"""

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS003"
ECHELON = 1

# Per-language patterns
_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "python": [
        (r'^\s*print\s*\(', "Python print() — debug leftover"),
        (r'^\s*pprint\s*\(', "Python pprint() — debug leftover"),
        (r'^\s*import\s+pdb\b', "Python debugger import (pdb)"),
        (r'^\s*breakpoint\s*\(\s*\)', "Python breakpoint()"),
        (r'^\s*import\s+ipdb\b', "Python ipdb import"),
    ],
    "javascript": [
        (r'console\.(?:log|debug|trace|dir)\s*\(', "JS console.log / debug"),
        (r'debugger\s*;?', "JS debugger statement"),
    ],
    "go": [
        (r'fmt\.(?:Println|Printf|Print)\s*\(', "Go fmt.Println / Printf — debug leftover"),
    ],
    "rust": [
        (r'dbg!\s*\(', "Rust dbg!() — debug leftover"),
        (r'println!\s*\(', "Rust println! — debug leftover"),
    ],
}

# Extensions mapping for languages
_LANG_EXTS = {
    "python": (".py", ".pyx", ".pyi"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "go": (".go",),
    "rust": (".rs",),
}


def _is_test_file(filepath: Path, ctx: AuditContext) -> bool:
    """Delegate to AuditContext's file classification."""
    return ctx.is_test_file(filepath)


def _is_cli_tool(content: str) -> bool:
    """Check if file is a CLI tool where print() is legitimate output."""
    cli_indicators = (
        r'import\s+argparse', r'import\s+click\b', r'import\s+typer\b',
        r'from\s+argparse\s+import', r'from\s+click\s+import',
        r'if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:',
        r'\.add_argument\s*\(', r'@click\.\w+',
        r'sys\.stdout\.write', r'logging\.basicConfig',
    )
    return any(re.search(p, content) for p in cli_indicators)


def detect(ctx: AuditContext) -> list[Finding]:
    """Find debug/diagnostic statements in production code."""
    if "GS003" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for lang, patterns in _PATTERNS.items():
        exts = _LANG_EXTS.get(lang, ())
        for fp in ctx.get_files(extensions=exts):
            if _is_test_file(fp, ctx):
                continue
            content = ctx.read_file(fp)
            if _is_cli_tool(content):
                continue  # print() is legitimate CLI output
            for pattern, label in patterns:
                for m in re.finditer(pattern, content, re.MULTILINE):
                    line_no = content[:m.start()].count("\n") + 1
                    # Skip if line has gsc:ignore
                    line_text = content.split("\n")[line_no - 1].strip()
                    if "gsc:ignore" in line_text:
                        continue
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="LOW",
                        title=label,
                        file_path=str(fp),
                        line_number=line_no,
                        detail=f"Line {line_no}: {line_text[:80]}",
                        fix_suggestion=(
                            "Replace with proper logging (logging.debug / logger.debug / slog). "
                            "Or add `# gsc:ignore` if intentional."
                        ),
                        references=[
                            "https://docs.python.org/3/howto/logging.html",
                        ],
                    ))

    return findings


description = "Debug / diagnostic statements left in production code"

```

---

### GS004 — `gs004_dangerous_subprocess.py` (echelon 2, noise_tier `normal`, 127 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS004 — Dangerous subprocess usage (command injection risk).

Detects:
- shell=True without input sanitization (shlex.quote)
- os.system() / os.popen() with formatted strings
- subprocess with user-controlled strings

Inspired by OWASP A03:2021 — Injection.
"""

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS004"
ECHELON = 2

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, title, fix hint)

    # Python: shell=True without shlex.quote
    (
        r'subprocess\.\w+\([^)]*shell\s*=\s*True',
        "subprocess with shell=True",
        "Use shell=False with list arguments, or wrap input with shlex.quote()",
    ),
    # Python: os.system() with formatted string
    (
        r'os\.system\s*\(\s*f["\']',
        "os.system() with f-string — command injection risk",
        "Replace with subprocess.run([...], shell=False)",
    ),
    (
        r'os\.system\s*\(\s*["\'][^"\']*%[sd]',
        "os.system() with %-formatting",
        "Replace with subprocess.run([...], shell=False)",
    ),
    (
        r'os\.system\s*\(\s*["\'][^"\']*\.format\(',
        "os.system() with .format() — command injection risk",
        "Replace with subprocess.run([...], shell=False)",
    ),
    # os.popen() — always uses shell
    (
        r'os\.popen\s*\(',
        "os.popen() — deprecated, uses shell",
        "Replace with subprocess.Popen([...], shell=False)",
    ),
    # commands.getoutput() — Python 2 legacy
    (
        r'commands\.(getoutput|getstatusoutput)\s*\(',
        "commands.getoutput() — deprecated shell wrapper",
        "Replace with subprocess.run([...], capture_output=True)",
    ),
    # subprocess with string (not list) — implicit shell on Windows
    (
        r'subprocess\.(call|run|Popen)\s*\(\s*["\'][^"\']+\$',
        "subprocess with string arg containing $variable",
        "Use list arguments to avoid shell expansion",
    ),
    # eval() on command strings
    (
        r'eval\s*\(\s*(?:input\(|.*f["\']|.*\.format\()',
        "eval() with dynamic input — code injection",
        "Never use eval() on user input. Use ast.literal_eval() or a parser.",
    ),
    # exec() on dynamic strings
    (
        r'exec\s*\(\s*(?!["\']{3})\w',
        "exec() on variable — code injection risk",
        "Avoid exec(); use explicit function calls or importlib",
    ),
]

# Static-literal command passed to shell=True / os.popen (no interpolation,
# concat, format, or $-var) is bad practice, not user-controlled injection.
_STATIC_SHELL = re.compile(
    r'(?:subprocess\.\w+\(\s*["\']|os\.popen\s*\(\s*["\'])'
    r'(?![\s\S]*(\$\{|["\']\s*\+|\{[a-zA-Z_]\w*\}|\.format\s*\(|%\s*\(|%[sd]))'
)


def detect(ctx: AuditContext) -> list[Finding]:
    """Find dangerous subprocess/shell usage in source code."""
    if "GS004" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files(extensions=(".py",)):
        content = ctx.read_file(fp)
        for pattern, title, fix in _PATTERNS:
            for m in re.finditer(pattern, content, re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue
                severity = "HIGH"
                # shell=True / os.popen with a static literal command is bad
                # practice, not user-controlled command injection → downgrade.
                if ("shell" in pattern or "popen" in pattern) and _STATIC_SHELL.search(line_text):
                    severity = "MEDIUM"
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity=severity,
                    title=title,
                    file_path=str(fp),
                    line=line_no,
                    detail=f"Line {line_no}: {line_text[:100]}",
                    fix_suggestion=fix,
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
                        "https://docs.python.org/3/library/subprocess.html#security-considerations",
                    ],
                ))

    return findings


description = "Dangerous subprocess/shell usage (command injection, shell=True, os.system, eval)"

```

---

### GS005 — `gs005_sql_injection.py` (echelon 2, noise_tier `precise`, 394 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GS005 — SQL/NoSQL Injection Detector (v2.0: pattern_id decomposition).

75 patterns across 9 languages. Each pattern has a unique pattern_id.
Per-pattern precision can be tracked and noisy patterns selectively disabled.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Finding
from .base import make_finding

# ── assign_ids (inlined for module-relative import) ────────────────────────

import re as _re

_TYPE_MAP = {
    "f-string": "FSTR", "format(": "FMT", "%.format": "FMT",
    "concat": "CONCAT", "$where": "NOSQL", "MongoDB": "NOSQL",
    "DynamoDB": "NOSQL", "Redis": "NOSQL",
    "Django": "ORM", "SQLAlchemy": "ORM", "Sequelize": "ORM",
    "Knex": "ORM", "Laravel": "ORM", "ActiveRecord": "ORM",
    "createQuery": "ORM", "JDBC": "JDBC", "Statement": "JDBC",
    "JPA": "JDBC", "Spring": "JDBC", "SqlCommand": "CSHARP",
}
_LANG_CODE = {"python": "PY", "javascript": "JS", "ruby": "RB",
              "php": "PHP", "java": "JAVA", "go": "GO",
              "csharp": "CS", "rust": "RS", "generic": "GEN"}


def _assign_ids(patterns):
    counters = {}
    result = []
    for regex, title, lang, needs_ctx in patterns:
        ptype = "GEN"
        for key, code in _TYPE_MAP.items():
            if key.lower() in title.lower():
                ptype = code; break
        lcode = _LANG_CODE.get(lang, "X")
        counters[(ptype, lcode)] = counters.get((ptype, lcode), 0) + 1
        pid = f"GS005-{ptype}-{lcode}-{counters[(ptype, lcode)]:03d}"
        result.append((pid, regex, title, lang, needs_ctx))
    return result

RULE_ID = "GS005"
ECHELON = 2
NOISE_TIER = "precise"
description = "GS005: SQL/NoSQL injection — 75 patterns, 9 languages, per-pattern precision tracking (v2.0)"

# ── User input sources for context filtering ───────────────────────────────

_USER_INPUT_SOURCES = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE|headers)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data|params)\s*\()',
    re.IGNORECASE,
)

_SQL_KEYWORDS = re.compile(
    r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|FROM|WHERE|'
    r'JOIN|INTO|SET|VALUES|TABLE|UNION|ORDER\s+BY|GROUP\s+BY|'
    r'HAVING|LIMIT|OFFSET|EXEC|EXECUTE)\b',
    re.IGNORECASE,
)


# ── Language extension map ─────────────────────────────────────────────────

_LANG_EXTS: dict[str, tuple[str, ...] | None] = {
    "python": (".py", ".pyi", ".pyx"),
    "javascript": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "ruby": (".rb", ".erb"),
    "php": (".php", ".phtml", ".php3", ".php4", ".php5"),
    "java": (".java", ".jsp", ".jspx"),
    "go": (".go",),
    "csharp": (".cs", ".razor", ".cshtml"),
    "rust": (".rs",),
    "generic": None,
}


# ── _PATTERNS (raw, without pattern_ids) ───────────────────────────────────

_RAW_PATTERNS: list[tuple[str, str, str, bool]] = [

    # ═══ PYTHON ═══════════════════════════════════════════════════════

    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*f["\']',
     "SQL f-string injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%',
     "SQL %-formatting injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*\{.*\}.*["\']\s*\.format\s*\(',
     "SQL .format() injection in execute()", "python", False),
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*["\'].*["\']\s*\+\s*(?!\s*["\'])',
     "SQL string concatenation in execute()", "python", False),
    (r'executemany\s*\(\s*f["\']',
     "SQL f-string injection in executemany()", "python", False),

    # Boolean/Time blind SQLi
    (r'\b(?:UNION)\s+SELECT\b', "UNION SELECT injection", "python", False),
    (r"(?:UNION)\s+(?:ALL\s+)?SELECT\s+.*SELECT",
     "UNION SELECT injection with multi-table", "python", False),
    (r'\bOR\s+[\'"]\d[\'"]\s*=\s*[\'"]\d[\'"]\b', "Boolean-based blind SQLi", "python", False),
    (r'\bAND\s+[\'"]\d[\'"]\s*=\s*[\'"]\d[\'"]\b', "Boolean-based blind SQLi numeric", "python", False),
    (r'\b(?:SLEEP|pg_sleep|WAITFOR\s+DELAY|BENCHMARK)\s*\(', "Time-based blind SQLi", "python", False),

    # Stacked queries
    (r';\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b', "Stacked query injection", "python", False),

    # Django ORM
    (r'\.raw\s*\(\s*f["\']', "Django raw() with f-string", "python", False),
    (r'\.raw\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%', "Django raw() with %-formatting", "python", False),
    (r'\.extra\s*\(\s*where\s*=\s*["\'].*["\']\s*[\+%]', "Django extra() with dynamic WHERE", "python", False),
    (r'\.extra\s*\(\s*tables\s*=\s*\[.*["\']\s*\+', "Django extra() with dynamic tables", "python", False),
    (r'cursor\.execute\s*\(\s*.*SELECT.*\{.*\}.*FROM', "Django cursor.execute() with interpolation", "python", False),
    (r'\.annotate\s*\(\s*.*RawSQL\s*\(', "Django RawSQL annotation injection", "python", False),
    (r'\.annotate\s*\(\s*.*Func\s*\(\s*.*Value\s*\(', "Django Func+Value expression injection", "python", False),
    (r'\.filter\s*\(\s*.*__\w+\s*=\s*.*\+', "Django filter() with string concat", "python", False),

    # SQLAlchemy
    (r'text\s*\(\s*f["\']', "SQLAlchemy text() with f-string", "python", False),
    (r'text\s*\(\s*["\'].*\{.*\}.*["\']\s*\.format\s*\(', "SQLAlchemy text() with .format()", "python", False),
    (r'text\s*\(\s*["\'][^"\']*%[sd]\b[^"\']*["\']\s*%', "SQLAlchemy text() with %-formatting", "python", False),
    (r'text\s*\(\s*["\'].*["\']\s*\+', "SQLAlchemy text() with string concat", "python", False),
    (r'\.from_statement\s*\(\s*text\s*\(', "SQLAlchemy from_statement(text())", "python", False),
    (r'session\.execute\s*\(\s*text\s*\(\s*f["\']', "SQLAlchemy session.execute(text(f))", "python", False),

    # Flask-SQLAlchemy
    (r'db\.engine\.execute\s*\(\s*f["\']', "Flask-SQLAlchemy f-string SQL", "python", False),
    (r'db\.session\.execute\s*\(\s*text\s*\(\s*f["\']', "Flask-SQLAlchemy text(f)", "python", False),

    # Second-order SQLi
    (r'(?:SELECT|INSERT|UPDATE|DELETE).*FROM\s+\w+\s+WHERE.*\[.*\]', "Second-order SQLi from stored data", "python", False),
    # Deactivated (20.08.2026): "execute with <collection>[idx]" patterns are
    # dict/list/attribute access — passing a value into execute(), NOT SQLi.
    # 3/3 revalidated FP, 0 TP. The real SQLi case (interpolation around the
    # access) is already caught by the dedicated f-string/format patterns above.

    # Pandas
    (r'read_sql_query\s*\(\s*f["\']', "Pandas read_sql_query with f-string", "python", False),
    (r'read_sql\s*\(\s*f["\']', "Pandas read_sql with f-string", "python", False),

    # ═══ JAVASCRIPT / TYPESCRIPT ═══════════════════════════════════════

    (r'\.(?:query|execute)\s*\(\s*`.*\$\{.*\}.*`', "Template literal SQL injection", "javascript", False),
    (r'\.(?:query|execute)\s*\(\s*[\"\'].*[\"\']\s*\+\s*', "String concat SQL injection", "javascript", False),
    (r'\.query\s*\(\s*.*SELECT.*\+', "query() with string concat", "javascript", False),
    (r'\.execute\s*\(\s*.*INSERT.*\+', "execute() with INSERT concat", "javascript", False),

    # Sequelize
    (r'sequelize\.query\s*\(\s*.*\$\{', "Sequelize query() with template literal", "javascript", False),
    (r'\.findAll\s*\(\s*\{.*where.*:\s*.*\$\{', "Sequelize findAll with dynamic where", "javascript", False),
    (r'\.query\s*\(\s*.*replacements.*\$\{', "Sequelize replacements injection", "javascript", False),

    # Knex
    (r'knex\.raw\s*\(\s*`.*\$\{', "Knex raw() with template literal", "javascript", False),
    (r'knex\s*\(.*\)\.whereRaw\s*\(', "Knex whereRaw() injection", "javascript", False),

    # MongoDB (NoSQL injection)
    (r'\$where\s*:\s*(?:f["\']|`\$\{)', "MongoDB $where with interpolation", "javascript", False),
    (r'\$regex\s*:\s*(?:request\.|req\.|params\[)', "MongoDB $regex from user input", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$where\s*:', "MongoDB find() with $where", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$expr\s*:', "MongoDB find() with $expr injection", "javascript", False),

    # ═══ PHP ═══════════════════════════════════════════════════════════

    (r'mysql_query\s*\(\s*["\'].*["\']\s*\.', "PHP mysql_query with concat", "php", False),
    (r'mysqli_query\s*\(\s*.*["\']\s*\.', "PHP mysqli_query with concat", "php", False),
    (r'mysqli::query\s*\(\s*.*["\']\s*\.', "PHP mysqli::query with concat", "php", False),
    (r'PDO::query\s*\(\s*["\'].*["\']\s*\.', "PHP PDO::query with concat", "php", False),
    (r'->prepare\s*\(\s*["\'].*["\']\s*\.', "PHP prepare() with concat", "php", False),
    (r'DB::select\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::select with concat", "php", False),
    (r'DB::raw\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::raw with concat", "php", False),
    (r'DB::statement\s*\(\s*["\'].*["\']\s*\.', "Laravel DB::statement with concat", "php", False),
    (r'pg_query\s*\(\s*.*["\']\s*\.', "PHP pg_query with concat", "php", False),

    # ═══ RUBY ══════════════════════════════════════════════════════════

    (r'\.(?:find_by_sql|find_by_sql)\s*\(\s*["\'].*#\{', "Rails find_by_sql with interpolation", "ruby", False),
    (r'\.where\s*\(\s*["\'].*#\{', "Rails where() with string interpolation", "ruby", False),
    (r'ActiveRecord::Base\.connection\.execute\s*\(\s*["\'].*#\{', "Rails execute() with interpolation", "ruby", False),
    (r'\.(?:select_all|select_rows)\s*\(\s*["\'].*#\{', "Rails select_all with interpolation", "ruby", False),
    (r'\.update_all\s*\(\s*["\'].*#\{', "Rails update_all with interpolation", "ruby", False),
    (r'\.delete_all\s*\(\s*["\'].*#\{', "Rails delete_all with interpolation", "ruby", False),

    # ═══ JAVA ════════════════════════════════════════════════════════════

    (r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)?\s*\(\s*["\'].*["\']\s*\+\s*',
     "Java JDBC Statement with string concat", "java", False),
    (r'String\s+\w+\s*=\s*["\']SELECT.*["\']\s*\+\s*\w+',
     "Java SQL query built with string concatenation", "java", False),
    (r'(?:jdbcTemplate|namedParameterJdbcTemplate)\.(?:query|update)\s*\(\s*["\'].*["\']\s*\+\s*',
     "Spring JDBC template with string concat", "java", False),
    (r'\.createQuery\s*\(\s*["\'].*["\']\s*\+\s*',
     "JPA/Hibernate createQuery with string concat", "java", False),
    (r'String\s+\w+\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*\w+',
     "Java SQL built with string concat (INSERT/UPDATE/DELETE)", "java", False),
    (r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)\s*\(\s*\w+\s*\)',
     "Java JDBC executeQuery/executeUpdate with SQL variable", "java", False),

    # ═══ GO ═════════════════════════════════════════════════════════════

    (r'db\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|".*"\s*\+\s*)',
     "Go database/sql with fmt.Sprintf or string concat", "go", False),
    (r'fmt\.Sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "Go fmt.Sprintf building SQL query", "go", False),

    # ═══ C# ═════════════════════════════════════════════════════════════

    (r'new\s+SqlCommand\s*\(\s*["\'].*["\']\s*\+\s*',
     "C# SqlCommand with string concat", "csharp", False),
    (r'\.Execute(?:Reader|Scalar|NonQuery)\s*\(\s*\)',
     "C# SqlCommand with string concat", "csharp", False),
    (r'string\.Format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
     "C# string.Format building SQL query", "csharp", False),

    # ═══ RUST ═══════════════════════════════════════════════════════════

    (r'sqlx::query\s*\(\s*["\'].*["\']\s*\+\s*',
     "Rust sqlx::query with string concat", "rust", False),
    (r'sqlx::query_as\s*\(\s*["\'].*["\']\s*\+\s*',
     "Rust sqlx::query_as with string concat", "rust", False),

    # ═══ NoSQL Injection ═══════════════════════════════════════════════

    (r'\$where\s*:\s*(?:f["\']|`\$\{)',
     "MongoDB $where with string interpolation — NoSQL injection", "javascript", False),
    (r'\$regex\s*:\s*(?:request\.|req\.|params\[)',
     "MongoDB $regex from user input — ReDoS / NoSQL injection", "javascript", False),
    (r'\.find\s*\(\s*\{\s*\$where\s*:',
     "MongoDB find() with $where — NoSQL injection", "javascript", False),
    (r'\.find_one_and_update\s*\(\s*\{\s*\$set\s*:',
     "MongoDB find_one_and_update with $set injection", "javascript", False),
]


# ── Build _PATTERNS with pattern_ids (deterministic) ───────────────────────

_PATTERNS: list[tuple[str, str, str, str, bool]] = _assign_ids(_RAW_PATTERNS)
# Format: (pattern_id, regex, title, language, extra_context_required)


# ── Sanitizer detection ────────────────────────────────────────────────────

_SANITIZER_PATTERNS = re.compile(
    r'\b(?:ident|scrub|escape_identifier|quote_ident|_sqlite_ident|sanitize)'
    r'|\.replace\([\"\']\\[\'\"][\"\'],\s*[\"\']\\1[\"\']\)'
    r'|_safe_\w+',
    re.IGNORECASE,
)

_TAINT_SOURCE_PATTERNS = re.compile(
    r'(?:request\.(?:args|form|values|json|data|GET|POST|COOKIE)|'
    r'input\s*\(|sys\.argv|os\.environ\[|'
    r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|'
    r'\.(?:get_json|form_data|params)\s*\()',
    re.IGNORECASE,
)


# Patterns that only represent SQLi when the query is *built by interpolation*.
# A bare `execute(<collection>[idx])` (prebuilt query) or a hardcoded `IN [...]`
# list inside a static query is NOT injection — skip when no interpolation is present.
_INTERPOLATION_REQUIRED = {
    "GS005-GEN-PY-008",  # Second-order SQLi from stored data
}

_REAL_INTERPOLATION = re.compile(
    r'f["\']|\.format\s*\(|["\']\s*%|\+\s*(?!\s*["\'])',
)


def _has_sanitizer(context: str) -> bool:
    return bool(_SANITIZER_PATTERNS.search(context))


def _has_taint_source(context: str) -> bool:
    return bool(_TAINT_SOURCE_PATTERNS.search(context))


def _get_disabled(ctx: AuditContext) -> set[str]:
    """Get disabled pattern IDs from AuditContext (cached per scan)."""
    try:
        return ctx.get_disabled_patterns(RULE_ID)
    except (AttributeError, Exception):
        return set()


# ── Core detection ─────────────────────────────────────────────────────────

def detect(ctx: AuditContext) -> list[Finding]:
    """Detect SQL/NoSQL injection patterns with per-pattern tracking.

    v2.0: pattern_ids in metadata, location-based dedup, disabled patterns.
    """
    if RULE_ID in ctx.skipped_detectors:
        return []

    disabled = _get_disabled(ctx)
    findings: list[Finding] = []

    for fp in ctx.get_source_files():
        try:
            content = ctx.read_file(fp)
        except Exception:
            continue

        lines = content.split("\n")

        # Group matches by (line, snippet) → one finding per location
        locations: dict[tuple[int, str], dict] = {}

        for pid, regex, title, lang, needs_context in _PATTERNS:
            if pid in disabled:
                continue

            exts = _LANG_EXTS.get(lang)
            if exts is not None and fp.suffix not in exts:
                continue

            for m in re.finditer(regex, content, re.IGNORECASE):
                matched = m.group(0)
                line_no = content[:m.start()].count("\n") + 1
                snippet = matched[:200]
                line = lines[line_no - 1] if line_no <= len(lines) else ""

                # Safety filters (preserved from v1)
                if "gsc:ignore" in line or "nosec" in line:
                    continue
                if "PRAGMA" in line.upper():
                    continue
                if "reply_text" in line:
                    continue
                if "text(" in matched and "text(" in line and not _SQL_KEYWORDS.search(line):
                    continue
                if not needs_context and len(_SQL_KEYWORDS.findall(line)) == 0:
                    if not re.search(r'[%{}]|\$\{|\\+.*SELECT|f["\']', line):
                        continue
                if re.search(r'(\?|%s)', line) and re.search(r'\.join\s*\(', line):
                    continue
                if re.search(r'(?:%[sd]|\?|:\w+)\s*["\']\s*,\s*[\[({]', line):
                    continue
                if pid in _INTERPOLATION_REQUIRED and not _REAL_INTERPOLATION.search(line):
                    continue

                key = (line_no, snippet)
                if key not in locations:
                    locations[key] = {"title": title, "pattern_ids": [],
                                      "lang": lang, "line": line}
                locations[key]["pattern_ids"].append(pid)

        # Build findings from grouped locations
        for (line_no, snippet), data in locations.items():
            severity = "CRITICAL"
            if "NoSQL" in data["title"] or "read_sql" in data["title"]:
                severity = "HIGH"
            if "format!" in data["title"]:
                severity = "HIGH"

            f = make_finding(
                rule_id=RULE_ID,
                title=data["title"],
                severity=severity,
                confidence=0.85,
                file=str(fp),
                line=line_no,
                snippet=snippet,
                metadata={
                    "pattern_ids": data["pattern_ids"],
                    "language": data["lang"],
                },
            )
            if f is None:
                continue

            # Downgrade f-string SQL if sanitizer or no taint source
            if f["severity"] == "CRITICAL" and "f-string" in f["title"]:
                context = "\n".join(lines[max(0, line_no - 3):line_no])
                if _has_sanitizer(context):
                    f["severity"] = "LOW"
                    f["title"] = f["title"] + " [sanitized — verify manually]"
                elif not _has_taint_source(context):
                    f["severity"] = "MEDIUM"
                    f["title"] = f["title"] + " [no user input — verify]"

            findings.append(f)

    return findings

```

---

### GS007 — `gs007_idor.py` (echelon 2, noise_tier `normal`, 249 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS007 — Broken Access Control: IDOR + BAC patterns.

Detects:
- Direct object reference without ownership/permission check (IDOR)
- Sequential/predictable ID enumeration (auto-increment, no UUID)
- Missing tenant/organization isolation (cross-org access)
- Support/admin/internal panel routes without auth
- Unprotected file/attachment download endpoints
- Operations on behalf of other users/orgs (create/edit/subscribe)

OWASP A01:2021 — Broken Access Control.
Inspired by: Meta $78K bounty (2026) — chained BAC in support infrastructure.
"""

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS007"
ECHELON = 2
NOISE_TIER = "normal"

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str]] = [
    # ── IDOR: Direct DB access ─────────────────────────────────────────────
    # Python/Django: direct get() without permission check
    (r'\.objects\.get\s*\(\s*pk\s*=\s*request\.', "Django direct PK lookup without auth check"),
    (r'\.objects\.get\s*\(\s*id\s*=\s*request\.', "Django direct ID lookup without auth check"),
    (r'\.objects\.filter\s*\(\s*pk\s*=\s*request\.', "Django direct PK filter without auth check"),

    # FastAPI: path parameter used directly in DB without auth
    (r'@app\.\w+\(.*\{.*id.*\}.*\)\s*\n\s*def\s+\w+\(.*\):\s*\n\s*(?!.*current_user|.*Depends)', "FastAPI route without auth on ID param"),

    # Rails: find(params[:id]) without ownership check
    (r'\.find\s*\(\s*params\s*\[\s*:id\s*\]\s*\)\s*\n(?!.*current_user|.*authenticate)', "Rails find(params[:id]) without auth"),

    # Express.js: req.params.id used directly in DB without auth middleware
    (r'(?:findById|findByPk|findOne)\s*\(\s*req\.params\.\w+\s*\)', "Express direct ID lookup without auth check"),
    # Laravel: Model::find($request->id) without auth
    (r'(?:\w+)::find\s*\(\s*\$request->\w+\s*\)', "Laravel Model::find without auth check"),

    # SQL ORDER BY / LIMIT from request params
    (r'(?:ORDER\s+BY|LIMIT|OFFSET)\s+.*request\.(?:args|GET|POST)\s*\[', "SQL clause from unsanitized request params"),

    # ── SEQUENTIAL ID ENUMERATION ──────────────────────────────────────────
    # Auto-increment PK in schema (enables enumeration) — word boundaries to avoid matching serializers/serialize
    (r'\b(?:AUTO_INCREMENT|AUTOINCREMENT|IDENTITY\s*\(\s*1\s*,\s*1\s*\)|nextval\s*\()', "Auto-increment PK enables ID enumeration (consider UUID)"),
    # PostgreSQL SERIAL/BIGSERIAL — with word boundaries (NOT serializers!)
    (r'\b(?:SERIAL|BIGSERIAL)\b', "PostgreSQL SERIAL PK enables ID enumeration"),
    # Integer ID from request without UUID validation
    (r'int\s*\(\s*(?:request\.(?:args|GET|POST|params))\s*\[', "Integer ID from request — predictable, enables enumeration"),
    # Loop iterating through sequential IDs
    (r'for\s+\w+\s+in\s+range\s*\(.*(?:id|ticket|order|user_id)', "Sequential ID iteration (potential enumeration attack)"),

    # ── CROSS-TENANT/ORG ISOLATION ─────────────────────────────────────────
    # Query without tenant/org filter
    (r'\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*request\.user\b', "User-scoped query missing org/tenant filter — cross-org access possible"),
    # Multi-tenant app: no tenant_id in WHERE clause
    (r'SELECT\s+.*FROM\s+\w+\s+WHERE\s+(?!.*tenant_id|.*org_id|.*organization_id).*\buser_id\s*=', "SQL query filtered by user_id only — missing tenant isolation"),
    # FastAPI: Depends(get_current_user) without Depends(get_current_org)
    (r'Depends\s*\(\s*get_current_user\s*\)\s*(?!.*Depends\s*\(\s*get_current_org)', "FastAPI with user auth but missing organization auth"),

    # ── ADMIN/SUPPORT PANEL EXPOSURE ───────────────────────────────────────
    # Admin routes without auth decorator
    (r'@(?:app|router|bp)\.\w+\(\s*[\'\"]/(?:admin|support|internal|staff|moderation)\b', "Admin/support route — verify auth decorator is present"),
    # Django admin-like views without @staff_member_required
    (r'def\s+\w+admin\w*\s*\(request.*\):\s*\n\s*(?!.*@\w+_required|.*permission)', "Django admin view without permission decorator"),
    # Flask blueprint for admin without @login_required
    (r"@\w+_blueprint\.route\s*\(\s*[\'\"]/(?:admin|support|internal)", "Flask admin/support blueprint route — verify auth"),

    # ── FILE/ATTACHMENT DOWNLOAD ───────────────────────────────────────────
    # File download endpoint with ID param, no ownership check
    (r'@(?:app|router)\.\w+\(\s*[\'\"].*(?:attachment|file|download|media).*\{.*\w+.*\}', "File/attachment download endpoint — verify ownership check"),
    # Django FileResponse with path from request
    (r'FileResponse\s*\(.*request\.(?:GET|POST).*\[', "File download path from request param — verify access control"),
    # Express: res.sendFile with req.params
    (r'(?:sendFile|download)\s*\(.*req\.(?:params|query)\.', "Express file send from request params — verify auth"),

    # ── TICKET/ORDER OPERATIONS ────────────────────────────────────────────
    # Create/update on behalf of another org
    (r'(?:create|update|delete|save)\s*\(.*request\.(?:data|body|POST).*org', "Ticket mutation — verify org membership before operation"),
    # Adding subscribers/participants without permission check
    (r'\badd_subscriber\b\s*\(', "Add subscriber/member operation — verify caller permission"),
    (r'\badd_participant\b\s*\(', "Add participant operation — verify caller permission"),
    # Status transition without ownership check
    (r'(?:status|state)\s*=\s*request\.(?:data|POST|body)\[.*[\"\'](?:status|state)', "Status change from request — verify caller owns this object"),

    # ── BATCH OPERATIONS (Gen+Eval PASS #1) ───────────────────────────────
    # Bulk create/update/delete without ownership check (Django, Sequelize, Mongoose, Laravel)
    (r'\b(?:bulk_create|bulk_update|insertMany|insert_many|bulkWrite|batchPut|batchDelete|bulk_save_objects)\s*\(', "Batch operation without ownership check"),

    # ── HTTP METHOD OVERRIDE (Gen+Eval PASS #4) ──────────────────────────
    # Method override bypass: X-HTTP-Method / _method → обход ACL
    (r'\b(?:HTTP_METHOD_OVERRIDE|X-HTTP-Method|X-HTTP-Method-Override)\b', "HTTP Method Override header — potential ACL bypass"),
    (r'\b_method\b\s*=', "HTTP method override via _method parameter — potential ACL bypass"),

    # ── FINTECH IDOR (2026 Pentest) ───────────────────────────────────────
    # Payment method access without ownership check
    (r'(?:payment_method|PaymentMethod|card|Card)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk)\s*=\s*',
     "Payment method/card lookup — verify ownership before exposing"),
    # Transaction/statement access by sequential ID
    (r'(?:transaction|Transaction|statement|Statement)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*.*request\.',
     "Transaction/statement lookup from request — verify account ownership"),
    # Bank account operations without ownership verification
    (r'(?:bank_account|BankAccount|account)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk|number)\s*=',
     "Bank account access — verify customer ownership"),
    # Invoice/bill access by ID
    (r'(?:invoice|Invoice|bill|Bill)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:id|pk|number)\s*=\s*request',
     "Invoice/bill access by request param — verify payer/recipient ownership"),
    # Balance/portfolio lookup by user ID (no auth check)
    (r'(?:balance|Balance|portfolio|Portfolio)\s*\.\s*(?:get|find|objects\.get)\s*\(\s*(?:user_id|account_id)\s*=\s*request',
     "Balance lookup by user_id from request — verify caller is the owner"),
]

# Skip patterns (legitimate use cases)
SKIP_PATTERNS = [
    r'login_required',
    r'permission_required',
    r'@authenticated',
    r'current_user',
    r'request\.user\.',
    r'user\s*=\s*request\.user\b',
    r'\.filter\s*\(.*user\s*=',
    r'\.filter\s*\(.*owner\s*=',
    r'\.filter\s*\(.*org\s*=',
    r'\.filter\s*\(.*tenant\s*=',
    r'\.filter\s*\(.*organization\s*=',
    r'is_authenticated',
    r'has_permission\s*\(',
    r'has_perm\s*\(',
    r'user_passes_test',
    r'@staff_member_required',
    r'@admin_required',
    r'@role_required',
    r'uuid\s*\(\s*',
    r'UUID\s*\(\s*',
    r'isinstance\s*\(.*UUID',
    r'requireAuth|require_auth|withAuth|with_auth',
    r'middleware\s*\(\s*[\'\"]auth[\'\"]\s*\)',
    r'@UseGuards\s*\(\s*AuthGuard',
    r'@Protected\s*\(',
    r'_enforce_\w+',
    r'check_ownership\s*\(',
    r'check_object_permission\s*\(',
    r'has_object_permission\s*\(',
    r'_check_access\s*\(',
]


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect IDOR + BAC patterns — object references without auth checks."""
    if "GS007" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files(extensions=(".py", ".rb", ".js", ".ts", ".php", ".sql", ".java", ".go")):
        # Skip vendor/minified/static bundles
        fname = fp.name.lower()
        if any(x in fname for x in (".min.", "-bundle", "bundle.", "vendor", ".pack.")):
            continue
        if "static/" in str(fp) and (fname.endswith(".min.js") or "bundle" in fname):
            continue
        content = ctx.read_file(fp)
        for pattern, title in _PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                line_text = content.split("\n")[line_no - 1].strip()
                if "gsc:ignore" in line_text:
                    continue

                # Check surrounding context for auth checks
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(content), m.end() + 150)
                surrounding = content[ctx_start:ctx_end]

                # Skip if auth check is nearby
                if any(re.search(s, surrounding, re.I) for s in SKIP_PATTERNS):
                    continue

                # Determine severity based on pattern category
                severity = "HIGH"
                if "admin" in title.lower() or "support" in title.lower():
                    severity = "CRITICAL"
                elif "enumeration" in title.lower() or "auto-increment" in title.lower() or "SERIAL" in title:
                    severity = "INFO"  # facilitator, not vulnerability on its own

                findings.append(Finding(
                    rule_id=RULE_ID,
                    category=severity,
                    title=title,
                    file_path=str(fp),
                    line_number=line_no,
                    detail=f"Line {line_no}: {line_text[:120]}",
                    fix_suggestion=_get_fix_suggestion(title),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
                        "https://whiteauth.com/2026/07/17/broken-access-control-in-meta-com-support-infrastructure/",
                    ],
                ))

    return findings


def _get_fix_suggestion(title: str) -> str:
    """Return context-aware fix suggestion based on pattern type."""
    if "enumeration" in title.lower() or "auto-increment" in title.lower():
        return (
            "Use UUID/GUID instead of auto-increment IDs for external-facing resources. "
            "If sequential IDs are required, add rate limiting and ownership checks."
        )
    elif "tenant" in title.lower() or "org" in title.lower() or "cross-org" in title.lower():
        return (
            "Add tenant_id/org_id filter to all queries. "
            "Verify current_user belongs to the same organization as the requested resource. "
            "Implement organization-scoped querysets."
        )
    elif "admin" in title.lower() or "support" in title.lower():
        return (
            "Add authentication AND authorization decorators to admin/support routes. "
            "Implement role-based access control (RBAC). "
            "Consider IP allowlisting for admin panels."
        )
    elif "file" in title.lower() or "attachment" in title.lower() or "download" in title.lower():
        return (
            "Verify file ownership before serving. Use signed URLs with expiry. "
            "Implement access control check: does the requesting user own/ have permission to this file?"
        )
    elif "ticket" in title.lower() or "subscriber" in title.lower() or "status" in title.lower():
        return (
            "Verify the caller has permission to perform this operation on this object. "
            "Check organization membership and role before allowing mutations. "
            "Log all administrative operations for audit trail."
        )
    else:
        return (
            "Verify the current user has permission to access this object. "
            "Check ownership: filter by user_id or check object ownership "
            "before returning data."
        )


description = "Broken Access Control — IDOR, sequential ID enumeration, cross-tenant access, admin panel exposure, unprotected file downloads, unauthorized ticket operations"

```

---

### GS008 — `gs008_dead_code.py` (echelon 1, noise_tier `normal`, 163 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS008 — Dead code: declared but never used.

Detects:
- Module-level UPPER_CASE constants referenced only once (declaration)
- Feature flags assigned but never read (VAR = os.environ.get('FLAG') → VAR unused)

Inspired by ATR_TP_LEVELS bug (2026-06-28): constants declared, never used,
causing ATR-based TP to never fire.
"""

import ast
import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS008"
ECHELON = 1

# Files to skip for dead-code analysis (test files, __init__ with exports)
_SKIP_PATTERNS = [
    "test_", "_test.", "conftest.py",
    "__init__.py",  # __init__ constants are exports, not dead code
]

# Minimum constant name length to consider
_MIN_CONSTANT_LEN = 4

# Known patterns that are never dead code
_ALWAYS_USED = {
    "__all__", "__version__", "__author__", "__doc__", "__file__",
}


def _extract_constants(source: str) -> list[tuple[str, str, int]]:
    """Extract module-level UPPER_CASE assignments with line numbers."""
    constants = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return constants

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if not name.isupper() or len(name) < _MIN_CONSTANT_LEN:
                continue
            if name in _ALWAYS_USED or name.startswith("__"):
                continue
            line = node.lineno
            line_text = source.split("\n")[line - 1].strip() if source else ""
            constants.append((name, line_text[:120], line))
    return constants


def _count_occurrences(name: str, source: str) -> int:
    """Count whole-word occurrences of name in source."""
    return len(re.findall(r"\b" + re.escape(name) + r"\b", source))


def _is_library_module(filepath: Path, content: str) -> tuple[bool, bool]:
    """Check if file is a library module (not application code).
    Returns (is_library, is_main_app).
    Library modules export constants for consumers — dead constant
    detection is noisy here. Feature flags still checked."""
    is_library = (filepath.parent / "__init__.py").exists()
    is_main = bool(re.search(
        r'if\s+__name__\s*==\s*["\']__main__["\']\s*:', content
    ))
    return is_library, is_main


def detect(ctx: AuditContext) -> list[Finding]:
    """Find dead code in Python source files."""
    if "GS008" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []

    for fp in ctx.get_files(extensions=(".py",)):
        # Skip test/init files
        fname = fp.name
        if any(fname.startswith(p) or p in fname for p in _SKIP_PATTERNS):
            continue
        if ctx.is_test_file(fp) or ctx.is_non_code_file(fp):
            continue

        content = ctx.read_file(fp)
        if not content:
            continue

        # Library modules: skip constant detection (exports = legitimate),
        # but still check feature flags (they're application concerns)
        is_library, is_main = _is_library_module(fp, content)

        # ── Check 1: Dead UPPER_CASE constants ──
        # Skip for library modules without a main guard — exported
        # constants are used by consumers, not within the same file.
        if not is_library or is_main:
            for name, line_text, line_no in _extract_constants(content):
                occurrences = _count_occurrences(name, content)
                if occurrences == 1:
                    if any(x in name for x in (
                        "FILE", "PATH", "DIR", "_KEY", "_SECRET",
                        "_URL", "_TOKEN", "_PASSWORD"
                    )):
                        continue

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="LOW",
                        title=f"Dead constant: {name} — declared but never read",
                        file_path=str(fp),
                        line_number=line_no,
                        detail=f"Line {line_no}: {line_text}",
                        fix_suggestion=(
                            f"Remove '{name}' or reference it in the code. "
                            f"If this is an exported constant, move it to __init__.py."
                        ),
                        references=[
                            "dead-code-audit skill",
                        ],
                    ))

        # ── Check 2: Feature flags assigned but never read ──
        for m in re.finditer(
            r"^(\w+)\s*=\s*os\.environ\.get\(['\"](\w+)['\"]",
            content, re.MULTILINE,
        ):
            var_name = m.group(1)
            flag_name = m.group(2)
            if flag_name.startswith("BYBIT_") or flag_name.startswith("HERMES_"):
                count = _count_occurrences(var_name, content)
                if count == 1:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        category="MEDIUM",
                        title=f"Dead feature flag: {var_name} = os.environ.get('{flag_name}') — never read",
                        file_path=str(fp),
                        line_number=content[:m.start()].count("\n") + 1,
                        detail=f"Feature flag '{flag_name}' assigned but never used",
                        fix_suggestion=(
                            f"Either use {var_name} in a condition, or remove the flag."
                        ),
                        references=[
                            "dead-code-audit skill",
                            "ATR_TP_ENABLED precedent (auto_tp.py)",
                        ],
                    ))

    return findings


description = "Dead code: constants and feature flags declared but never used"

```

---

### GS009 — `gs009_supply_chain.py` (echelon 2, noise_tier `normal`, 184 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS009 — Supply Chain Scanner (Bumblebee integration).

Scans developer endpoint for:
- Package manager artifacts (npm, PyPI, Go, Ruby, Composer, Homebrew)
- Editor extensions (VS Code, Cursor, Windsurf)
- MCP configurations
- Browser extensions
- Agent skills

Delegates to bumblebee CLI (Perplexity, Apache 2.0).
"""
import json
import subprocess
import os
from typing import List, Optional

from . import Finding

RULE_ID = "GS009"
ECHELON = 2  # Security echelon — supply chain is a real threat vector
SEVERITY = "HIGH"
CATEGORY = "supply-chain"
description = (
    "Supply chain scanner: detects packages, editor extensions, MCP configs, "
    "and developer-tool metadata across package ecosystems (npm, PyPI, Go, "
    "Ruby, Composer, Homebrew, MCP, editor-extension, browser-extension, agent-skill). "
    "Powered by Perplexity Bumblebee."
)

BUMBLEBEE_BIN = os.path.expanduser("~/go/bin/bumblebee")


def _find_bumblebee() -> Optional[str]:
    """Locate bumblebee binary."""
    if os.path.isfile(BUMBLEBEE_BIN) and os.access(BUMBLEBEE_BIN, os.X_OK):
        return BUMBLEBEE_BIN
    # Try PATH
    for path in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(path, "bumblebee")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def detect(ctx) -> List[Finding]:
    """Scan with Bumblebee and convert to GSC findings."""
    findings: List[Finding] = []
    
    bumblebee = _find_bumblebee()
    if not bumblebee:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message="Bumblebee not installed. Install: go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest",
            fix_suggestion="Run: go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest",
            references=["https://github.com/perplexityai/bumblebee"],
        ))
        return findings

    try:
        # Run bumblebee on the project directory
        scan_dir = ctx.project_root or os.getcwd()
        cmd = [
            bumblebee, "scan",
            "--profile", "baseline",
            "--root", scan_dir,
            "--emit-summary",
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PATH": os.environ.get("PATH", "") + ":/usr/local/go/bin"},
        )
        
        if result.returncode != 0:
            findings.append(Finding(
                rule_id=RULE_ID,
                severity="LOW",
                category=CATEGORY,
                echelon=ECHELON,
                file="N/A",
                line=0,
                message=f"Bumblebee scan failed: {result.stderr[:200]}",
                fix_suggestion="Check Bumblebee installation and permissions.",
                references=["https://github.com/perplexityai/bumblebee"],
            ))
            return findings

        # Parse JSON lines
        packages_by_eco: dict[str, list[dict]] = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            record_type = record.get("record_type", "")
            if record_type == "package":
                eco = record.get("ecosystem", "unknown")
                packages_by_eco.setdefault(eco, []).append(record)
            elif record_type == "scan_summary":
                summary = record
        
        # Report interesting ecosystems
        interesting = {"mcp", "editor-extension", "browser-extension", "agent-skill"}
        for eco, pkgs in sorted(packages_by_eco.items()):
            count = len(pkgs)
            if eco in interesting:
                for pkg in pkgs:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        severity="MEDIUM" if eco == "mcp" else "LOW",
                        category=CATEGORY,
                        echelon=ECHELON,
                        file=pkg.get("source_file", "N/A"),
                        line=0,
                        message=f"[{eco}] {pkg['package_name']}@{pkg.get('version', '?')} — {pkg.get('source_type', '?')}",
                        fix_suggestion=f"Review {eco} package: {pkg['package_name']}",
                        references=[f"https://github.com/perplexityai/bumblebee"],
                    ))
            else:
                # Summary for non-interesting ecosystems
                findings.append(Finding(
                    rule_id=RULE_ID,
                    severity="LOW",
                    category=CATEGORY,
                    echelon=ECHELON,
                    file=f"{scan_dir}/",
                    line=0,
                    message=f"[{eco}] {count} packages found (Bumblebee baseline scan)",
                    fix_suggestion="Review supply chain exposure. Use --exposure-catalog for threat intel matching.",
                    references=["https://github.com/perplexityai/bumblebee"],
                ))
        
        if not findings:
            findings.append(Finding(
                rule_id=RULE_ID,
                severity="INFO",
                category=CATEGORY,
                echelon=ECHELON,
                file="N/A",
                line=0,
                message="Bumblebee scan completed — no packages found.",
                fix_suggestion="",
            ))
            
    except subprocess.TimeoutExpired:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message="Bumblebee scan timed out (>30s).",
            fix_suggestion="Consider narrowing scan scope with --root or --ecosystem.",
        ))
    except Exception as e:
        findings.append(Finding(
            rule_id=RULE_ID,
            severity="LOW",
            category=CATEGORY,
            echelon=ECHELON,
            file="N/A",
            line=0,
            message=f"Bumblebee error: {e}",
            fix_suggestion="Check Bumblebee binary and Go installation.",
        ))

    return findings

```

---

### GS010 — `gs010_ssh_hardening.py` (echelon 2, noise_tier `normal`, 152 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS010 — Weak SSH Configuration Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects dangerous SSH server configurations:
- PermitRootLogin without forced-commands-only
- PasswordAuthentication enabled without 2FA
- Empty AllowedUsers/AllowedGroups
- Weak ciphers/macs/kex
- X11Forwarding enabled
- PermitUserEnvironment enabled (LD_PRELOAD vector)
- AgentForwarding enabled
- MaxAuthTries too high (>6)

Sources: SSH Hardening & Offensive Mastery (Redteam Kit)
"""
from . import AuditContext, Finding

RULE_ID = "GS010"
ECHELON = 2
description = "Weak SSH server configuration — dangerous sshd_config settings"


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS010" in ctx.skipped_detectors:
        return []
    findings = []

    # Only check sshd_config files
    for fp in ctx.get_source_files():
        if fp.name not in ("sshd_config", "sshd_config.dist", "sshd_config.template"):
            continue
        if fp.suffix in (".md", ".txt", ".org", ".rst"):
            continue  # Skip documentation

        try:
            content = fp.read_text()
        except Exception:
            continue

        lines = content.split("\n")

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # CRITICAL: PermitRootLogin without forced-commands-only
            if "PermitRootLogin" in stripped and "without-password" not in stripped.replace(" ", "").lower() \
               and "prohibit-password" not in stripped.replace(" ", "").lower() \
               and "forced-commands-only" not in stripped.replace(" ", "").lower():
                if "yes" in stripped.lower().split() or "yes" == stripped.split()[-1].lower():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="CRITICAL",
                        title="SSH root login enabled",
                        detail=f"PermitRootLogin is set to 'yes' — allows direct root SSH access. "
                               f"Use 'prohibit-password' or 'forced-commands-only'.",
                        fix_suggestion="Set 'PermitRootLogin prohibit-password' or 'PermitRootLogin no'",
                        references=["SSH Hardening & Offensive Mastery §3.1.3"]
                    ))

            # HIGH: PasswordAuthentication enabled (weak auth)
            if "PasswordAuthentication" in stripped:
                parts = stripped.lower().split()
                if "yes" in parts:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="HIGH",
                        title="SSH password authentication enabled",
                        detail="PasswordAuthentication yes — vulnerable to brute-force and credential stuffing. "
                               "Use key-based authentication + 2FA instead.",
                        fix_suggestion="Set 'PasswordAuthentication no' and use SSH keys",
                        references=["SSH Hardening & Offensive Mastery §3.1.7", "Fail2Ban §3.2.3.1"]
                    ))

            # HIGH: PermitUserEnvironment enabled (LD_PRELOAD attack vector)
            if "PermitUserEnvironment" in stripped:
                if "yes" in stripped.lower().split():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="HIGH",
                        title="SSH user environment enabled — LD_PRELOAD vector",
                        detail="PermitUserEnvironment yes allows users to set environment variables like "
                               "LD_PRELOAD, which can lead to privilege escalation. CVE-2018-15473 related.",
                        fix_suggestion="Set 'PermitUserEnvironment no'",
                        references=["SSH Hardening & Offensive Mastery §4.1.4", "CVE-2018-15473"]
                    ))

            # MEDIUM: X11Forwarding enabled
            if "X11Forwarding" in stripped:
                if "yes" in stripped.lower().split():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="MEDIUM",
                        title="SSH X11 forwarding enabled",
                        detail="X11Forwarding yes exposes graphical applications to potential hijacking.",
                        fix_suggestion="Set 'X11Forwarding no'",
                        references=["SSH Hardening & Offensive Mastery §3.1.9"]
                    ))

            # MEDIUM: Agent forwarding enabled
            if "AllowAgentForwarding" in stripped and "no" not in stripped.lower().split():
                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=str(fp.relative_to(ctx.path)),
                    line=lineno,
                    severity="MEDIUM",
                    title="SSH agent forwarding enabled",
                    detail="Agent forwarding allows SSH agent keys to be forwarded, enabling lateral movement.",
                    fix_suggestion="Set 'AllowAgentForwarding no'",
                    references=["SSH Hardening & Offensive Mastery §3.2.1"]
                ))

            # MEDIUM: MaxAuthTries too high
            if "MaxAuthTries" in stripped:
                parts = stripped.split()
                for p in parts:
                    try:
                        val = int(p)
                        if val > 6:
                            findings.append(Finding(
                                rule_id=RULE_ID,
                                file_path=str(fp.relative_to(ctx.path)),
                                line=lineno,
                                severity="MEDIUM",
                                title=f"SSH MaxAuthTries too high ({val})",
                                detail=f"MaxAuthTries={val} allows excessive authentication attempts, "
                                       f"enabling brute-force attacks. Recommend 3-6.",
                                fix_suggestion="Set 'MaxAuthTries 3'",
                                references=["SSH Hardening & Offensive Mastery §3.1.4"]
                            ))
                        break
                    except ValueError:
                        continue

    return findings

```

---

### GS011 — `gs011_jwt_vulnerabilities.py` (echelon 2, noise_tier `normal`, 121 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS011 — JWT/JOSE Vulnerability Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects JWT/JOSE implementation vulnerabilities:
- Hardcoded JWT secrets
- alg:none bypass patterns
- Weak HMAC secrets (<256 bits)
- Missing signature verification (decode without verify)
- 'none' algorithm allowed in decoding

Sources: Hacking APIs (No Starch Press), 2025 Playbooks
"""
from . import AuditContext, Finding
import re

RULE_ID = "GS011"
ECHELON = 2
description = "JWT/JOSE vulnerabilities — weak signatures, alg:none, hardcoded secrets"


# Patterns from Hacking APIs and real-world JWT vulnerabilities
JWT_SECRET_PATTERNS = [
    (re.compile(r'(?:jwt|JWT|json.?web.?token)_?(?:secret|key|signing)\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]', re.I),
     "Hardcoded JWT secret/key", "CRITICAL"),
    (re.compile(r'(?:secret|SECRET)_?(?:key|KEY)\s*[:=]\s*[\'"]([^\'"]{1,64})[\'"]', re.I),
     "Potential JWT signing secret (short)", "HIGH"),
    (re.compile(r'(?:config|CONFIG)\s*\[[\'"]?(?:JWT_|JWT)?(?:SECRET|secret)[_\s]?(?:KEY|key)?[\'"]?\s*\]\s*=\s*[\'"]([^\'"]{4,})[\'"]', re.I),
     "Hardcoded JWT secret via config dict-assignment (e.g. app.config['JWT_SECRET_KEY'])", "CRITICAL"),
]

JWT_ALG_PATTERNS = [
    # alg: 'none' or alg: "none"
    (re.compile(r'[\'"]alg[\'"]\s*:\s*[\'"]none[\'"]', re.I),
     "JWT alg:none bypass — algorithm set to 'none'", "CRITICAL"),
    # jwt.decode without verify
    (re.compile(r'jwt\.decode\s*\(\s*.*?verify\s*=\s*False', re.I | re.DOTALL),
     "JWT decode() with verify=False — signature bypass", "CRITICAL"),
    # jwt.decode without options={'verify_signature': True}
    (re.compile(r'jwt\.decode\s*\([^)]*\)', re.I | re.DOTALL),
     "JWT decode() — verify signature is explicitly enabled?", "LOW"),
    # HS256 with weak secret (< 32 chars)
    (re.compile(r'(?:SECRET|secret|KEY|key)\s*[:=]\s*[\'"]([\w\-]{1,31})[\'"]', re.I),
     "Weak JWT HS256 secret (<256 bits)", "HIGH"),
]

JWT_LIB_IMPORTS = re.compile(
    r'(?:import|from)\s+(?:jwt|PyJWT|python-jose|jose|authlib)', re.I
)


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS011" in ctx.skipped_detectors:
        return []
    findings = []

    for fp in ctx.get_source_files(extensions=(".py", ".js", ".ts", ".go", ".java", ".rb")):
        try:
            content = fp.read_text()
        except Exception:
            continue

        rel_path = str(fp.relative_to(ctx.path))

        # Check if file uses JWT libraries
        has_jwt_import = bool(JWT_LIB_IMPORTS.search(content))

        # 1. Check for hardcoded JWT secrets
        for pattern, title, severity in JWT_SECRET_PATTERNS:
            for match in pattern.finditer(content):
                secret_value = match.group(1)
                if any(skip in secret_value.lower() for skip in
                       ('***', 'your-', 'changeme', 'secrethere', 'placeholder', 'example')):
                    continue

                lineno = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=severity,
                    title=title,
                    detail=f"Found JWT secret in code: '{secret_value[:8]}...'. "
                           f"JWT secrets must be stored in environment variables or vaults.",
                    fix_suggestion="Move secret to environment variable or secrets manager. "
                                   "Rotate exposed secret immediately.",
                    references=["Hacking APIs Ch.8 Attacking Authentication"],
                    secret_value=secret_value,
                ))

        # 2. Check for JWT algorithm vulnerabilities
        for pattern, title, severity in JWT_ALG_PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count("\n") + 1

                # Lower severity for files without JWT imports (likely false positive)
                eff_severity = severity if has_jwt_import else (
                    "LOW" if severity == "HIGH" else "MEDIUM" if severity == "CRITICAL" else severity
                )

                if eff_severity == "LOW" and not has_jwt_import:
                    continue  # Skip low-severity without JWT imports

                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=eff_severity,
                    title=title,
                    detail=f"Detected: {match.group(0)[:100]}",
                    fix_suggestion="Use RS256/ES256 instead of HS256. Always verify signatures. "
                                   "Never allow 'none' algorithm.",
                    references=["Hacking APIs Ch.8", "OWASP: JWT Cheat Sheet"]
                ))

    return findings

```

---

### GS012 — `gs012_mass_assignment.py` (echelon 2, noise_tier `normal`, 120 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS012 — Mass Assignment Vulnerability Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects mass assignment vulnerability patterns:
- Django: request.POST in create/update without fields/exclude
- FastAPI/Starlette: request data spread into model without filtering
- Rails: params in create/update without strong_params/permit
- Flask: request.form in model constructor without filtering
- GraphQL: mutations accepting full input objects without allowlists

Sources: Hacking APIs Ch.11 Mass Assignment (No Starch Press)
"""
from . import AuditContext, Finding
import re

RULE_ID = "GS012"
ECHELON = 2
description = "Mass Assignment — unfiltered request data in model create/update"


# Patterns from Hacking APIs Ch.11 and real-world mass assignment vulns
PATTERNS = [
    # Django: Model.objects.create(**request.POST)
    (re.compile(r'\.objects\.(?:create|update|get_or_create|update_or_create)\s*\(\s*\*\*\s*request\.(?:POST|DATA|body|json)', re.I),
     "Django mass assignment via **request.POST/DATA", "HIGH",
     "Unfiltered request data in model create/update allows role/privilege escalation. "
     "Use ModelForm with 'fields' or serializer with 'fields/exclude'.",
     "Use ModelForm with explicit 'fields' list or DRF serializer with defined fields."),

    # Django: instance.field = request.POST.get() then save()
    (re.compile(r'\.(?:save|update)\s*\(\s*\)', re.I),
     "Possible mass assignment — check for unfiltered request.POST", "LOW",
     "Generic save/update — may be safe. Verify surrounding context for request.POST usage.",
     "Review if request data is filtered before assignment."),

    # FastAPI/Starlette: **request.json() / **body.dict() spread
    (re.compile(r'\*\*\s*(?:request\.(?:json|body|form|data)|body\.(?:dict|model_dump))\s*\(\s*\)', re.I),
     "FastAPI mass assignment via **request.json() spread", "HIGH",
     "Unpacking request body directly into model enables field injection. "
     "Use Pydantic model with Field(exclude=True) or explicit field whitelist.",
     "Define Pydantic schema with only allowed fields, or use model_dump(exclude={'admin', 'role'})."),

    # Rails: Model.new(params) / Model.create(params) / model.update(params) without permit
    (re.compile(r'(?:\.new|\.create|\.update|\.update_attributes|\.assign_attributes)\s*\(\s*(?:params|request\.params)', re.I),
     "Rails mass assignment — params without permit/require", "HIGH",
     "Direct params in model create/update bypasses strong parameters. "
     "Use params.require(:model).permit(:field1, :field2).",
     "Add params.require(:model).permit(:allowed_fields) before model assignment."),

    # GraphQL: mutation accepting full input object
    (re.compile(r'mutation\s+\w+\s*\(?\s*\$?\w*\s*:\s*(?:String|Input|JSON)', re.I),
     "GraphQL mutation accepting unrestricted input", "MEDIUM",
     "Unrestricted input type in GraphQL mutation enables mass assignment. "
     "Define explicit input types with only allowed fields.",
     "Use GraphQL input types with allowlisted fields, add field-level authorization."),

    # JavaScript: Object.assign(user, req.body)
    (re.compile(r'Object\.(?:assign|spread)\s*\(\s*\w+\s*,\s*(?:req|request)\.(?:body|params|query)', re.I),
     "JS/TS mass assignment via Object.assign/spread with request body", "HIGH",
     "Assigning request body directly to object allows privilege escalation.",
     "Whitelist allowed fields: const {name, email} = req.body; user.name = name; user.email = email."),
]

# Secondary patterns (context-dependent)
CONTEXT_PATTERNS = [
    (re.compile(r'(?:fields|exclude)\s*=\s*\([^)]*\)|fields\s*=\s*\[[^\]]*\]|fields\s*=\s*\{[^}]*\}', re.I),
     "Explicit field whitelist detected — likely safe"),
    (re.compile(r'(?:require|permit)\s*\([^)]*\)', re.I),
     "Strong parameters pattern detected — likely safe"),
    (re.compile(r'(?:schema|Schema|serializer)\s*[:.]\s*(?:\w+Serializer|ModelSchema)', re.I),
     "Serializer/schema usage detected — verify fields are restricted"),
]


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS012" in ctx.skipped_detectors:
        return []
    findings = []

    for fp in ctx.get_source_files(extensions=(".py", ".rb", ".js", ".ts", ".graphql", ".graphqls")):
        try:
            content = fp.read_text()
        except Exception:
            continue

        rel_path = str(fp.relative_to(ctx.path))

        # First check for primary mass assignment patterns
        for pattern, title, severity, detail, fix in PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count("\n") + 1

                # Skip LOW severity if file is likely safe (has explicit field lists)
                if severity == "LOW":
                    # Check nearby context for filtering patterns
                    context_ok = any(
                        cp.search(content[max(0, match.start()-200):match.start()+200])
                        for cp, _ in CONTEXT_PATTERNS[:2]
                    )
                    if context_ok:
                        continue

                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=severity,
                    title=title,
                    detail=detail,
                    fix_suggestion=fix,
                    references=["Hacking APIs Ch.11 Mass Assignment", "OWASP API4:2023"]
                ))

    return findings

```

---

### GS013 — `gs013_graphql_security.py` (echelon 2, noise_tier `normal`, 147 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS013 — GraphQL Security Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects GraphQL security misconfigurations:
- Introspection enabled in production
- No query depth limiting
- No rate limiting on GraphQL endpoint
- Field suggestions enabled
- Debug mode enabled
- Excessive error disclosure

Sources: Hacking APIs Ch.14 Attacking GraphQL (No Starch Press)
"""
from . import AuditContext, Finding
import re

RULE_ID = "GS013"
ECHELON = 2
description = "GraphQL security — introspection, depth limiting, error disclosure"


PATTERNS = [
    # Apollo Server: introspection enabled
    (re.compile(r'introspection\s*:\s*(?:true|1|yes)', re.I),
     "GraphQL introspection enabled", "HIGH",
     "Introspection exposes entire API schema to attackers, enabling automated attacks. "
     "Disable in production or restrict to authenticated/authorized users.",
     "Set 'introspection: false' in production or use Apollo plugin for conditional introspection."),

    # Apollo: debug mode
    (re.compile(r'debug\s*:\s*(?:true|1|yes)', re.I),
     "GraphQL debug mode enabled", "MEDIUM",
     "Debug mode leaks stack traces and internal logic to clients.",
     "Set 'debug: false' in production."),

    # No depth limiting
    (re.compile(r'(?:depth|maxDepth|query_depth|MAX_DEPTH)\s*[:=]\s*(\d+)', re.I),
     "GraphQL depth limit check", "INFO",
     "Verify depth limit is reasonable (recommended: 3-10). Current: {match.group(1)}.",
     "Ensure depth limit is < 10 to prevent recursive query DoS."),

    # Graphene-Django: introspection enabled
    (re.compile(r'graphql_view\s*\([^)]*graphiql\s*=\s*True', re.I),
     "Graphene-Django GraphiQL enabled", "HIGH",
     "GraphiQL in production exposes schema introspection and query interface.",
     "Set 'graphiql=False' in production Django settings."),

    # Hasura: no admin secret
    (re.compile(r'HASURA_GRAPHQL_ADMIN_SECRET\s*[:=]\s*[\'\"]?\s*[\'\"]?', re.I),
     "Hasura admin secret may be empty", "CRITICAL",
     "Empty HASURA_GRAPHQL_ADMIN_SECRET allows unauthenticated admin access.",
     "Set a strong HASURA_GRAPHQL_ADMIN_SECRET environment variable."),

    # GraphQL Yoga: cors
    (re.compile(r'cors\s*:\s*\{[^}]*origin\s*:\s*[\'\"]\*[\'\"]', re.I),
     "GraphQL CORS origin wildcard", "LOW",
     "CORS origin='*' allows cross-origin GraphQL queries from any domain.",
     "Restrict CORS origin to specific domains in production."),

    # Excessive error disclosure
    (re.compile(r'(?:stacktrace|stack_trace|include_stacktrace)\s*:\s*(?:true|1)', re.I),
     "GraphQL error stack traces exposed", "MEDIUM",
     "Including stack traces in GraphQL errors leaks internal paths and logic.",
     "Set 'includeStacktraceInErrorResponses: false' in production."),

    # Disable suggestions
    (re.compile(r'(?:fieldSuggestions|suggestions)\s*:\s*(?:true|1)', re.I),
     "GraphQL field suggestions enabled", "LOW",
     "Field suggestions help attackers discover field names via trial and error.",
     "Disable field suggestions in production."),
]

# Files that indicate GraphQL is in use
GRAPHQL_FILES = {
    ".graphql", ".graphqls",
    "schema.graphql", "schema.graphqls",
    "apollo-server.js", "apollo-server.ts", "apollo.config.js",
    "graphene.py",
}


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS013" in ctx.skipped_detectors:
        return []
    findings = []

    for fp in ctx.get_source_files(extensions=(".py", ".js", ".ts", ".yaml", ".yml", ".json", ".graphql", ".graphqls")):
        # Skip if not a GraphQL-related file
        is_graphql_file = (
            fp.suffix in (".graphql", ".graphqls") or
            fp.name in ("schema.graphql", "schema.graphqls", "apollo-server.js",
                        "apollo-server.ts", "apollo.config.js") or
            "apollo" in fp.name.lower() or
            "graphql" in fp.name.lower() or
            "hasura" in fp.name.lower()
        )

        try:
            content = fp.read_text()
        except Exception:
            continue

        # Check if file references GraphQL
        has_graphql_ref = bool(re.search(
            r'(?:graphql|GraphQL|apollo|Apollo|hasura|Hasura|graphene|Graphene)',
            content, re.I
        ))

        if not is_graphql_file and not has_graphql_ref:
            continue  # Skip non-GraphQL files

        rel_path = str(fp.relative_to(ctx.path))

        for pattern, title, severity, detail, fix in PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count("\n") + 1

                # For depth limit pattern, only report if value is > 10
                if "depth limit" in title.lower():
                    try:
                        depth_val = int(match.group(1))
                        if depth_val <= 10:
                            continue  # OK
                    except ValueError:
                        pass

                # Manual {match.group(N)} substitution — str.format() doesn't support method calls
                formatted_detail = re.sub(r'\{match\.group\((\d+)\)\}', lambda m: (match.group(int(m.group(1))) or ""), detail)

                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=rel_path,
                    line=lineno,
                    severity=severity,
                    title=title,
                    detail=formatted_detail,
                    fix_suggestion=fix,
                    references=["Hacking APIs Ch.14 Attacking GraphQL"]
                ))

    return findings

```

---

### GS014 — `gs014_credential_exposure.py` (echelon 2, noise_tier `normal`, 300 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS014 — Credential Exposure Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects credential exposure patterns from Redteam Kit:
- Unquoted service paths (Windows)
- Stored credentials in config files
- SAM/SYSTEM backup files
- Credential files in home directories
- AlwaysInstallElevated registry equivalent (Linux sudoers)
- DPAPI/Credential Manager files
- MacAfee SiteList.xml passwords
- Unattended installation files (autounattend.xml, kickstart)

Sources: Window Privilege Escalation, SSH Hardening & Offensive Mastery,
2025 Playbooks (Credential Stuffing)
"""
from . import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS014"
ECHELON = 2
description = "Credential exposure — stored credentials, backup auth files, weak sudoers"


# Files that indicate credential exposure.
# Entry shape: (patterns, title, severity, detail, fixture_sensitive).
# `fixture_sensitive=True` → skip test/fixture paths (vectors/, test/, tests/,
# fixtures/, dummyserver/, *.example/*.sample/*.template/*.test) — those are
# test fixtures / public materials, not real committed credentials.
CREDENTIAL_FILE_PATTERNS = [
    # Windows-like credential files
    (["*.sam", "*.sam.bak", "SYSTEM", "SYSTEM.bak", "ntds.dit"],
     "Potential SAM/SYSTEM backup — Windows credential database",
     "CRITICAL", "SAM/SYSTEM backups allow offline credential extraction.", False),

    # DPAPI master keys
    (["*/DPAPI/*", "*/Microsoft/Protect/*"],
     "DPAPI master key file — encrypted credential storage",
     "MEDIUM", "DPAPI keys may contain decryptable credentials if user password is known.", False),

    # Credential manager files
    (["*.rdp", "*.rdg", "credentials.xml", "SiteList.xml"],
     "Stored credential file (RDP/MacAfee/credential manager)",
     "HIGH", "RDP and credential manager files may contain saved passwords.", False),

    # SSH keys with weak paths
    (["id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key"],
     "Private key file — verify proper permissions and no passphrase",
     "MEDIUM", "Private keys should have 600 permissions and passphrase protection.", True),

    # Config files with potential credentials
    (["*.env", ".env.*", "*.envrc", ".credentials", "credentials.yml",
      "credentials.json", "credentials.ini", ".netrc"],
     "Environment/credential file — check for hardcoded secrets",
     "LOW", "These files should be gitignored. Verify no secrets are committed.", True),

    # Unattended installation files
    (["autounattend.xml", "unattend.xml", "Unattend.xml",
      "*.kickstart", "preseed.cfg", "answerfile*"],
     "Unattended installation file — may contain encoded passwords",
     "CRITICAL", "Unattended files often contain base64-encoded admin passwords.", False),

    # Shell history files (shouldn't be in repo)
    ([".bash_history", ".zsh_history", ".fish_history", ".psql_history", ".mysql_history"],
     "Shell history file in repo — may contain credentials in command lines",
     "MEDIUM", "Shell history files may contain passwords passed as command arguments.", False),
]

# PostgreSQL connection strings, extracted from CONTENT_PATTERNS so they get
# dedicated FP filters (self-reference, variable interpolation, placeholder
# passwords, documentation/docstring) instead of the old single-lookahead.
POSTGRES_CONN_RE = re.compile(
    r'postgres(?:ql)?://(?P<pg_user>[^:@]+):(?P<pg_pass>[^@]+)@',
    re.I,
)

# Placeholder/example passwords — PREFIX match, not exact token: password123@,
# your_password@, test_password@ are all documentation, not real creds. The old
# lookahead `(?!token@)` only matched the exact token@ and let these slip.
PG_PLACEHOLDER_RE = re.compile(
    r'(?:\*\*\*|passw(?:or)?d|pass|pwd|secret|change[_-]?me|example|your|xxx|'
    r'scott|tiger|user|test|admin|postgres(?:ql)?|demo|sample|dummy|'
    r'foo|bar|baz|redacted|placeholder)',
    re.I,
)

# Content-based patterns
CONTENT_PATTERNS = [
    # Base64-encoded admin password in autounattend
    (re.compile(r'<AdministratorPassword>.*?<Value>([^<]{20,})</Value>', re.I | re.DOTALL),
     "Base64-encoded admin password in unattend file", "CRITICAL",
     "Windows autounattend.xml contains encoded Administrator password. "
     "This is trivially decodable (base64)."),

    # WireGuard/OpenVPN keys in config
    (re.compile(r'PrivateKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}', re.I),
     "WireGuard private key in config", "HIGH",
     "WireGuard PrivateKey exposed in configuration file. "
     "Use external key storage or environment variable."),

    # sudoers: NOPASSWD for ALL commands
    (re.compile(r'^\s*\S+\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*NOPASSWD\s*:\s*ALL', re.I | re.MULTILINE),
     "sudoers NOPASSWD:ALL — unrestricted sudo without password", "HIGH",
     "NOPASSWD on ALL commands allows privilege escalation without re-authentication. "
     "Restrict to specific commands with NOPASSWD."),

    # sudoers: user with ALL=(ALL) ALL
    (re.compile(r'^\s*(\S+)\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*ALL', re.I | re.MULTILINE),
     "sudoers: full sudo access — verify it's intentional", "LOW",
     "Full sudo access detected. Verify user requires full privileges."),
]

# Public cert/key PEM headers — these are NOT private keys and must not be flagged.
PUBLIC_KEY_MARKERS = (
    "BEGIN CERTIFICATE", "BEGIN PUBLIC KEY", "BEGIN X509",
    "BEGIN TRUSTED CERTIFICATE", "BEGIN RSA PUBLIC KEY",
    "BEGIN EC PUBLIC KEY", "BEGIN DSA PUBLIC KEY",
)

# Directory components that mark a test/fixture path (not real credentials).
TEST_FIXTURE_COMPONENTS = {
    "vectors", "testdata", "fixtures", "__fixtures__", "tests", "test", "dummyserver",
}


def _match_glob(path: Path, pattern: str) -> bool:
    """Simple glob matching for credential file patterns."""
    import fnmatch
    # Handle path patterns like */DPAPI/*
    if "/" in pattern or "\\" in pattern:
        return fnmatch.fnmatch(str(path).replace("\\", "/"), pattern)
    return fnmatch.fnmatch(path.name, pattern)


def _is_test_fixture_path(rel_path: str) -> bool:
    """True if rel_path is a test vector / fixture / example file, not a real credential."""
    p = rel_path.replace("\\", "/").lower()
    parts = p.split("/")
    for comp in parts[:-1]:                     # directory components only
        if comp in TEST_FIXTURE_COMPONENTS:
            return True
    name = parts[-1]
    if name == "test.env":
        return True
    return name.endswith((".example", ".sample", ".template", ".test"))


def _in_docstring(content: str, pos: int) -> bool:
    """True if `pos` sits inside a \"\"\"...\"\"\" / '''...''' docstring block.

    Quote-parity is an approximation (acceptable per the brief's "context
    analysis" tool): a URL inside a string literal is an example, not a real
    credential, so a false "in docstring" only ever suppresses an FP.
    """
    for quote in ('"""', "'''"):
        if content[:pos].count(quote) % 2 == 1:
            return True
    return False


def _is_public_key_material(fp: Path) -> bool:
    """True if a .pem/.key file is a public certificate/key (not a private key).

    Covers three cases:
    1. binary (DER) content — a PEM private key is always ASCII/base64, so a
       binary .pem/.key is a DER certificate/public key;
    2. PEM headers that mark a public cert/key (BEGIN CERTIFICATE / PUBLIC KEY);
    3. raw OpenSSH public keys (ssh-rsa AAAA…, ssh-ed25519 …) stored in *.key.
    """
    try:
        head = fp.read_bytes()[:2048]
    except Exception:
        return False
    if not head:
        return False
    # Binary (DER) content cannot be a PEM private key (those are always ASCII).
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    if printable / len(head) < 0.9:
        return True
    text = head.decode("utf-8", errors="ignore")
    if any(m in text for m in PUBLIC_KEY_MARKERS):
        return True
    # OpenSSH public key without a PEM header (sometimes stored in *.key)
    stripped = text.lstrip()
    return stripped.startswith(("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ",
                                "ecdsa-sha2-", "sk-ssh-ed25519 ", "sk-ecdsa-"))


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS014" in ctx.skipped_detectors:
        return []
    findings = []

    # Get ALL files (not just source — credential files may be in any location)
    all_files = ctx.get_files()

    for fp in all_files:
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Check filename patterns
        for patterns, title, severity, detail, fixture_sensitive in CREDENTIAL_FILE_PATTERNS:
            if not any(_match_glob(fp, pat) for pat in patterns):
                continue

            # Don't flag SSH keys in .ssh/ directories (user home)
            if (fp.suffix in (".pem", ".key") or fp.name.startswith("id_")) and ".ssh/" in str(fp):
                continue

            # Skip test vectors / fixtures / examples (not real credentials)
            if fixture_sensitive and _is_test_fixture_path(rel_path):
                continue

            # .pem/.key that are public certs/keys — not private keys
            if fp.suffix in (".pem", ".key") and _is_public_key_material(fp):
                continue

            findings.append(Finding(
                rule_id=RULE_ID,
                file_path=rel_path,
                line=1,
                severity=severity,
                title=title,
                detail=detail,
                fix_suggestion="Remove from repository. Add to .gitignore. "
                               "Rotate any exposed credentials.",
                references=["Window Privilege Escalation Guide",
                            "SSH Hardening & Offensive Mastery"]
            ))

        # 2. Check content-based patterns (only for text files)
        if fp.suffix in (".xml", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json",
                         ".txt", ".md", ".sh", ".bash", ".py", ".rb", ""):
            try:
                content = fp.read_text()
            except Exception:
                continue

            for pattern, title, severity, detail in CONTENT_PATTERNS:
                for match in pattern.finditer(content):
                    lineno = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity=severity,
                        title=title,
                        detail=detail,
                        fix_suggestion="Remove hardcoded credential. Use environment variables "
                                       "or secrets manager. Rotate exposed secrets.",
                        references=["Redteam Kit", "2025 Playbooks - Credential Stuffing"]
                    ))

            # 3. PostgreSQL connection strings — dedicated FP filters.
            # Skip documentation files (examples, not real creds).
            if fp.suffix.lower() not in (".md", ".txt", ".rst"):
                for match in POSTGRES_CONN_RE.finditer(content):
                    pg_user = match.group("pg_user").strip()
                    pg_pass = match.group("pg_pass").strip()
                    # user:user@ / postgres:postgres@ / remnawave:remnawave@ — stub self-reference
                    if pg_pass.lower() == pg_user.lower():
                        continue
                    # ${ENV} / %(VAR) / {vault} / <password> — variable reference, no secret
                    if pg_pass.startswith(("$", "%", "{", "<")):
                        continue
                    # placeholder/example passwords (prefix match)
                    if PG_PLACEHOLDER_RE.match(pg_pass):
                        continue
                    # regex-pattern self-flagging: a password containing regex
                    # alternation/groups is a detector's own pattern, not a URL
                    if "|" in pg_pass or "(?:" in pg_pass:
                        continue
                    # URL in a commented-out line (example, not a live credential)
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    if content[line_start:match.start()].lstrip().startswith(("#", "//", "--")):
                        continue
                    # URL inside a docstring (example, not a credential)
                    if fp.suffix.lower() == ".py" and _in_docstring(content, match.start()):
                        continue
                    lineno = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity="HIGH",
                        title="PostgreSQL connection string with embedded password",
                        detail="Database URL contains password in plaintext. Use environment variable.",
                        fix_suggestion="Remove hardcoded credential. Use environment variables "
                                       "or secrets manager. Rotate exposed secrets.",
                        references=["Redteam Kit", "2025 Playbooks - Credential Stuffing"]
                    ))

    return findings

```

---

### GS015 — `gs015_entry_points.py` (echelon 1, noise_tier `noisy`, 158 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS015 — Python Entry Point Coverage Detector (Inspired by Deepsec)
Echelon: 1 (SOURCE)
Noise Tier: noisy

Marks every Python HTTP handler as a candidate for AI review.
Does NOT flag vulnerabilities — just ensures the AI sees every entry point.

Covers: Flask, FastAPI, Django, Sanic, Tornado, aiohttp, Falcon, Bottle
"""
from . import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS015"
ECHELON = 1
NOISE_TIER = "noisy"
description = "Entry-point coverage — marks HTTP handlers for AI review (noisy matcher)"


# Entry point patterns for Python frameworks
ENTRY_PATTERNS = [
    # FastAPI / Starlette
    (re.compile(r'@\w+\.(?:get|post|put|delete|patch|options|head|route)\s*\(', re.I),
     "FastAPI/Starlette route handler", "fastapi"),
    
    # Flask
    (re.compile(r'@\w+\.(?:route|get|post|put|delete|patch)\s*\(', re.I),
     "Flask route handler", "flask"),
    
    # Django views (class-based)
    (re.compile(r'class\s+\w+\((?:APIView|ViewSet|ModelViewSet|GenericAPIView)', re.I),
     "Django REST class-based view", "django"),
    
    # Django views (function-based)
    (re.compile(r'@api_view\s*\(', re.I),
     "Django REST function-based view", "django"),
    
    # Sanic
    (re.compile(r'@\w+\.(?:get|post|put|delete|patch|route|websocket)\s*\(', re.I),
     "Sanic route handler", "sanic"),
    
    # Tornado
    (re.compile(r'class\s+\w+\s*\(\s*(?:tornado\.web\.)?RequestHandler', re.I),
     "Tornado request handler", "tornado"),
    
    # aiohttp
    (re.compile(r'async\s+def\s+\w+\s*\(\s*request\s*:\s*(?:aiohttp\.)?\w*Request', re.I),
     "aiohttp request handler", "aiohttp"),
    
    # Falcon
    (re.compile(r'class\s+\w+\s*\(\s*:\s*Resource', re.I),
     "Falcon resource handler", "falcon"),

    # Generic HTTP method handlers
    (re.compile(r'def\s+(?:do_GET|do_POST|do_PUT|do_DELETE|do_PATCH)\s*\(', re.I),
     "BaseHTTPServer handler", "generic"),
    
    # WSGI/ASGI apps
    (re.compile(r'(?:app|application)\s*=\s*\w+\(', re.I),
     "WSGI/ASGI application entry", "generic"),
]

# Paths to skip — not real entry points, just demo/test/sample code
_SKIP_PATH_PATTERNS = re.compile(
    r'(?:/|\A)(?:tests?|fixtures?|examples?|samples?|demo|docs?)/',
    re.IGNORECASE)
TARGET_GLOBS = [
    "**/routes/**/*.py",
    "**/views/**/*.py", 
    "**/handlers/**/*.py",
    "**/api/**/*.py",
    "**/endpoints/**/*.py",
    "**/controllers/**/*.py",
    "**/routers/**/*.py",
    "**/app.py",
    "**/main.py",
    "**/server.py",
    "**/urls.py",
    "**/wsgi.py",
    "**/asgi.py",
]


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS015" in ctx.skipped_detectors:
        return []
    findings = []

    # Only target Python files in entry-point directories
    for fp in ctx.get_files(extensions=(".py",)):
        rel_path = str(fp.relative_to(ctx.path))
        
        # Check if file is in an entry-point location
        is_entry_point = any(
            fp.match(glob) for glob in TARGET_GLOBS
        )
        
        # Also check files that aren't in obvious entry-point dirs but contain routes
        if not is_entry_point:
            continue

        # Skip tests and non-code
        if ctx.is_test_file(fp) or ctx.is_non_code_file(fp):
            continue
        # Skip demo/test/sample directories
        if _SKIP_PATH_PATTERNS.search(rel_path):
            continue

        try:
            content = fp.read_text()
        except Exception:
            continue

        found_framework = None
        for pattern, title, framework in ENTRY_PATTERNS:
            matches = list(pattern.finditer(content))
            if matches:
                found_framework = framework
                
                # Report up to 10 entry points per file
                for match in matches[:10]:
                    lineno = content[:match.start()].count("\n") + 1
                    matched_text = match.group(0)[:60]
                    
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity="INFO",
                        title=title,
                        detail=f"Entry point detected: {matched_text}. "
                               f"Marked for AI security review.",
                        fix_suggestion="AI review will check for auth, rate limiting, input validation.",
                        noise_tier=NOISE_TIER,
                        references=["Deepsec-inspired entry-point coverage"]
                    ))

        # If file is in entry-point dir but no patterns matched, mark whole file
        if not found_framework and is_entry_point:
            findings.append(Finding(
                rule_id=RULE_ID,
                file_path=rel_path,
                line=1,
                severity="INFO",
                title="Entry-point directory file — AI review recommended",
                detail=f"File in entry-point directory ({rel_path.split('/')[0]}) "
                       f"with no recognized framework patterns. Manual review needed.",
                fix_suggestion="AI will review for custom framework security patterns.",
                noise_tier=NOISE_TIER,
                references=["Deepsec-inspired entry-point coverage"]
            ))

    return findings

```

---

### GS016 — `gs016_linux_priv_esc.py` (echelon 2, noise_tier `normal`, 151 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS016 — Linux Privilege Escalation Paths Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects privilege escalation vectors learned from:
- OverTheWire Bandit levels 0-12
- Common Linux misconfigurations
- SUID/GUID/capability abuse patterns
- Writable cron/systemd paths
- World-readable sensitive configs
- Command obfuscation techniques (spaces, dashes, hidden files)

Sources: Bandit wargame, CIS Benchmarks, OWASP Linux Hardening
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS016"
ECHELON = 2
NOISE_TIER = "normal"
description = "Linux privilege escalation paths — SUID, cron, sudo, capabilities, world-readable secrets"

# ── Regex patterns ──────────────────────────────────────────────────────────

# SUID/GUID binaries that shouldn't have it
SUID_BINARIES = re.compile(
    r'chmod\s+[47]\d{2,3}\s+/(?!usr/local|tmp/).*'
    r'|chmod\s+u\+s\s+/(?!usr/local|tmp/).*'
    r'|-rwsr-xr-x.*/(?!usr/(bin|lib|libexec|sbin)|sbin/|bin/).*',
    re.MULTILINE,
)

# Sudo NOPASSWD for non-root users
SUDO_NOPASSWD = re.compile(
    r'^\s*[^#\s]+\s+ALL\s*=\s*\(ALL\)\s*NOPASSWD\s*:\s*ALL',
    re.MULTILINE,
)

# World-readable files matching password/shadow/key patterns
WORLD_READABLE_SECRETS = re.compile(
    r'^-r..r..r[-x].*\s+(/etc/(shadow|passwd|gshadow|group)\b'
    r'|/home/[^/]+/\.(ssh|gnupg|aws|config/gcloud)/\S+'
    r'|.*\.(pem|key|p12|pfx|jks|keystore)$)',
    re.MULTILINE,
)

# Cron jobs or systemd timers with writable scripts
WRITABLE_CRON = re.compile(
    r'^\s*[^#].*\s+(/home/|/tmp/|/var/tmp/|/opt/)\S+\.(sh|py|rb|pl)\b',
    re.MULTILINE,
)

# Files with leading dashes or special characters (Bandit L2 obfuscation)
OBFUSCATED_FILENAMES = re.compile(
    r'^\s*(-[rwx-]{9}|[rwx-]{9})\s+.*\s+'
    r'(--[\w\s-]+|\.\.\.[\w-]+|[^\w./-][^\w./-][\w\s.-]+)\s*$',
    re.MULTILINE,
)

# Dangerous capabilities on binaries (cap_setuid, cap_sys_admin, etc.)
DANGEROUS_CAPABILITIES = re.compile(
    r'cap_setuid\+e[ip]|cap_sys_admin\+e[ip]|cap_dac_override\+e[ip]'
    r'|cap_net_raw\+e[ip]|cap_sys_ptrace\+e[ip]',
)

# PATH hijack — writable directories early in PATH
WRITABLE_PATH = re.compile(
    r'(export\s+)?PATH\s*=\s*["\']?(\.:?|/tmp|/var/tmp|/dev/shm)[^"\']*["\']?',
)

# Python eval/exec with user input (Bandit-style code injection)
DANGEROUS_EVAL = re.compile(
    r'\b(eval|exec|__import__)\s*\(\s*(input|sys\.argv|request\.\w+|raw_input)',
)

# Password in command line arguments (visible in ps)
PASSWORD_IN_CMD = re.compile(
    r'(passwd|password|pass|pwd|secret|token|key)\s*=\s*["\'][^\s]{4,}["\']'
    r'\s+(ssh|mysql|psql|curl|wget|aws|gcloud)\b',
)


def _check_line(line: str, lineno: int, file_path: str) -> list[Finding]:
    """Check a single line against all patterns."""
    findings = []

    checks = [
        (SUID_BINARIES, "CRITICAL", "SUID binary outside standard system paths — potential privilege escalation"),
        (SUDO_NOPASSWD, "CRITICAL", "Sudo NOPASSWD:ALL — unrestricted root access without password"),
        (WORLD_READABLE_SECRETS, "CRITICAL", "World-readable credential file — secrets exposed to all users"),
        (DANGEROUS_CAPABILITIES, "HIGH", "Dangerous Linux capability on binary — container escape or privilege escalation"),
        (WRITABLE_CRON, "HIGH", "Writable script in user directory executed by cron — privilege escalation via cron hijack"),
        (DANGEROUS_EVAL, "HIGH", "eval/exec with untrusted input — arbitrary code execution"),
        (WRITABLE_PATH, "MEDIUM", "Writable directory in PATH early entry — PATH hijacking risk"),
        (PASSWORD_IN_CMD, "MEDIUM", "Password in command-line argument — visible in /proc and ps output"),
        (OBFUSCATED_FILENAMES, "LOW", "Obfuscated filename (leading dashes, triple dots) — anti-forensics or hiding technique"),
    ]

    for pattern, severity, message in checks:
        if pattern.search(line):
            findings.append(Finding(
                rule_id=RULE_ID,
                severity=severity,
                file_path=file_path,
                line=lineno,
                detail=message,
                fix_suggestion=f"Review and remove the privilege escalation vector: {line.strip()[:100]}",
                cwe="CWE-269" if severity == "CRITICAL" else "CWE-732" if severity == "HIGH" else "CWE-668",
            ))

    return findings


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect privilege escalation paths in shell scripts, configs, playbooks."""
    if RULE_ID in ctx.skipped_detectors:
        return []

    findings = []
    target_extensions = {'.sh', '.bash', '.py', '.rb', '.pl',
                         '.conf', '.cfg', '.ini', '.service',
                         '.yaml', '.yml', '.toml',
                         'sshd_config', 'sudoers', 'crontab',
                         'Dockerfile', 'Makefile'}

    for fp in ctx.get_source_files():
        # Check by extension or filename
        ext = fp.suffix.lower()
        name = fp.name.lower()
        if ext not in target_extensions and name not in target_extensions:
            continue
        if ext in ('.md', '.txt', '.org', '.rst'):
            continue

        try:
            content = fp.read_text()
        except Exception:
            continue

        for lineno, line in enumerate(content.split('\n'), 1):
            if not line.strip() or line.strip().startswith('#'):
                continue
            findings.extend(_check_line(line, lineno, str(fp)))

    return findings

```

---

### GS017 — `gs017_weak_passwords.py` (echelon 2, noise_tier `normal`, 331 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS017 — Weak & Default Passwords Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects weak and default credentials — a top-3 fintech vulnerability per 2026 pentests:
- Hardcoded default passwords (admin:admin, root:root)
- Weak password policies (no complexity, short minimums)
- Default credentials in configs, Dockerfiles, .env files
- Common Russian/enterprise default passwords
- Database connection strings with weak passwords

Sources: 2026 Fintech Pentest Report, OWASP ASVS V2.1, PCI-DSS 8.3
"""
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

# Paths that can never hold a real production credential — benchmark/calibration
# corpora (deliberately vulnerable), tutorials/examples, vendored deps. Mirrors the
# EXCLUDE_PATH_RE of sibling detectors (GS029/GS034/GS035/GS040); get_source_files()
# only drops tests/fixtures, so these leak into the scan.
EXCLUDE_PATH_RE = re.compile(
    r'(?:^|[/\\])'
    r'(?:benchmark|calibration|examples?|samples?|tutorials?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|third[_-]party)'
    r'(?:[/\\]|$)',
    re.IGNORECASE,
)

# ── Default credential pairs ─────────────────────────────────────────────────

# Common Russian/enterprise default:password pairs
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

# Hardcoded passwords in variable assignments. The key is captured so a value
# equal to its own key (SECRET = "SECRET") can be filtered as a placeholder stub.
HARDCODED_PASSWORD_VARS = re.compile(
    r'^\s*(?P<k>PASSWORD|PASSWD|PASS|PWD|SECRET|ADMIN_PASS|DB_PASS|DB_PASSWORD|API_SECRET)'
    r'\s*[:=]\s*[\'"](?P<v>[^\'"]{1,20})[\'"]\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Weak password policy (min length < 8, no complexity)
WEAK_PASSWORD_POLICY = re.compile(
    r'(?:min(?:imum)?[_\s]*(?:password|pwd)[_\s]*(?:length|len|size))\s*[:=]\s*([0-7])\b',
    re.IGNORECASE,
)

# .env files with short passwords (< 8 chars). The bare KEY token is dropped — it
# was a documented noise source (KEY=dev, key=s, …) — in favour of explicit *_KEY
# tokens that are actually secrets. Longest alternatives first so SECRET_KEY= is
# not consumed as SECRET.
SHORT_ENV_PASSWORDS = re.compile(
    r'^\s*(?P<k>PASSWORD|PASS|PWD|SECRET_KEY|SECRET|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY|ENCRYPTION_KEY)'
    r'\s*=\s*[\'"]?(?P<v>[A-Za-z0-9_@#.\-]{1,7})[\'"]?\s*$',
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
    r'(?:password|пароль)\s*[:=]\s*(?P<v>\S+)\s*$',
    re.IGNORECASE | re.MULTILINE,
)


def _is_placeholder(value: str) -> bool:
    """Filter out placeholder/example values."""
    return any(skip in value.lower() for skip in (
        '***', 'your-', 'changeme', 'placeholder', 'example',
        'test', 'xxxx', 'secrethere', 'put_your', 'replace',
        'ваш_', 'пример',
    ))


# Values that are never passwords — default args (password=None), booleans,
# and numeric sentinels that leak through short-value rules.
ENV_SENTINELS = frozenset({
    "none", "null", "nil", "true", "false", "undefined", "nan", "inf",
})


# Common weak/default passwords. HARDCODED_PASSWORD_VARS only fires when the
# value looks plausibly WEAK — flagging strong hardcoded secrets is out of
# scope for a "Weak & Default Passwords" detector and was producing a flood of
# benchmark-corpus FP (`password = 'SuperSecret331'`).
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
    """True if `value` plausibly looks like a WEAK/default password.

    In scope: all-digit values, short values (<8 chars), single-case words,
    and short word+digits patterns. Out of scope: long (>12) mixed-case values
    with digits/punctuation (hardcoded-secret detectors' job), and mixed-case
    word+digits longer than 10 chars (SuperSecret5 — a deliberate password, not
    a default stub). This cuts the synthetic benchmark FP (`password =
    'SuperSecret331'`) while keeping Pass1234 / Summer2024 / P@ssw0rd in scope.
    """
    v = value.strip()
    if not v:
        return False
    low = v.lower()
    if low in ENV_SENTINELS:
        return False                              # None/true/false/null — not a password
    if low in WEAK_VALUE_WORDS:
        return True
    if v.isdigit():
        return True                               # all-digit → weak regardless of length
    if len(v) > 12:
        return False                              # long mixed → not weak (heuristic)
    if len(v) < 8:
        return True                               # short → weak
    if v.isalpha() and (v.islower() or v.isupper()):
        return True                               # single-case word → weak
    if re.fullmatch(r"[a-z]+[0-9]{1,4}", low):    # word + trailing digits (Pass1234/Summer2024)
        # Mixed-case forms long enough are deliberate, not default stubs —
        # only short ones stay in scope for a *weak* password detector.
        is_mixed_case = any(c.isupper() for c in v) and any(c.islower() for c in v)
        if is_mixed_case and len(v) > 10:
            return False
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

        # Path exclusion: benchmark/calibration/examples/vendor can never hold
        # a real production credential.
        if EXCLUDE_PATH_RE.search(rel_path):
            continue

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
            password_key = match.group("k")
            password_value = match.group("v")
            if _is_placeholder(password_value):
                continue
            if password_value.strip().lower() == password_key.strip().lower():
                continue  # self-reference placeholder (SECRET = "SECRET")
            if len(password_value) >= 20:
                continue  # Skip long random-looking strings
            if password_value.startswith("$"):
                continue  # shell expansion (${N:-...} / $VAR), not a literal
            if password_value.startswith(("/", "./", "../", "~")) or re.match(r"^[A-Za-z]:[\\/]", password_value):
                continue  # path value (PWD = "/app"), not a credential
            if not _is_weak_value(password_value):
                continue  # strong/non-weak value — out of scope for GS017
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
                if _is_placeholder(env_value):
                    continue  # PASSWORD=xxxx, SECRET=test — unfilled templates
                if len(env_value) < 5:
                    if env_value.lower() in ENV_SENTINELS:
                        continue  # default arg / boolean / numeric sentinel
                    if env_value.lower() == env_key:
                        continue  # self-reference: KEY="key"
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
            commented_value = match.group("v")
            if _is_placeholder(commented_value) or commented_value.startswith(("$", "{", "%", "<", "(")):
                continue  # placeholder/reference in docs, not a literal credential
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

---

### GS018 — `gs018_payment_abuse.py` (echelon 2, noise_tier `normal`, 331 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS018 — Payment Logic Abuse Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects business-logic vulnerabilities in payment/fintech code —
the #2 finding in 2026 fintech pentest reports (scanners are blind to these):

- Missing idempotency on payment callbacks (double cashback)
- Promo code abuse (redeem without locking)
- Race conditions in balance updates (no SELECT FOR UPDATE)
- Cancel/refund after payment without state validation
- Negative amount/price validation missing
- Float arithmetic for money (rounding exploit)
- Webhook handlers without signature verification (replay attacks)
- SMS/notification abuse in payment flows

Sources: 2026 Fintech Pentest Report, OWASP ASVS V5 (Business Logic)
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS018"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Payment logic abuse — double cashback, promo code abuse, "
    "race conditions, rounding, missing idempotency"
)

# ── Regex patterns ──────────────────────────────────────────────────────────

# 1. Missing idempotency keys on payment/callback endpoints
MISSING_IDEMPOTENCY = re.compile(
    r'(?:@(?:app|router|bp|blueprint)\\.(?:route|post|get|put).*\n'
    r'^(?!.*(?:idempotenc|idempotent|idempotency_key|idempotencyKey|'
    r'X-Idempotency|duplicate_check|already_processed))'
    r'.*def\s+(?:payment_?callback|payout_?callback|webhook|'
    r'charge_?callback|transaction_?callback|cashback))',
    re.IGNORECASE | re.MULTILINE,
)

# 2. Promo code / coupon redeem without locking
PROMO_REDEEM_NO_LOCK = re.compile(
    r'def\s+(?:redeem|apply|activate|use)[_(].*(?:promo|coupon|discount|code|voucher)',
    re.IGNORECASE,
)

PROMO_WITHOUT_LOCK_CHECK = re.compile(
    r'promo.*(?:count|usage|uses|redeemed).*\\+=|'
    r'promo.*\\.save\\s*\\(\\)(?!.*select_for_update|with transaction|atomic)',
    re.IGNORECASE | re.DOTALL,
)

# 3. Balance/account update without atomic locking
BALANCE_RACE_CONDITION = re.compile(
    r'(?:balance|amount|credit|debit|wallet)\\s*[+\\-]?=\\s*'
    r'(?!.*(?:\\.select_for_update|SELECT.*FOR UPDATE|'
    r'BEGIN.*COMMIT|with.*transaction|@transaction\\.atomic|'
    r'UPDATE.*WHERE.*balance))',
    re.IGNORECASE | re.DOTALL,
)

# Simple balance increment without protection
RAW_BALANCE_INCREMENT = re.compile(
    r'(?:balance|wallet|account)\\s*\\.\\s*(?:balance|amount|sum)\\s*\\+=\\s*',
    re.IGNORECASE,
)

# 4. Cancel/refund after payment without state validation
CANCEL_MISSING_STATE_CHECK = re.compile(
    r'def\s+(?:cancel|refund|void|chargeback|reverse|rollback)\b',
    re.IGNORECASE,
)

# Payment-domain signal required inside a cancel/refund/rollback function body.
# DB-driver rollback()/cancel() (peewee/django/twisted) carry none of these and
# are filtered out (see DETECTOR_BRIEF_GS018.md, Лид 4).
PAYMENT_CONTEXT = re.compile(
    r'\b(?:payment|invoice|checkout|cashback|subscription|billing)(?:_\w+)?\b|'
    r'\border[._](?:id|number|status|state|total|amount|line)|'
    r'\bcharge[._](?:id|amount|status)|'
    r'\brefund[._](?:amount|id|status|reason)|'
    r'\btransaction[._]id|'
    r'\bpurchase[._](?:id|order|total)',
    re.IGNORECASE,
)

STATE_CHECK_MISSING = re.compile(
    r'(?:cancel|refund|void|reverse).*'
    r'(?!.*(?:\\.status\\s*==|\\.state\\s*==|if.*status|'
    r'can_be_cancelled|can_be_refunded|is_refundable|is_cancellable))',
    re.IGNORECASE | re.DOTALL,
)

# 5. Float arithmetic for money (should use Decimal)
FLOAT_MONEY = re.compile(
    r'(?:price|amount|sum|total|balance|cost|fee|tax|commission|'
    r'cashback|bonus|discount|payment|charge|refund|deposit|withdrawal)'
    r'\s*=\s*float\s*\(.*?\)\s*[-+*/%]',
    re.IGNORECASE,
)

# Float operations on money
FLOAT_MONEY_OP = re.compile(
    r'(?:float|int)\\(.*(?:price|amount|sum|total|balance|cost|fee|tax|'
    r'commission|cashback|bonus|payment)\\)',
    re.IGNORECASE,
)

# 6. Webhook handler without signature verification
WEBHOOK_NO_SIGNATURE = re.compile(
    r'@(?:app|router|bp|blueprint)\\.(?:route|post).*(?:webhook|callback|hook)',
    re.IGNORECASE,
)

NO_SIG_VERIFY = re.compile(
    r'webhook|callback.*'
    r'(?!.*(?:verify.*signature|verify_signature|validate.*signature|'
    r'hmac|X-Signature|X-Hub-Signature|webhook.*secret|sha256|sha512|'
    r'signature_header))',
    re.IGNORECASE | re.DOTALL,
)

# 7. Rate limiting missing on sensitive payment ops
NO_RATE_LIMIT_PAYMENT = re.compile(
    r'@(?:app|router|bp)\\.(?:route|post).*(?:payment|payout|transfer|'
    r'withdraw|deposit|charge|redeem|checkout|topup)'
    r'(?!.*(?:rate_limit|RateLimit|throttle|Throttle|limiter))',
    re.IGNORECASE | re.DOTALL,
)

# 8. Negative amount validation missing
MISSING_NEGATIVE_CHECK = re.compile(
    r'(?:amount|price|sum|total)\s*=\s*(?:float|int|Decimal)\s*\(.*request',
    re.IGNORECASE,
)


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS018" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # Skip if file has no payment-related keywords at all
        if not re.search(r'payment|payout|cashback|promo|coupon|'
                         r'balance|wallet|refund|chargeback|webhook|'
                         r'checkout|invoice|transaction|billing',
                         content, re.IGNORECASE):
            continue

        # 1. Missing idempotency on payment callbacks
        # (We use a combined approach: find payment callback functions,
        #  then check if they have idempotency logic)
        payment_endpoints = re.finditer(
            r'def\s+(payment_?callback|payout_?callback|webhook|'
            r'charge_?callback|transaction_?callback|cashback)\s*\(',
            content, re.IGNORECASE,
        )
        for match in payment_endpoints:
            # Get ~20 lines around the function
            func_start = match.start()
            func_end = min(func_start + 2000, len(content))
            func_body = content[func_start:func_end]

            if not re.search(r'idempotenc|duplicate|already.processed|'
                            r'unique.*constraint|once.*only', func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Payment callback without idempotency: {match.group(0)}",
                    detail="No idempotency key or duplicate check found. Risk: double cashback/charge.",
                    fix_suggestion="Add idempotency key (UUID per transaction). Check before processing. Use DB unique constraint on payment_id.",
                    noise_tier="normal",
                ))

        # 2. Promo code redeem without locking
        promo_funcs = PROMO_REDEEM_NO_LOCK.finditer(content)
        for match in promo_funcs:
            name_m = re.match(r'def\s+(\w+)', content[match.start():])
            fname = name_m.group(1).lower() if name_m else ''
            # read-only check (has_/is_/get_/check_/can_/pending), not a redeem action
            if re.search(r'(?:^|_)(?:is|has|have|get|check|can|exists|pending)(?:_|$)', fname):
                continue
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'select_for_update|SELECT.*FOR UPDATE|'
                            r'with.*transaction|@transaction\.atomic|'
                            r'BEGIN|lock|Lock|mutex|Mutex',
                            func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Promo code redeem without locking: {match.group(0)}",
                    detail="Promo code redemption without DB lock or transaction. Risk: concurrent reuse.",
                    fix_suggestion="Use SELECT FOR UPDATE on promo code row. Wrap in transaction with commit on success.",
                    noise_tier="normal",
                ))

        # 3. Balance update without atomic protection
        for match in RAW_BALANCE_INCREMENT.finditer(content):
            ctx_end = min(match.start() + 1000, len(content))
            ctx_body = content[match.start():ctx_end]
            if not re.search(r'select_for_update|SELECT.*FOR UPDATE|'
                            r'with.*transaction|@transaction|'
                            r'atomic|lock|Lock|Mutex',
                            ctx_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Balance update without atomic locking — race condition risk",
                    detail=f"Direct balance += at line {_lineno(content, match.start())} without SELECT FOR UPDATE or transaction isolation.",
                    fix_suggestion="Use SELECT ... FOR UPDATE before balance modification. Or use UPDATE ... SET balance = balance + ? WHERE ... RETURNING balance.",
                    noise_tier="normal",
                ))

        # 4. Cancel/refund without state check
        cancel_funcs = CANCEL_MISSING_STATE_CHECK.finditer(content)
        for match in cancel_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not PAYMENT_CONTEXT.search(func_body):
                continue
            if not re.search(r'\.status\s*==|\.state\s*==|if\s+.*status|'
                            r'can_be_cancelled|can_be_refunded|'
                            r'is_refundable|is_cancellable|allowed_states',
                            func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Cancel/refund without state validation: {match.group(0)}",
                    detail="Cancel/refund function lacks state check. Risk: refund after completion.",
                    fix_suggestion="Validate order status before processing cancel/refund. Define allowed transition states explicitly.",
                    noise_tier="normal",
                ))

        # 5. Float for money
        for match in FLOAT_MONEY.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Float used for monetary value: {match.group(0).strip()[:80]}",
                detail="Float arithmetic for money leads to rounding errors exploitable for arbitrage.",
                fix_suggestion="Use Decimal(str(amount)) for all monetary calculations. Never use float for money.",
                noise_tier="precise",
            ))

        # 6. Webhook without signature verification
        webhook_routes = WEBHOOK_NO_SIGNATURE.finditer(content)
        for match in webhook_routes:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'verify.*signature|verify_signature|'
                            r'validate.*signature|hmac|X-Signature|'
                            r'X-Hub-Signature|webhook.*secret|sha256|sha512|'
                            r'signature_header|compute_signature',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Webhook handler without signature verification",
                    detail="Webhook/callback endpoint lacks HMAC signature validation. Vulnerable to forged callbacks.",
                    fix_suggestion="Validate webhook signature using shared secret (HMAC-SHA256). Compare constant-time. Include timestamp to prevent replay.",
                    noise_tier="precise",
                ))

        # 7. Rate limiting missing on payment endpoints
        payment_routes = list(re.finditer(
            r'@(?:app|router|bp|blueprint)\\.(?:route|post|get).*'
            r'(?:payment|payout|transfer|withdraw|deposit|charge|redeem|checkout|topup)',
            content, re.IGNORECASE,
        ))
        for match in payment_routes:
            route_end = min(match.end() + 2000, len(content))
            route_body = content[match.start():route_end]
            if not re.search(r'rate_limit|RateLimit|throttle|Throttle|'
                            r'limiter|@limiter|@rate', route_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Payment endpoint without rate limiting",
                    detail="Sensitive payment endpoint lacks rate limit protection.",
                    fix_suggestion="Add rate limiting: max 5-10 requests/minute per user for payment endpoints. Use token bucket or sliding window.",
                    noise_tier="normal",
                ))

        # 8. Negative amount validation
        amount_lines = MISSING_NEGATIVE_CHECK.finditer(content)
        for match in amount_lines:
            ctx_end = min(match.end() + 500, len(content))
            ctx_body = content[match.end():ctx_end]
            if not re.search(r'(?:if|assert).*(?:>\\s*0|>=|positive|'
                            r'amount.*>[^=]|price.*>[^=]|validate.*amount|'
                            r'raise.*ValueError)',
                            ctx_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Amount from request without negative validation",
                    detail="Amount/price taken from request without checking > 0. Negative amounts can exploit refund logic.",
                    fix_suggestion="Validate all amounts: must be > 0, within allowed range. Add explicit check before processing.",
                    noise_tier="normal",
                ))

    return findings

```

---

### GS019 — `gs019_auth_session.py` (echelon 2, noise_tier `normal`, 386 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS019 — Authentication & Session Weaknesses Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects auth/session vulnerabilities — #5 in fintech pentest reports:

- SMS exhaustion / no rate limiting on OTP sends
- Session fixation (no regeneration after login)
- Weak session token generation (predictable)
- Missing HttpOnly/Secure flags on session cookies
- JWT without expiration (immortal tokens)
- Hardcoded session secrets
- Missing MFA for sensitive operations
- Auth bypass via missing decorators
- OTP brute-force protection missing
- Password reset token weaknesses

Sources: 2026 Fintech Pentest Report, OWASP ASVS V2/V3, PCI-DSS 8
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS019"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Auth/session weaknesses — SMS exhaustion, session fixation, "
    "weak tokens, missing cookie flags, immortal JWT, OTP brute-force"
)

# ── Regex patterns ──────────────────────────────────────────────────────────

# 1. OTP/SMS send without rate limiting
OTP_SEND_PATTERNS = re.compile(
    r'def\s+(?:send_otp|send_sms|send_code|send_verification|'
    r'request_otp|otp_request)',
    re.IGNORECASE,
)

NO_COOLDOWN_CHECK = re.compile(
    r'(?:send_otp|send_sms|send_code).*'
    r'(?!.*(?:cooldown|rate_limit|RateLimit|throttle|last_sent|'
    r'resend.*(?:second|minute|hour)|wait|delay|backoff))',
    re.IGNORECASE | re.DOTALL,
)

# 2. Session fixation — login without session regeneration
LOGIN_PATTERNS = re.compile(
    r'def\s+(?:login|signin|sign_in|log_in)\s*\(',
    re.IGNORECASE,
)

NO_SESSION_REGENERATION = re.compile(
    r'(?:login|signin|sign_in|log_in).*'
    r'(?!.*(?:session\\.regenerate|session_regenerate_id|'
    r'new_session|clear_session|session\\.clear|logout.*before|'
    r'request\\.session\\.clear|flush.*session|rotate.*session|'
    r'contrib\.auth\.login|login\(request|cycle_key))',
    re.IGNORECASE | re.DOTALL,
)

# 3. Missing HttpOnly/Secure/SameSite on cookies
SET_COOKIE_PATTERNS = re.compile(
    r'(?:set_cookie|Set-Cookie|response\.set_cookie|'
    r'response\.headers\[.Set-Cookie|make_response.*set_cookie)',
    re.IGNORECASE,
)

MISSING_COOKIE_FLAGS = re.compile(
    r'set_cookie\\([^)]+\\)'
    r'(?!.*(?:httponly|HttpOnly|secure|Secure|samesite|SameSite))',
    re.IGNORECASE | re.DOTALL,
)

# 4. JWT without expiration
JWT_NO_EXPIRATION = re.compile(
    r'(?:jwt\\.encode|jwt\\.sign|create_access_token|'
    r'create_refresh_token|JWT\\.encode)\\([^)]*\\)',
    re.IGNORECASE,
)

NO_EXP_CHECK = re.compile(
    r'(?:jwt\\.encode|create_access_token).*'
    r'(?!.*(?:exp(?:ires)?|expiration|expiry|exp_delta|'
    r'timedelta|datetime\\.utcnow|time\\.time|EXPIRATION))',
    re.IGNORECASE | re.DOTALL,
)

# 5. Hardcoded session/flask secret
SESSION_SECRET_HARDCODED = re.compile(
    r'(?:SESSION_SECRET|FLASK_SECRET|SECRET_KEY|JWT_SECRET|'
    r'APP_SECRET|CSRF_SECRET|session_secret)\s*=\s*["\']'
    r'(?!.*(?:os\.environ|os\.getenv|env\.get|config\(|'
    r'getenv|process\.env|import.*secret))'
    r'([^"\']{4,})["\']',
    re.IGNORECASE,
)

# Flask/object dict-assignment: app.config['SECRET_KEY'] = 'value'
FLASK_CONFIG_SECRET_HARDCODED = re.compile(
    r"(?:config|CONFIG)\s*\[['\"]?(?:SESSION_|FLASK_|APP_|CSRF_)?"
    r"(?:SECRET|secret)[_\s]?(?:KEY|key)?['\"]?\s*\]\s*=\s*['\"]"
    r"([^'\"]{4,})['\"]",
    re.IGNORECASE,
)

# 6. Missing MFA for sensitive operations
SENSITIVE_OPS = re.compile(
    r'def\s+(?:withdraw|transfer|payout|delete_account|'
    r'change_password|reset_password|update_email|add_payment_method)',
    re.IGNORECASE,
)

NO_MFA_CHECK = re.compile(
    r'(?:withdraw|transfer|payout|delete_account|change_password).*'
    r'(?!.*(?:mfa|2fa|otp|totp|verify.*code|confirm.*code|'
    r'challenge|authenticator|second.*factor))',
    re.IGNORECASE | re.DOTALL,
)

# 7. Decorator-based auth bypass (missing @login_required, @auth_required)
ROUTE_PATTERN = re.compile(
    r'@(?:app|router|bp|blueprint|routes)\\.(?:route|get|post|put|delete|patch)',
    re.IGNORECASE,
)

AUTH_DECORATORS = re.compile(
    r'@(?:login_required|auth_required|authenticated|'
    r'require_auth|jwt_required|token_required|'
    r'permission_required|role_required|has_permission|'
    r'authorize|guard)',
    re.IGNORECASE,
)

# 8. OTP without brute-force protection
OTP_VERIFY_PATTERNS = re.compile(
    r'def\s+(?:verify_otp|check_otp|validate_otp|verify_code|'
    r'confirm_code|verify_sms|check_code)',
    re.IGNORECASE,
)

NO_BRUTE_FORCE = re.compile(
    r'(?:verify_otp|check_otp|verify_code).*'
    r'(?!.*(?:attempt|retry|fail.*count|lock|block|'
    r'throttle|rate_limit|max.*try|too_many))',
    re.IGNORECASE | re.DOTALL,
)

# 9. Password reset token weaknesses
RESET_TOKEN_PATTERNS = re.compile(
    r'def\s+(?:reset_password|forgot_password|password_reset|'
    r'generate_reset_token|create_reset_token)',
    re.IGNORECASE,
)

WEAK_RESET_TOKEN = re.compile(
    r'(?:reset.*token|token.*reset)\s*=\s*'
    r'(?:random\.randint|random\.choice|str\(uuid|hashlib\.md5|'
    r'["\'].{1,16}["\']|secrets\.token_hex\([1-7]\))',
    re.IGNORECASE,
)


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _has_auth_decorator(content: str, route_pos: int) -> bool:
    """Check if a route has auth decorators within preceding 5 lines."""
    lines_before = content[max(0, route_pos - 500):route_pos].split("\n")
    recent = "\n".join(lines_before[-6:])
    return bool(AUTH_DECORATORS.search(recent))


_TEST_SECRET_MARKERS = (
    '0x0000', '10000000-', '6leixact',   # hCaptcha / reCAPTCHA public test keys
    'dummy', 'fake', 'placeholder', 'changeme', 'your-', 'example', 'sample',
    'xxx', '***',
)


def _is_placeholder_secret(value: str) -> bool:
    return any(m in value.lower() for m in _TEST_SECRET_MARKERS)


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS019" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # 1. OTP/SMS send without rate limiting
        otp_funcs = OTP_SEND_PATTERNS.finditer(content)
        for match in otp_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'cooldown|rate_limit|RateLimit|throttle|'
                            r'last_sent|resend.*(?:second|minute|hour)|'
                            r'wait|delay|backoff|cool.*down|too_often',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"OTP/SMS send without rate limiting: {match.group(0)}",
                    detail="SMS/OTP send function lacks cooldown/throttle. Risk: SMS exhaustion, financial loss.",
                    fix_suggestion="Add cooldown (60s between sends per phone). Daily limit per number. Rate limit per IP.",
                    noise_tier="precise",
                ))

        # 2. Session fixation
        login_funcs = LOGIN_PATTERNS.finditer(content)
        for match in login_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'session\\.regenerate|session_regenerate_id|'
                            r'new_session|clear_session|session\\.clear|'
                            r'logout.*before|flush.*session|rotate.*session|'
                            r'request\\.session\\.clear',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Login without session regeneration: {match.group(0)}",
                    detail="Session ID not regenerated after login. Vulnerable to session fixation.",
                    fix_suggestion="Call session.regenerate() or session_regenerate_id() immediately after successful authentication.",
                    noise_tier="normal",
                ))

        # 3. Missing cookie flags
        for match in MISSING_COOKIE_FLAGS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Cookie set without HttpOnly/Secure/SameSite flags",
                detail=match.group(0)[:120],
                fix_suggestion="Add httponly=True, secure=True, samesite='Strict' to all session/auth cookies.",
                noise_tier="precise",
            ))

        # 4. JWT without expiration
        jwt_encodes = JWT_NO_EXPIRATION.finditer(content)
        for match in jwt_encodes:
            ctx_end = min(match.end() + 2000, len(content))
            ctx_body = content[match.start():ctx_end]
            if not re.search(r'exp(?:ires)?\\b|expiration|expiry|exp_delta|'
                            r'timedelta|datetime\\.utcnow|time\\.time\\b|'
                            r'EXPIRATION|access_token_expire',
                            ctx_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title="JWT created without expiration claim",
                    detail="JWT.encode without 'exp' claim. Tokens are immortal.",
                    fix_suggestion="Always set 'exp' claim on all JWTs. Max 15 minutes for access tokens, 7 days for refresh tokens.",
                    noise_tier="precise",
                ))

        # 5. Hardcoded session secrets
        for match in SESSION_SECRET_HARDCODED.finditer(content):
            secret_value = match.group(1)
            if _is_placeholder_secret(secret_value) or 'os.environ' in secret_value.lower():
                continue
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Hardcoded session/JWT secret: {match.group(0).strip()[:100]}",
                detail="Session/JWT secret hardcoded in source. Anyone with code access can forge tokens.",
                fix_suggestion="Load from environment variable or secrets manager. Use random 64+ char secret.",
                noise_tier="precise",
                secret_value=secret_value,
            ))

        # 5b. Hardcoded secrets via Flask/object dict-assignment
        for match in FLASK_CONFIG_SECRET_HARDCODED.finditer(content):
            secret_value = match.group(1)
            if _is_placeholder_secret(secret_value) or 'os.environ' in secret_value.lower():
                continue
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Hardcoded session/JWT secret (config dict-assignment): {match.group(0).strip()[:100]}",
                detail="Session/JWT secret hardcoded via app.config[]. Anyone with code access can forge tokens.",
                fix_suggestion="Load from environment variable or secrets manager. Use random 64+ char secret.",
                noise_tier="precise",
                secret_value=secret_value,
            ))

        # 6. Missing MFA on sensitive operations
        sensitive_funcs = SENSITIVE_OPS.finditer(content)
        for match in sensitive_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'mfa|2fa|otp|totp|verify.*code|confirm.*code|'
                            r'challenge|authenticator|second.*factor|'
                            r'verification.*code',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Sensitive operation without MFA: {match.group(0)}",
                    detail="Withdraw/transfer/password-change without second factor. PCI-DSS 8.3 requires MFA for sensitive ops.",
                    fix_suggestion="Add OTP/TOTP challenge before executing sensitive operations.",
                    noise_tier="normal",
                ))

        # 7. Auth bypass — routes without @auth_required
        all_routes = ROUTE_PATTERN.finditer(content)
        for match in all_routes:
            # Check only non-trivial routes (not /health, /ping, /status)
            route_line = content[match.end():min(match.end() + 200, len(content))]
            if re.search(r'(?:/health|/ping|/status|/metrics|/ready)', route_line):
                continue
            if not _has_auth_decorator(content, match.start()):
                # Get the function definition line
                func_match = re.search(
                    r'def\s+(\w+)',
                    content[match.end():min(match.end() + 500, len(content))]
                )
                func_name = func_match.group(1) if func_match else "unknown"
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Route without auth decorator: {func_name}",
                    detail=f"Route '{func_name}' lacks @login_required or equivalent. May be intentional (public API) or an oversight.",
                    fix_suggestion="Verify this route is intentionally public. If protected, add @login_required decorator.",
                    noise_tier="normal",
                ))

        # 8. OTP verify without brute-force protection
        otp_verifies = OTP_VERIFY_PATTERNS.finditer(content)
        for match in otp_verifies:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'attempt|retry|fail.*count|lock|block|'
                            r'throttle|rate_limit|max.*try|too_many|'
                            r'MAX_ATTEMPTS|attempts_left',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"OTP verification without brute-force protection: {match.group(0)}",
                    detail="OTP verify function lacks attempt counting/lockout. 6-digit OTP = 1M combinations, brute-forceable.",
                    fix_suggestion="Limit to 5 attempts per OTP. Add exponential backoff. Lock account after 10 failed attempts.",
                    noise_tier="precise",
                ))

        # 9. Weak password reset token
        reset_funcs = RESET_TOKEN_PATTERNS.finditer(content)
        for match in reset_funcs:
            func_end = min(match.start() + 2000, len(content))
            func_body = content[match.start():func_end]
            if WEAK_RESET_TOKEN.search(func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Weak password reset token generation: {match.group(0)}",
                    detail="Reset token uses predictable source (randint, short string, MD5). Tokens can be guessed.",
                    fix_suggestion="Use secrets.token_urlsafe(32) or equivalent cryptographically-secure random generator. Min 256 bits entropy.",
                    noise_tier="precise",
                ))

    return findings

```

---

### GS020 — `gs020_xss_injection.py` (echelon 1, noise_tier `normal`, 329 lines)
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

```

---

### GS021 — `gs021_csrf_ssrf.py` (echelon 2, noise_tier `normal`, 151 lines)
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

```

---

### GS022 — `gs022_open_redirect.py` (echelon 2, noise_tier `normal`, 129 lines)
```python
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

from . import AuditContext, Detector, Finding

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

```

---

### GS023 — `gs023_race_conditions.py` (echelon 3, noise_tier `noisy`, 148 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS023 — Race Conditions / TOCTOU.

Real-World Bug Hunting + Web Hacking 101:
- Time-of-check to time-of-use (TOCTOU)
- Parallel request races (double-spend, double-redeem)
- Async race conditions in JS/Python
- File system races (symlink, tmpfile)

ECHELON: 3 (semantic, needs code flow analysis)
"""

from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Detector, Finding

RULE_ID = "GS023"
ECHELON = 3
NOISE_TIER = "noisy"
description = "Race Conditions / TOCTOU — double-spend, async races, fs races (Bug Hunting)"

RACE_PATTERNS: list[tuple[str, str, str]] = [
    # TOCTOU — file system
    (r'os\.path\.exists\s*\(.*\).*\n.*open\s*\(', "TOCTOU: exists() then open() — file may change between calls", "HIGH"),
    (r'os\.access\s*\(.*\).*\n.*open\s*\(', "TOCTOU: os.access() then open() — race window", "HIGH"),
    (r'Path\(.*\)\.exists\s*\(\).*\n.*open\s*\(', "TOCTOU: Path.exists() then open()", "MEDIUM"),
    (r'tempfile\.(?:mktemp|mkstemp|mkdtemp)', "TOCTOU: tempfile without secure flags", "MEDIUM"),
    (r'os\.symlink\s*\(', "Potential TOCTOU: symlink creation — verify target validation", "INFO"),

    # Double-spend / payment races
    (r'\.save\s*\(\).*\n.*\.save\s*\(\)', "Potential race: two saves without SELECT FOR UPDATE", "HIGH"),
    (r'select_for_update|SELECT.*FOR UPDATE', "Race protection: SELECT FOR UPDATE (verify coverage)", "INFO"),
    (r'\.objects\.(?:get|filter)\s*\(.*\).*\n.*\.save\s*\(', "Potential race: Django get-then-save without locking", "HIGH"),
    (r'UPDATE.*WHERE.*\n.*SELECT', "Potential race: UPDATE then SELECT — lost update problem", "HIGH"),
    (r'transaction\.atomic|@transaction\.atomic', "Transaction present — verify isolation level", "INFO"),

    # Async races
    (r'await\s+.*\n.*await\s+.*(?:same_resource|balance|stock)', "Potential async race: parallel awaits on shared state", "MEDIUM"),
    (r'Promise\.all\s*\(', "Potential JS race: Promise.all on mutable state", "MEDIUM"),
    (r'async\s+def.*\n.*(?:global|self\.)', "Potential async race: async function with shared state", "MEDIUM"),
    (r'threading\.(?:Lock|RLock|Semaphore)', "Race protection: threading lock (verify scope)", "INFO"),

    # Coupon/promo races
    (r'(?:coupon|promo|voucher|discount).*\.(?:get|filter).*\n.*\.(?:delete|update|save)',
     "Potential coupon race: get-then-use without locking", "HIGH"),
    (r'(?:redeem|claim|apply).*coupon', "Coupon redemption — verify idempotency and locking", "MEDIUM"),

    # Idempotency
    (r'idempotency_key|idempotent|Idempotency-Key', "Idempotency: key present (verify correctness)", "INFO"),
    (r'stripe\.(?:charge|payment|customer).*create', "Stripe API — verify idempotency key", "INFO"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.rb', '.go', '.java', '.php'}

EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__', 'migrations'}

EXCLUDE_PATTERNS = ['test_', 'test/', '.test.', '.spec.', '__test__', 'migration']


def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    files = _collect_files(ctx.path)

    for file_path in files:
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue

        rel_path = str(file_path.relative_to(ctx.path))
        if _is_skip_path(rel_path):
            continue

        for pattern, message, severity in RACE_PATTERNS:
            # Multi-line patterns need DOTALL
            flags = re.IGNORECASE | (re.DOTALL if '\\n' in pattern else 0)
            for match in re.finditer(pattern, content, flags):
                line_no = content[:match.start()].count('\\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet, content):
                    continue
                if _is_noise_pattern(pattern, content):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category="race_condition",
                    file=rel_path, line=line_no, snippet=snippet.strip()[:200],
                    message=message, cwe="CWE-362",
                    cvss={"HIGH":"7.0","MEDIUM":"5.3","INFO":"0.0"}.get(severity,"5.0"),
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


def _is_false_positive(snippet: str, full_context: str = "") -> bool:
    s = snippet.strip()
    if s.startswith('//') or s.startswith('#') or s.startswith('/*') or s.startswith('*'):
        return True
    if s.startswith('<!--'):
        return True
    # os.path.exists → open is OK if wrapped in try/with
    if 'os.path.exists' in s or 'Path(' in s:
        if re.search(r'(with|try)\s*:', full_context):
            return True
    return False


def _is_skip_path(rel_path: str) -> bool:
    """Skip demo/test/sample/migration directories."""
    return bool(re.search(
        r'(?:/|\A)(?:tests?|fixtures?|examples?|samples?|demo|docs?|migrations?)/',
        rel_path, re.IGNORECASE
    ))


def _is_noise_pattern(pattern: str, full_context: str) -> bool:
    """Additional context checks to reduce noise."""
    # save()+save() is fine if it's different fields
    if re.search(r'\.save\s*\(\)', pattern) and re.search(r'select_for_update|\.objects\.select_for_update|transaction\.atomic', full_context):
        return True
    # async def + global is fine if it's a single-threaded context
    if 'async' in pattern and 'global' in pattern:
        if not re.search(r'(?:balance|stock|inventory|counter|ledger)', full_context, re.IGNORECASE):
            return True
    return False

```

---

### GS024 — `gs024_llm_sqli.py` (echelon 2, noise_tier `normal`, 233 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS020 — LLM-based SQL Injection Detector (Pilot).
Replaces 87 regex patterns with a single LLM call per candidate file.
Faster, more accurate, fewer false positives.

Strategy:
1. Quick grep pre-filter: find files with SQL keywords (execute, cursor, raw, query)
2. For each candidate: send 20 lines of context to DeepSeek
3. LLM returns: {vulnerable: bool, confidence: 0-1, reason: str}
4. Only report high-confidence findings

Cost: ~$0.001/file. On 100 candidates = $0.10/day.
Precision target: >50% (vs <5% for regex approach).
"""

import os
import sys
import re
from pathlib import Path


RULE_ID = "GS024"
ECHELON = 2
CATEGORY = "CRITICAL"
DESCRIPTION = "LLM-based SQL/NoSQL injection detection — replaces 87 regex patterns with one smart call"


# Quick pre-filter: files that contain SQL-like patterns
PRE_FILTER_PATTERNS = [
    r'(?:execute|cursor|cursor\(\)|raw|query|text)\s*\(',
    r'(?:\.execute|\.raw|\.query|\.exec)\s*\(',
    r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:FROM|INTO|SET|TABLE)',
    r'(?:find_by_sql|find_by_sql\s*\()',
    r'(?:\$where|\$regex)',
]


def _get_api_key() -> str | None:
    """Get DeepSeek API key from env or .env file."""
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        # Try .env file (Hermes stores keys here, not in config.yaml)
        for env_path in [
            os.path.expanduser("~/.hermes/.env"),
            os.path.expanduser("~/.hermes/env"),
            ".env",
        ]:
            if os.path.exists(env_path):
                try:
                    with open(env_path) as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("DEEPSEEK_API_KEY="):
                                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                                if api_key:
                                    return api_key
                except Exception:
                    pass
    return api_key or None


def _quick_grep_filter(file_path: Path) -> bool:
    """Quick check: does this file contain SQL-like patterns?"""
    try:
        content = file_path.read_text(errors="replace")
        for pattern in PRE_FILTER_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    except Exception:
        pass
    return False


def _extract_candidates(file_path: Path, max_per_file: int = 5) -> list[dict]:
    """Extract candidate lines for LLM analysis."""
    try:
        lines = file_path.read_text(errors="replace").split("\n")
    except Exception:
        return []

    candidates = []
    for i, line in enumerate(lines):
        if len(candidates) >= max_per_file:
            break
        # Only lines that contain execute/query/raw + string formatting
        if re.search(r'(?:execute|query|raw|cursor)\s*\(\s*(?:f["\']|["\'].*%.*["\'])', line, re.IGNORECASE):
            start = max(0, i - 10)
            end = min(len(lines), i + 10)
            snippet = "\n".join(f"{j+1}: {l}" for j, l in enumerate(lines[start:end], start))
            candidates.append({
                "line_number": i + 1,
                "line": line.strip(),
                "snippet": snippet,
            })
    return candidates


def _call_llm(snippet: str, file_path: str) -> dict:
    """Unified LLM classify via gsc_llm_providers."""
    from gsc_llm_providers import llm_chat

    prompt = f"""You are a security code auditor. Analyze this code for SQL injection vulnerabilities.

CODE:
```
{snippet[:2500]}
```

Determine if this is a REAL SQL injection vulnerability or a SAFE pattern.

SAFE patterns (NOT vulnerabilities):
- Parameterized queries: cursor.execute("SELECT ...", (param,))
- SQLAlchemy ORM: session.query(User).filter(...)
- Django ORM: Model.objects.filter(...)
- Static SQL strings (no user input interpolation)
- f-strings with trusted/internal variables only
- Test fixtures, documentation examples

REAL vulnerabilities:
- f-string with user-controlled input: cursor.execute(f"SELECT ... WHERE id={{request.GET['id']}}")
- String formatting with external data: cursor.execute("SELECT ..." % user_input)
- Raw SQL concatenation with request params

Reply with JSON only:
{{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "one sentence"}}"""

    content = llm_chat(
        "You are a security auditor. Reply with JSON only.",
        prompt, max_tokens=200, temperature=0.1,
    )
    if not content:
        return {"vulnerable": False, "confidence": 0, "reason": "No LLM provider configured"}

    try:
        import json
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(content[start:end])
            return {
                "vulnerable": result.get("vulnerable", False),
                "confidence": result.get("confidence", 0.5),
                "reason": result.get("reason", ""),
            }
    except Exception as e:
        return {"vulnerable": False, "confidence": 0, "reason": f"LLM error: {str(e)[:100]}"}

    return {"vulnerable": False, "confidence": 0, "reason": "Failed to parse response"}


def detect(ctx) -> list:
    """
    LLM-based SQL injection detection.
    ctx: AuditContext with get_source_files(), project_path, etc.
    """
    findings = []

    # Check if we have an API key
    api_key = _get_api_key()
    if not api_key:
        return findings

    source_files = ctx.get_source_files(extensions=(".py", ".go", ".ts", ".js", ".java", ".rb", ".php"))
    if not source_files:
        return findings

    # Phase 1: Quick grep pre-filter → extract candidates per file
    file_candidates: list[tuple[Path, list[dict]]] = []
    total_candidates = 0
    for fp in source_files:
        if total_candidates >= 30:
            break
        if _quick_grep_filter(fp):
            cands = _extract_candidates(fp, max_per_file=3)
            if cands:
                file_candidates.append((fp, cands))
                total_candidates += len(cands)

    if not file_candidates:
        return findings

    # Phase 2: LLM analysis (limited to 30 candidates per scan for cost control)
    for fp, cands in file_candidates:
        for c in cands:
            result = _call_llm(c["snippet"], str(fp))
            if result.get("vulnerable") and result.get("confidence", 0) >= 0.7:
                findings.append({
                    "rule_id": RULE_ID,
                    "title": "LLM: SQL injection detected",
                    "category": "CRITICAL",
                    "echelon": ECHELON,
                    "file_path": str(fp),
                    "line_number": c["line_number"],
                    "detail": f"LLM confidence: {result['confidence']:.0%}. {result['reason']}",
                    "noise_tier": "precise",
                })

    return findings


# Standalone test
if __name__ == "__main__":
    # Test with a sample
    test_code = '''
def vulnerable(request):
    user_id = request.GET.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def safe(param):
    cursor.execute("SELECT * FROM users WHERE id = ?", (param,))
'''
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_path = f.name

    print(f"Testing LLM detector on: {test_path}")
    # Mock AuditContext
    class MockCtx:
        def get_source_files(self, extensions=None):
            return [Path(test_path)]
        project_path = Path(test_path).parent
        skipped_detectors = set()

    findings = detect(MockCtx())
    for f in findings:
        print(f"  [{f['category']}] {f['title']}: {f['detail']}")

    os.unlink(test_path)

```

---

### GS025 — `gs025_ai_provenance.py` (echelon 2, noise_tier `normal`, 169 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS025 — AI-Code Provenance Scanner.

Two tasks:
  1. Estimate AI provenance likelihood (ai_provenance_score).
  2. Catch insecure defaults that AI assistants set most often
     (permissive CORS, debug=True, wildcard bind, hardcoded secrets,
      eval, insecure random, missing rate limits).

Design: GS025 patterns are real vulnerabilities — always reported.
AI score only boosts confidence and adds metadata. Not a duplicate
of existing 23 detectors: focus is on "AI-favored insecure defaults".
Deduplication via finding_key in gsc_external.
"""
from __future__ import annotations

import re
from typing import Any

from . import AuditContext, Finding

# ── AI provenance markers (comment patterns across languages) ──────
AI_MARKERS: list[tuple[str, float]] = [
    (r"(?:#|//|\*)\s*(?:Generated|Created|Written|Assisted|Authored|Scaffolded)"
     r"\s+by\s+(?:AI|Copilot|GPT[-\s]?\d*|Claude|Cursor|ChatGPT|an?\s+assistant)", 0.40),
    (r"(?:#|//)\s*TODO:\s*(?:review|verify|check|audit|harden|secure)\b", 0.15),
    (r'(?:#|//|"""|\*)\s*Examples?:\s*\n', 0.10),
    (r"\b(?:openai|anthropic|langchain|llama_index|ChatCompletion)\b", 0.10),
]

# ── AI-favored insecure defaults ──────────────────────────────────
AI_VULN_PATTERNS: list[tuple[str, str, str, float]] = [
    ("permissive_cors",
     r'CORS\([^)]*allow_origins=\[\s*["\']\*["\']\s*\]'
     r'|Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*',
     "HIGH", 0.70),
    ("debug_mode",
     r"^[ \t]*debug[ \t]*=[ \t]*True[ \t]*(?:#.*)?$"
     r"|\bapp\.run\([^)]*debug[ \t]*=[ \t]*True",
     "HIGH", 0.75),
    ("wildcard_bind",
     r'host\s*=\s*["\']0\.0\.0\.0["\']',
     "MEDIUM", 0.55),
    ("eval_usage",
     r"\beval\s*\(|\bexec\s*\(|\bchild_process\b.*\beval\b",
     "HIGH", 0.70),
    ("hardcoded_secret",
     r"^[ \t]*(?:api[_-]?key|secret|password|passwd|token|client_secret)"
     r"[ \t]*=[ \t]*[\"'][A-Za-z0-9_\-./+]{12,}[\"']",
     "CRITICAL", 0.80),
    ("insecure_random",
     r"\brandom\.random\(\).*(?:auth|token|session|otp)"
     r"|\bMath\.random\(\).*(?:auth|token|session|otp)",
     "MEDIUM", 0.60),
    ("no_rate_limit_auth",
     r"@(?:app\.route|router\.(?:get|post|put|delete))\([^)]*"
     r"(?:/login|/signin|/password|/register)[^)]*\)",
     "MEDIUM", 0.50),
]

AI_THRESHOLD = 0.5


class GS025Detector:
    """AI-Code Provenance + AI-favored insecure defaults. Regex-only, fork-safe."""

    rule_id = "GS025"
    name = "AI Code Provenance Scanner"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content:
            return findings

        ai_score = self._ai_likelihood(content)

        for pattern_id, regex, severity, base_conf in AI_VULN_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = self._snippet(content, line_no)

                confidence = base_conf
                if ai_score >= AI_THRESHOLD:
                    confidence = min(0.95, base_conf + ai_score * 0.2)

                findings.append({
                    "rule_id": f"GS025-{pattern_id}",
                    "title": f"AI-favored insecure default: {pattern_id}",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "language": language,
                    "metadata": {
                        "ai_provenance_score": round(ai_score, 2),
                        "ai_generated_likely": ai_score >= AI_THRESHOLD,
                        "pattern_id": pattern_id,
                    },
                })
        return findings

    def _ai_likelihood(self, content: str) -> float:
        score = 0.0
        for regex, weight in AI_MARKERS:
            if re.search(regex, content, re.IGNORECASE):
                score += weight
        lines = content.splitlines()
        if len(lines) > 200:
            comment_count = sum(1 for ln in lines if ln.strip().startswith(("#", "//", "/*", "*")))
            if comment_count < 5:
                score += 0.10
        return min(1.0, score)

    def _snippet(self, content: str, line_no: int, window: int = 2) -> str:
        lines = content.splitlines()
        start = max(0, line_no - 1 - window)
        end = min(len(lines), line_no + window)
        return "\n".join(lines[start:end])


# ── Registry bridge (module-level interface expected by DetectorEntry) ──
RULE_ID = "GS025"
ECHELON = 2
NOISE_TIER = "normal"
description = "GS025: AI-Code Provenance — detect AI-favored insecure defaults"


def detect(ctx) -> list[Finding]:
    """Bridge function for registry compatibility.

    Converts GS025Detector's internal dicts to the Finding contract
    (file_path/line_number/detail) so downstream consumers can locate
    findings. Previously returned raw dicts with 'file'/'line' keys,
    which resolved to file_path=None in gsc_external.
    """
    det = GS025Detector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        if fp.suffix not in {'.py', '.js', '.ts', '.tsx', '.go', '.rs', '.java', '.rb', '.php'}:
            continue
        if ctx.is_test_file(fp):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        for raw in det.detect(rel, content):
            findings.append(Finding(
                rule_id=raw["rule_id"],
                category=raw["severity"],
                title=raw["title"],
                file_path=raw["file"],
                line=raw["line"],
                detail=raw.get("snippet", ""),
                confidence=raw.get("confidence"),
                metadata=raw.get("metadata"),
                language=raw.get("language"),
            ))
    return findings

```

---

### GS028 — `gs028_invariants.py` (echelon ?, noise_tier `normal`, 45 lines)
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS028 — Security Invariant Engine (v0.20).

Deterministic verification of invariants from the scanned repo's
.gsc-audit.yml. No LLM required. Instantiated per-scan (config is
repo-specific), NOT in the global DETECTORS registry.

Confidence = 0.90 (confirmed band) — invariants are the team's own
policy-as-code rules, so violations are high-confidence by design.
"""
from gsc_core.gsc_invariant_engine import InvariantEngine

INVARIANT_CONFIDENCE = 0.90


class GS028Detector:
    rule_id = "GS028"
    name = "Security Invariant Engine"
    requires_llm = False

    def __init__(self, engine: InvariantEngine):
        self.engine = engine

    def detect(self, file_path: str, content: str, language: str = "auto"):
        findings = []
        for v in self.engine.verify_file(file_path, content):
            findings.append({
                "rule_id": f"GS028-{v.invariant_id}",
                "title": v.message,
                "severity": v.severity,
                "confidence": INVARIANT_CONFIDENCE,
                "file": file_path,
                "line": v.line,
                "snippet": v.snippet,
                "language": language,
                "metadata": {
                    "invariant_id": v.invariant_id,
                    "invariant_type": v.invariant_type,
                },
            })
        return findings

```

---

### GS029 — `gs029_secrets.py` (echelon ?, noise_tier `normal`, 107 lines)
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS029 — Secrets Detection (v0.29).

Standalone SAST detector in main pipeline. Reuses narrowed patterns
from cross-repo secrets (v0.27) with entropy filter + redaction.

No value is stored or displayed — only fact of detection.
"""

from __future__ import annotations

import math, re
from typing import Dict, List

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                   'aws_access_key',  None, "CRITICAL"),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY', 'private_key',    None, "CRITICAL"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'jwt_token', 0, "HIGH"),
    (r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*'
     r'[\'"]?([A-Za-z0-9+/=_.\-!@#$%^&*]{12,})',                 'config_secret',   1, "HIGH"),
    (r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s\'"]{10,}', 'db_url',  None, "HIGH"),
]

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)(?:tests?|fixtures?|examples?|samples?|tutorials?|devscripts?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv)(?:/|$)', re.IGNORECASE)

EXCLUDE_FILE_RE = re.compile(
    r'(?:^test_|_test\.|conftest\.|setup\.|conf\.py$)', re.IGNORECASE)

MIN_ENTROPY = 3.0

# Placeholder / demo / example secret values — skipped when the captured value
# begins with an unambiguous placeholder marker (no real secret starts with these).
# Anchored at start via .match(); `(?![a-z])` prevents prefix collisions with
# real English words (e.g. "democratic", "testing", "examplesecret").
PLACEHOLDER_VALUE_RE = re.compile(
    r'(?i)^(?:'
    r'your[_\- ]?(?:api[_\- ]?key|token|secret|password|passwd|key|value|here)'  # your_api_key_here
    r'|(?:change|replace)[_\- ]?me'                                              # changeme / replace_me
    r'|dummy|fake|placeholder|redacted'
    r'|(?:sample|example|demo|test)(?![a-z])'                                    # example_… / test-… / test123
    r'|x{4,}'                                                                    # xxxx
    r'|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}'                                        # <KEY> ${KEY} {{KEY}}
    r'|[а-яё]+[_\- ]?(?:ключ|пароль|секрет|токен|api[_\- ]?key)'                 # ваш-ключ-здесь
    r')'
)

# Canonical AWS documentation example access key — appears in countless READMEs/
# tutorials. Non-functional by definition; never a real credential.
AWS_EXAMPLE_KEYS = {"AKIAIOSFODNN7EXAMPLE"}

# Loopback DB connection strings (localhost / 127.0.0.1 / ::1, with optional
# userinfo and port) are dev/default examples, not leaked production credentials.
DB_URL_LOOPBACK_RE = re.compile(
    r'(?i)^(?:mongodb|mysql|postgresql|redis|amqp)://'
    r'(?:[^/@\s]+@)?'
    r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)(?::\d+)?(?:/|$)'
)


def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class GS029SecretsDetector:
    rule_id = "GS029"
    name = "Secrets Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> List[Dict]:
        if EXCLUDE_PATH_RE.search(file_path):
            return []
        fname = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
        if EXCLUDE_FILE_RE.search(fname):
            return []
        findings = []
        for pattern, secret_type, capture_idx, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                if capture_idx is not None:
                    value = m.group(capture_idx)
                    if _shannon_entropy(value) < MIN_ENTROPY:
                        continue
                    if PLACEHOLDER_VALUE_RE.match(value):
                        continue
                if secret_type == "aws_access_key" and m.group(0) in AWS_EXAMPLE_KEYS:
                    continue
                if secret_type == "db_url" and DB_URL_LOOPBACK_RE.match(m.group(0)):
                    continue
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule_id": f"GS029-{secret_type}",
                    "title": f"Potential {secret_type} exposed",
                    "severity": severity,
                    "confidence": 0.85,
                    "file_path": file_path,
                    "line_number": line_no,
                    "detail": f"<redacted:{secret_type}> at line {line_no}",
                    "metadata": {"secrets": {"type": secret_type}},
                })
        return findings

```

---

### GS030 — `gs030_sca.py` (echelon ?, noise_tier `normal`, 19 lines)
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GS030 — SCA detector. Thin wrapper over gsc_sca for external scan pipeline."""

from pathlib import Path
from gsc_core.gsc_sca import parse_repo_manifests, query_osv, sca_findings


class GS030Detector:
    rule_id = "GS030"
    name = "Software Composition Analysis (dependencies CVE)"
    requires_llm = False

    def detect_repo(self, repo_root, db=None):
        packages = parse_repo_manifests(repo_root)
        if not packages:
            return []
        osv_results = query_osv(packages, db=db)
        return sca_findings(packages, osv_results)

```

---

### GS031 — `gs031_iac.py` (echelon ?, noise_tier `normal`, 23 lines)
```python
#!/usr/bin/env python3
"""GS031 — IaC misconfiguration detector (v0.34)."""
from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform, detect_ansible, _is_kubernetes
import re

class GS031IaCDetector:
    rule_id = "GS031"
    name = "Infrastructure as Code Misconfigurations"
    requires_llm = False

    def detect(self, file_path, content, language="auto"):
        if file_path.endswith(".tf") or file_path.endswith(".tfvars"):
            return detect_terraform(file_path, content)
        base = file_path.split("/")[-1].lower()
        if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
            return detect_dockerfile(file_path, content)
        if file_path.endswith(".yml") or file_path.endswith(".yaml"):
            if _is_kubernetes(content):
                return detect_kubernetes(file_path, content)
            # Detect Ansible playbooks (hosts: or tasks: at top level)
            if re.search(r'^\s*(?:hosts|tasks|handlers|become)\s*:', content, re.MULTILINE):
                return detect_ansible(file_path, content)
        return []

```

---

### GS032 — `gs032_prompt_injection.py` (echelon 1, noise_tier `sensitive`, 302 lines)
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS032 — Prompt Injection Detector.

Detects malicious prompt injections targeting AI coding agents
(Claude Code, Codex, Gemini CLI) that read code/docs from repos.

Attack vectors (from "Claude Code and Gemini CLI Flaws" — Aug 2026):
  - GitHub issues/PRs with embedded system prompts
  - "Ignore previous instructions" override patterns
  - Simulated agent tool calls in code comments / markdown
  - Credential exfiltration prompts hidden in docs
  - Zero-width / invisible Unicode characters for hidden text
  - HTML/Markdown comments with injected instructions

File targets: .md, .txt, .py, .js, .ts, .yml, .yaml, .json, .html
"""

from __future__ import annotations

import re
import math
from typing import Any

# ── INJECTION PATTERNS ─────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[str, str, str, float, str | None]] = [
    # --- Override / jailbreak ---
    ("override_instruction",
     r'(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)'
     r'\s+(?:instructions?|prompts?|context|messages?|directives?)',
     "CRITICAL", 0.95, None),
    ("role_hijack",
     r'(?i)\byou\s+are\s+(?:now|no\s+longer)\b.{0,80}'
     r'(?:system|assistant|hacker|attacker|evil|malicious)',
     "CRITICAL", 0.90, None),
    ("system_prompt_override",
     r'(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)|'
     r'you\s+are\s+(?:now\s+)?(?:a\s+)?(?:hacker|attacker|evil|malicious|bot)|'
     r'your\s+(?:new\s+)?(?:goal|task|job|purpose)\s+is\s+(?:now\s+)?to|'
     r'from\s+now\s+on\s+you\s+(?:must|will|should|are))',
     "HIGH", 0.75, None),

    # --- Agent tool simulation ---
    ("fake_tool_call_execute",
     r'(?i)(?:execute_command|shell_exec|run_command|subprocess\.run|'
     r'os\.system|bash\s+-c)\s*[\(]\s*["\'].{3,}["\']',
     "HIGH", 0.70, None),
    ("fake_tool_call_file",
     r'(?i)(?:write_file|read_file|patch_file|append_file)\s*\(\s*["\']',
     "MEDIUM", 0.60, None),
    ("fake_tool_call_delegate",
     r'(?i)(?:delegate_task|spawn_agent|create_subagent)\s*\(\s*["\']',
     "HIGH", 0.70, None),
    ("fake_tool_call_terminal",
     r'(?i)(?:terminal|exec)\s*\(\s*(?:command|cmd)\s*=\s*["\']',
     "MEDIUM", 0.55, None),

    # --- Credential exfiltration ---
    ("exfil_curl",
     r'(?i)curl\s+.*(?:https?://|\.(?:com|net|io|dev|xyz|tk|ml|ga|cf)/)'
     r'.{0,100}(?:\$\(|`|&&|;|\|)',
     "CRITICAL", 0.80, None),
    ("exfil_env_send",
     r'(?i)(?:cat|echo|export|printenv|env\s*\|\s*grep)'
     r'\s+.*(?:\.env|secrets?|token|api[_-]?key|credential)'
     r'.{0,60}(?:\||>|curl|wget|nc\s|ncat|socat|telnet)',
     "CRITICAL", 0.85, None),
    ("exfil_git_clone_malicious",
     r'(?i)git\s+clone\s+(?:https?://|git@)'
     r'(?!github\.com/[^/]+/[^/]+\.git\b)',
     "MEDIUM", 0.50, None),
    ("exfil_base64_payload",
     r'(?i)(?:echo|printf)\s+[\'"]?(?:[A-Za-z0-9+/]{40,}={0,2})[\'"]?\s*\|\s*base64\s+-d',
     "HIGH", 0.75, None),

    # --- Hidden text vectors ---
    ("zero_width_chars",
     r'[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\uFEFF]{3,}',
     "MEDIUM", 0.85, None),
    ("hidden_html_comment",
     r'<!--.{20,}(?:(?:ignore|override)\s+(?:previous|all|instructions?|'
     r'prompts?)|(?:execute|run)\s+(?:command|shell)|'
     r'(?:curl|wget)\s+(?:https?://)|'
     r'(?:api[_.-]?key|token|secret|credential)\s*[=:]|'
     r'<system>|</system>).{10,}-->',
     "HIGH", 0.70, None),
    ("markdown_link_injection",
     r'\[.{0,5}\]\((?:javascript:|data:text/html|vbscript:)',
     "HIGH", 0.80, None),
    ("markdown_image_exfil",
     r'!\[.{0,20}\]\(https?://(?!github\.com|img\.shields\.io|'
     r'raw\.githubusercontent\.com)[^/\s]+\.[a-z]{2,}/[^)]+\)',
     "LOW", 0.30, None),

    # --- AI agent specific (code-only: skip in .py/.js — legit API usage) ---
    ("anthropic_system_injection",
     r'(?i)(?:<system>|</system>|<instructions>|</instructions>|'
     r'<anthropic_function_calls>|</anthropic_function_calls>|'
     r'<claude_system>|</claude_system>)',
     "CRITICAL", 0.90, {'.md', '.txt', '.html', '.htm', '.yml', '.yaml'}),
    ("openai_tool_injection",
     r'(?i)(?:"role":\s*"system".{0,30}"content":\s*"(?:ignore|forget|you are now|'
     r'from now on|execute|hack|steal|exfil)|'
     r'"function_call".{0,50}(?:execute|shell|bash|curl|wget))',
     "HIGH", 0.70, {'.md', '.txt', '.html', '.htm'}),
    ("codex_specific",
     r'(?i)(?:codex\s+execute|codex\s+terminal|codex\s+shell|'
     r'codex\s+run\s+command)',
     "HIGH", 0.70, None),
    ("gemini_cli_specific",
     r'(?i)(?:gemini\s+(?:run|exec|shell|bash|terminal)\b)',
     "MEDIUM", 0.60, None),
]

# ── EXCLUDE PATHS ─────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build|'
    r'\.next|\.nuxt|coverage|\.nyc_output|'
    r'graphify-out|openwiki|\.claude/commands)'  # generated + AI config
    r'(?:/|$)', re.IGNORECASE)

EXCLUDE_EXTENSIONS = {
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.webm', '.ogg',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.lock', '.pyc', '.pyo', '.class', '.so', '.dll',
}

TARGET_EXTENSIONS = {
    '.md', '.txt', '.rst', '.adoc',    # documentation
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.rb',  # code
    '.yml', '.yaml',                    # configs (no .json — mostly generated data)
    '.html', '.htm',                    # web
}

# ── ENTROPY CHECK ──────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── DETECTOR ───────────────────────────────────────────────────────────

class GS032PromptInjectionDetector:
    rule_id = "GS032"
    name = "Prompt Injection Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content:
            return findings

        # Skip the detector itself (contains its own patterns in docstrings/regexes)
        if 'gs032_prompt_injection.py' in file_path:
            return findings

        # Skip excluded paths
        if EXCLUDE_PATH_RE.search(file_path):
            return findings

        # Only scan target extensions
        ext = file_path[file_path.rfind('.'):] if '.' in file_path else ''
        if ext.lower() not in TARGET_EXTENSIONS:
            return findings

        # Skip binary-looking content (high null byte ratio or mostly non-printable)
        if self._looks_binary(content):
            return findings

        # Check for "suspicious density" — many injection patterns = higher risk
        pattern_hits = 0

        for entry in INJECTION_PATTERNS:
            if len(entry) == 5:
                pattern_id, regex, severity, base_conf, file_filter = entry
            else:
                pattern_id, regex, severity, base_conf = entry
                file_filter = None

            # Check file extension filter
            if file_filter is not None:
                ext_lower = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
                if ext_lower not in file_filter:
                    continue

            matches = list(re.finditer(regex, content, re.MULTILINE))
            if not matches:
                continue

            pattern_hits += len(matches)

            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                snippet = self._snippet(content, line_no)
                matched_text = match.group(0)

                # Boost confidence for high-entropy hidden strings
                confidence = base_conf
                if pattern_id == "zero_width_chars":
                    confidence = 0.95
                elif pattern_id in ("exfil_base64_payload",):
                    if _shannon_entropy(matched_text) > 4.5:
                        confidence = min(0.95, base_conf + 0.1)

                findings.append({
                    "rule_id": f"GS032-{pattern_id}",
                    "title": f"Potential prompt injection: {pattern_id}",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "file_path": file_path,
                    "line_number": line_no,
                    "detail": f"Matched pattern '{pattern_id}' at line {line_no}",
                    "snippet": snippet,
                    "language": language,
                    "metadata": {
                        "detector": "GS032",
                        "pattern_id": pattern_id,
                        "matched_text": matched_text[:120],
                        "suspicious_density": pattern_hits >= 3,
                    },
                })

        # Flag entire file if too many patterns (likely an attack doc)
        if pattern_hits >= 5:
            findings.append({
                "rule_id": "GS032-high_density",
                "title": "High density of prompt injection patterns — likely attack document",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "file_path": file_path,
                "line_number": 1,
                "detail": f"File contains {pattern_hits} injection patterns — treat as hostile",
                "snippet": self._snippet(content, 1),
                "language": language,
                "metadata": {
                    "detector": "GS032",
                    "pattern_id": "high_density",
                    "total_pattern_hits": pattern_hits,
                },
            })

        return findings

    def _looks_binary(self, content: str) -> bool:
        """Check if content appears to be binary data."""
        if not content:
            return False
        sample = content[:4096]
        non_printable = sum(1 for ch in sample if ord(ch) < 9 and ch != '\n' and ch != '\r' and ch != '\t')
        return (non_printable / max(len(sample), 1)) > 0.3

    def _snippet(self, content: str, line_no: int, context: int = 2) -> str:
        """Extract a few lines around the match for context."""
        lines = content.splitlines()
        start = max(0, line_no - 1 - context)
        end = min(len(lines), line_no + context)
        return "\n".join(lines[start:end])


# ── Registry bridge ────────────────────────────────────────────────────

RULE_ID = "GS032"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS032: Prompt Injection — detect AI agent hijack via code/docs/issues"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility — uses AuditContext."""
    from pathlib import Path
    det = GS032PromptInjectionDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext not in TARGET_EXTENSIONS:
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS033 — `gs033_cicd.py` (echelon 1, noise_tier `sensitive`, 231 lines)
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS033 — CI/CD Pipeline Anti-Patterns (v1.0).

Scans GitHub Actions, GitLab CI, Jenkins, and other CI configs for:
  - Long-lived tokens instead of OIDC
  - Direct prod deploy without staging/canary
  - Secrets exposed in logs
  - pull_request_target without sandbox
  - Missing CODEOWNERS / branch protection
  - Self-hosted runners without isolation

Book reference: Brikman "Fundamentals of DevOps", 2026, ch.5 (CI/CD).
"""

from __future__ import annotations

import re
import hashlib
from typing import Any

# ── PATTERNS ──────────────────────────────────────────────────────────

CICD_PATTERNS: list[tuple[str, str, str, float]] = [
    # --- Token/credential antipatterns ---
    ("long_lived_token",
     r'(?i)(?:\$\{\{\s*secrets\.\w+\s*\}\}|TOKEN|GITHUB_TOKEN|'
     r'secrets\.(?:GITHUB_TOKEN|DEPLOY_KEY|NPM_TOKEN|PYPI_TOKEN|'
     r'DOCKER_PASSWORD|AWS_ACCESS_KEY_ID)|'
     r'with:\s*\n\s*token:\s*\$\{\{\s*secrets\.)',
     "HIGH", 0.80),

    # --- Deploy without safety ---
    ("prod_deploy_no_staging",
     r'(?i)name:\s*(?:deploy.*prod|production.*deploy|release)',
     "MEDIUM", 0.50),  # context-dependent — flag for review

    ("deploy_no_canary",
     r'(?i)(?:deploy|rollout|release).{0,50}(?:production|prod)'
     r'(?!.{0,100}(?:canary|staging|blue.green|rolling))',
     "LOW", 0.40),

    # --- Secret exposure in logs ---
    ("secret_in_log",
     r'(?i)(?:echo|cat|printf).{0,30}secrets\.\w+',
     "CRITICAL", 0.95),

    ("secret_in_env_dump",
     r'(?i)(?:printenv|env\s*\|\s*grep|set\s*\|\s*grep)',
     "HIGH", 0.70),

    # --- Pull request risks ---
    ("pull_request_target_unsafe",
     r'pull_request_target.{0,100}actions/checkout@v\d+\s*\n\s*with:'
     r'\s*\n\s*ref:\s*',
     "CRITICAL", 0.90),

    ("pull_request_no_sandbox",
     r'pull_request_target(?!.{0,200}(?:environment:|environment\s*:))',
     "HIGH", 0.70),

    # --- Runner security ---
    ("self_hosted_runner",
     r'runs-on:\s*(?:self-hosted|\[.*self-hosted)',
     "MEDIUM", 0.60),

    # --- Checkout safety ---
    ("persist_credentials",
     r'actions/checkout@v\d+(?!.{0,200}persist-credentials:\s*false)',
     "MEDIUM", 0.65),

    ("checkout_no_ref",
     r'actions/checkout@v\d+(?!.{0,200}ref:\s*)',
     "LOW", 0.30),

    # --- Unsafe script execution ---
    ("script_injection_via_var",
     r'run:\s*\|\s*\n\s*.*github\.event\.(?:issue|comment|pull_request)',
     "CRITICAL", 0.85),

    ("curl_pipe_bash_in_ci",
     r'run:\s*\|\s*\n\s*curl\s+.*\|\s*(?:sh|bash|python)',
     "HIGH", 0.75),
]

# ── EXCLUSIONS ────────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
    r'(?:/|$)', re.IGNORECASE)

CI_FILE_PATTERNS = [
    r'.github/workflows/.*\.ya?ml$',
    r'\.gitlab-ci\.ya?ml$',
    r'Jenkinsfile$',
    r'\.circleci/config\.ya?ml$',
    r'\.travis\.ya?ml$',
    r'azure-pipelines\.ya?ml$',
]


def _is_ci_file(file_path: str) -> bool:
    for pattern in CI_FILE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


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
        "language": "yaml",
        "metadata": {
            "detector": "GS033",
            "pattern_id": rule_id.replace("GS033-", ""),
        },
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS033CICDDetector:
    rule_id = "GS033"
    name = "CI/CD Pipeline Anti-Patterns"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content:
            return findings

        if EXCLUDE_PATH_RE.search(file_path):
            return findings

        if not _is_ci_file(file_path):
            return findings

        pattern_hits = 0

        for pattern_id, regex, severity, base_conf in CICD_PATTERNS:
            matches = list(re.finditer(regex, content, re.MULTILINE))
            if not matches:
                continue

            pattern_hits += len(matches)

            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                snippet = _snippet(content, line_no)
                matched = match.group(0)[:120]

                confidence = base_conf
                if pattern_id == "secret_in_log":
                    confidence = 0.98

                findings.append(_finding(
                    f"GS033-{pattern_id}", severity,
                    f"CI/CD anti-pattern: {pattern_id}",
                    file_path, line_no, snippet, confidence,
                ))

        # Special: check for CODEOWNERS when CI exists
        if pattern_hits >= 1 and not self._has_codeowners(content):
            findings.append(_finding(
                "GS033-no_codeowners", "LOW",
                "CI pipeline exists but no CODEOWNERS detected in workflow",
                file_path, 1, "(check repo for CODEOWNERS file)", 0.30,
            ))

        # High density = CI file has many issues
        if pattern_hits >= 4:
            findings.append(_finding(
                "GS033-high_risk_pipeline", "HIGH",
                f"CI pipeline has {pattern_hits} anti-patterns — manual review required",
                file_path, 1, f"({pattern_hits} anti-patterns found)", 0.85,
            ))

        return findings

    def _has_codeowners(self, content: str) -> bool:
        # Code that mentions CODEOWNERS or @owner references in the CI file
        return bool(re.search(r'(?i)(?:CODEOWNERS|code.owners)', content))


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS033"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS033: CI/CD Anti-Patterns — detect unsafe GitHub Actions/GitLab CI patterns"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS033CICDDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if not _is_ci_file(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS034 — `gs034_supply_chain.py` (echelon 1, noise_tier `sensitive`, 260 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS034 — npm Supply Chain Attack Detector.

Detects patterns from ChainDrop (Aug 2026) and similar npm supply chain worms:
  - Suspicious preinstall/postinstall scripts in package.json
  - Downloader stagers (setup.mjs, loader.js)
  - Infostealer payloads (Math_Symbol.js, obfuscated JS)
  - Bun runtime download (evasion — not a typical npm dep)
  - C2/exfiltration domains (npm-cache[.]com, etc.)
  - npm token validation before exfil (registry.npmjs.org/-/whoami)

Attack chain (ChainDrop):
  1. Compromised maintainer → malicious commit
  2. package.json: "preinstall": "node setup.mjs"
  3. setup.mjs downloads Bun → runs infostealer → exfils tokens
  4. Stolen tokens → infect more repos → worm spreads
  5. GitHub Actions provenance = valid → bypasses trust checks
"""

from __future__ import annotations

import json
import re
import hashlib
from pathlib import Path
from typing import Any


# ── PACKAGE.JSON PATTERNS ─────────────────────────────────────────────

PACKAGE_JSON_RULES: list[tuple[str, str, str, float]] = [
    # --- Suspicious lifecycle scripts ---
    ("preinstall_script",
     r'"preinstall"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "CRITICAL", 0.90),
    ("postinstall_script",
     r'"postinstall"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "HIGH", 0.75),
    ("install_script",
     r'"install"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "HIGH", 0.70),

    # --- Known ChainDrop stagers ---
    ("setup_mjs_stager",
     r'setup\.mjs|loader\.mjs|init\.mjs|bootstrap\.mjs',
     "CRITICAL", 0.95),
    ("infostealer_payload",
     r'Math_Symbol\.js|math_init\.js|crypto_utils\.js|random_bytes\.js',
     "CRITICAL", 0.90),

    # --- Bun download evasion ---
    ("bun_runtime_download",
     r'(?i)(?:bun-sh/bun|bun\.sh|oven-sh/bun).{0,100}(?:releases/download|install)',
     "HIGH", 0.85),

    # --- Token/credential theft ---
    ("token_theft_npm",
     r'registry\.npmjs\.(?:org|com)/-/whoami',
     "CRITICAL", 0.95),
    ("token_theft_github",
     r'(?i)(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}',
     "CRITICAL", 0.85),
    ("aws_key_theft",
     r'(?i)(?:AKIA|ASIA)[A-Z0-9]{16}',
     "CRITICAL", 0.90),

    # --- Exfiltration ---
    ("exfil_domain",
     r'(?i)(?:npm-cache\.com|npm-cdn\.com|npm-registry\.xyz|'
     r'npm-mirror\.net|package-cache\.org)',
     "CRITICAL", 0.95),
    ("exfil_github_repo",
     r'(?i)github\.com/[^/]+/(?:Shai-Hulud|chaindrop|token-dump|'
     r'secret-exfil|cred-collector)',
     "CRITICAL", 0.90),

    # --- Obfuscation markers ---
    ("obfuscated_js",
     r'(?i)(?:atob|btoa)\s*\(\s*[\'"`][A-Za-z0-9+/=]{100,}[\'"`]\s*\)',
     "HIGH", 0.80),
    ("eval_obfuscation",
     r'eval\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode)',
     "HIGH", 0.85),

    # --- Dependency confusion / typo-squatting ---
    ("typo_squatting",
     r'"(?:@?\w+[-_](?:utils|helper|core|lib|common|config|tools|'
     r'auth|api|client|server|proxy|cache|logger|parser)[-_.]\w+)"\s*:\s*"[~^]',
     "LOW", 0.30),
]


# ── JS/MJS FILE PATTERNS ──────────────────────────────────────────────

JS_MALWARE_RULES: list[tuple[str, str, str, float]] = [
    ("bun_downloader",
     r'(?i)(?:fetch|https?://).{0,100}(?:github\.com/oven-sh/bun|'
     r'bun\.sh)/releases/download',
     "CRITICAL", 0.95),
    ("token_collector",
     r'(?i)process\.env(?!\.CI|\.NODE_ENV|\.PATH|\.HOME|\.USER)',
     "HIGH", 0.70),
    ("env_dump_all",
     r'(?i)(?:Object\.(?:entries|keys|values)|for\s*\(.*in)\s*\(?\s*process\.env',
     "CRITICAL", 0.85),
    ("file_exfiltrator",
     r'(?i)readFile(?:Sync)?\s*\(.{0,100}(?:npmrc|gitconfig|credentials|'
     r'id_rsa|\.env|config\.json)',
     "CRITICAL", 0.90),
    ("github_exfil_api",
     r'(?i)fetch\s*\(.{0,50}api\.github\.com.{0,50}'
     r'(?:contents|PUT|Authorization)',
     "CRITICAL", 0.90),
    ("encoded_payload",
     r'(?:atob|Buffer\.from)\s*\(\s*[\'"`][A-Za-z0-9+/=]{200,}[\'"`]\s*\)',
     "CRITICAL", 0.90),
]


# ── EXCLUSIONS ────────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
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
        "metadata": {"detector": "GS034", "pattern_id": rule_id.replace("GS034-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS034SupplyChainDetector:
    rule_id = "GS034"
    name = "npm Supply Chain Attack Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings

        fname = file_path.split("/")[-1].lower()
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''

        # Scan package.json
        if fname == "package.json":
            findings.extend(self._scan_package_json(file_path, content))

        # Scan JS/MJS files for malware patterns
        if ext in ('.js', '.mjs', '.cjs', '.ts'):
            findings.extend(self._scan_js_file(file_path, content))

        return findings

    def _scan_package_json(self, file_path: str, content: str) -> list[dict[str, Any]]:
        findings = []
        pattern_hits = 0

        for pattern_id, regex, severity, base_conf in PACKAGE_JSON_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = _snippet(content, line_no)
                findings.append(_finding(
                    f"GS034-{pattern_id}", severity,
                    f"Supply chain risk in package.json: {pattern_id}",
                    file_path, line_no, snippet, base_conf,
                ))
                pattern_hits += 1

        if pattern_hits >= 3:
            findings.append(_finding(
                "GS034-package_json_critical", "CRITICAL",
                f"package.json has {pattern_hits} supply chain red flags — likely compromised",
                file_path, 1, f"({pattern_hits} patterns matched)", 0.95,
            ))

        return findings

    def _scan_js_file(self, file_path: str, content: str) -> list[dict[str, Any]]:
        findings = []
        fname = file_path.split("/")[-1].lower()

        # Only flag uncommon filenames (not typical app code)
        suspicious_names = {'setup', 'loader', 'init', 'bootstrap', 'runtime',
                            'helper', 'utils', 'math_symbol', 'math_init',
                            'random_bytes', 'crypto_utils'}
        is_suspicious_name = any(n in fname.replace('.js', '').replace('.mjs', '')
                                 for n in suspicious_names)

        for pattern_id, regex, severity, base_conf in JS_MALWARE_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                # Boost confidence for files with suspicious names
                conf = min(0.98, base_conf + 0.1) if is_suspicious_name else base_conf
                snippet = _snippet(content, line_no)
                findings.append(_finding(
                    f"GS034-{pattern_id}", severity,
                    f"Supply chain malware pattern in JS: {pattern_id}",
                    file_path, line_no, snippet, conf,
                ))

        return findings


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS034"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS034: npm Malware Patterns — detect ChainDrop worms, dependency confusion, typosquatting in package.json"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS034SupplyChainDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        fname = fp.name.lower()
        ext = fp.suffix.lower()
        if fname != "package.json" and ext not in ('.js', '.mjs', '.cjs', '.ts'):
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

```

---

### GS035 — `gs035_php.py` (echelon 1, noise_tier `sensitive`, 239 lines)
```python
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

```

---

### GS036 — `gs036_nodejs.py` (echelon 1, noise_tier `sensitive`, 195 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS036 — Node.js/JavaScript Vulnerability Detector.

Detects:
  - Prototype pollution (__proto__, constructor.prototype assignments)
  - eval() with user input / dynamic strings
  - Command injection (child_process.exec with user input)
  - Path traversal (path.join with user-controlled segments)
  - SSRF via fetch/axios/request with user-provided URLs
  - NoSQL injection ($where, $regex with user input in MongoDB)
  - JWT none algorithm / hardcoded secret
  - dangerouslySetInnerHTML in JSX
  - Hardcoded secrets (API keys, tokens, passwords)
  - require() with dynamic paths
  - Insecure deserialization (node-serialize, js-yaml load)
  - ReDoS (regex with user input)
"""

from __future__ import annotations

import re
import hashlib
from typing import Any


NODE_RULES: list[tuple[str, str, str, float]] = [
    # --- Prototype Pollution ---
    ("prototype_pollution_proto",
     r'(?:obj|target|dest|data)\[["\']__proto__["\']\]\s*=',
     "CRITICAL", 0.95),
    ("prototype_pollution_constructor",
     r'(?:obj|target|dest|data)\.constructor\.prototype\s*=',
     "CRITICAL", 0.95),
    ("prototype_pollution_merge",
     r'(?i)(?:\.extend|\.merge|\.assign|Object\.assign)\s*\([^)]*req\.(?:body|query|params)',
     "CRITICAL", 0.90),

    # --- eval() injection ---
    ("eval_user_input",
     r'eval\s*\(\s*(?:req\.(?:body|query|params|headers)|process\.argv)',
     "CRITICAL", 0.98),

    # --- Command Injection ---
    ("command_injection_exec",
     r'(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^)]*(?:req\.(?:body|query|params)|process\.argv)',
     "CRITICAL", 0.95),
    ("command_injection_shell",
     r'(?:exec|execSync)\s*\([^,]*,[^{]*\{[^}]*shell\s*:\s*true',
     "HIGH", 0.80),

    # --- Path Traversal ---
    ("path_traversal",
     r'path\.(?:join|resolve)\s*\([^)]*req\.(?:body|query|params)',
     "HIGH", 0.85),
    ("path_traversal_fs",
     r'(?:readFileSync|readFile|createReadStream|createWriteStream)\s*\(\s*[^)]*req\.',
     "HIGH", 0.80),

    # --- SSRF ---
    ("ssrf_fetch",
     r'(?:fetch|axios|request|got|superagent)\s*\(\s*req\.(?:body|query|params)',
     "HIGH", 0.85),
    ("ssrf_http",
     r'(?:http\.get|http\.request|https\.get|https\.request)\s*\(\s*req\.',
     "HIGH", 0.80),

    # --- NoSQL Injection ---
    ("nosql_injection_where",
     r'\$(?:where|regex|ne|gt|lt|in|nin)\s*:',
     "HIGH", 0.70),
    ("nosql_injection_user_input",
     r'(?:\.find|\.findOne|\.update|\.deleteOne)\s*\(\s*req\.(?:body|query)',
     "HIGH", 0.75),

    # --- JWT ---
    ("jwt_none_algorithm",
     r'(?i)algorithm\s*:\s*["\']none["\']',
     "CRITICAL", 0.95),
    ("jwt_hardcoded_secret",
     r'(?i)(?:jwt\.sign|jwt\.verify)\s*\([^)]*["\'][A-Za-z0-9_-]{20,}["\']',
     "HIGH", 0.80),

    # --- React XSS ---
    ("dangerously_set_html",
     r'dangerouslySetInnerHTML\s*=\s*\{',
     "MEDIUM", 0.60),

    # --- Hardcoded Secrets ---
    ("hardcoded_api_key",
     r'(?i)(?:apiKey|api_key|apiSecret|api_secret|secretKey|secret_key)\s*[:=]\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_token",
     r'(?i)(?:token|authToken|accessToken)\s*[:=]\s*["\'](?:ghp_|gho_|github_pat_|sk-)[A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.90),

    # --- Dynamic require ---
    ("require_user_input",
     r'require\s*\(\s*req\.(?:body|query|params)',
     "CRITICAL", 0.90),

    # --- Deserialization ---
    ("insecure_deserialization",
     r'(?i)(?:serialize\.unserialize|js-yaml\.load|yaml\.load)\s*\(',
     "HIGH", 0.75),

    # --- ReDoS ---
    ("redos",
     r'(?:\.test|\.match|\.exec|\.replace)\s*\(\s*new\s+RegExp\s*\(\s*',
     "LOW", 0.40),

    # --- npm pre/postinstall — supply chain ---
    ("npm_lifecycle_script",
     r'"(?:preinstall|postinstall|install)"\s*:\s*"(?:node|sh|bash|curl|wget)',
     "CRITICAL", 0.90),
]


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
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
        "metadata": {"detector": "GS036", "pattern_id": rule_id.replace("GS036-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS036NodeDetector:
    rule_id = "GS036"
    name = "Node.js Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext not in ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'):
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in NODE_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS036-{pattern_id}", severity,
                    f"Node.js security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS036-high_risk", "CRITICAL",
                f"Node.js file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.95))
        return findings


RULE_ID = "GS036"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS036: Node.js Vulnerability Detection — prototype pollution, eval, command injection, SSRF, NoSQLi"


def detect(ctx) -> list[dict]:
    det = GS036NodeDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file(): continue
        ext = fp.suffix.lower()
        if ext not in ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'): continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS037 — `gs037_python.py` (echelon 1, noise_tier `sensitive`, 220 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS037 — Python Vulnerability Detector.

Detects:
  - pickle RCE (pickle.loads with untrusted data)
  - eval()/exec() with user input
  - SSTI in Jinja2 (render_template_string with user input)
  - Command injection (os.system/subprocess with user input)
  - YAML deserialization (yaml.load with unsafe Loader)
  - Hardcoded secrets (API keys, passwords, tokens)
  - Path traversal (open/os.path.join with user input)
  - SQL injection (string formatting in queries)
  - Insecure tempfile (tempfile.mktemp)
  - Debug mode enabled in production (DEBUG=True, Flask)
  - Insecure deserialization (marshal.loads with untrusted data)
  - XML external entity (XXE) in lxml/etree
"""

from __future__ import annotations

import re, hashlib
from typing import Any


PYTHON_RULES: list[tuple[str, str, str, float]] = [
    # --- pickle RCE ---
    ("pickle_rce",
     r'(?i)pickle\.(?:loads?|load)\s*\(\s*(?:request\.(?:data|form|args|json)|input\b)',
     "CRITICAL", 0.98),
    ("pickle_load_any",
     r'(?i)pickle\.(?:loads?|load)\s*\(', "HIGH", 0.70),

    # --- eval/exec ---
    ("eval_user_input",
     r'(?i)eval\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()',
     "CRITICAL", 0.95),
    ("exec_user_input",
     r'(?i)exec\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()',
     "CRITICAL", 0.95),

    # --- SSTI (Jinja2) ---
    ("ssti_render_template_string",
     r'(?i)render_template_string\s*\(\s*(?:request\.(?:args|form|json|data)|f["\'])',
     "CRITICAL", 0.90),
    ("ssti_format_string",
     r'(?i)\.format\s*\(.*request\.(?:args|form|json|data)',
     "HIGH", 0.70),

    # --- Command Injection ---
    ("command_injection_os",
     r'(?i)os\.(?:system|popen)\s*\(\s*(?:request\.(?:args|form|json|data)|f["\'])',
     "CRITICAL", 0.95),
    ("command_injection_subprocess",
     r'(?i)subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*(?:request\.|input\s*\()',
     "CRITICAL", 0.95),
    ("command_injection_shell_true",
     r'(?i)subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
     "HIGH", 0.80),

    # --- YAML Deserialization ---
    ("yaml_unsafe_load",
     r'(?i)yaml\.load\s*\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|Base)Loader)',
     "HIGH", 0.80),
    ("yaml_full_load",
     r'(?i)yaml\.(?:full_load|unsafe_load|load_all)\s*\(',
     "CRITICAL", 0.85),

    # --- Hardcoded Secrets ---
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "HIGH", 0.70),
    ("hardcoded_api_key",
     r'(?i)(?:API_KEY|api_key|api_key|SECRET_KEY)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "HIGH", 0.70),
    ("hardcoded_token",
     r'(?i)(?:token|auth_token|access_token)\s*=\s*["\'](?:sk-|ghp_|gho_)[A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.92),

    # --- Path Traversal ---
    ("path_traversal_open",
     r'(?i)(?:open|file)\s*\(\s*(?:os\.path\.join|f["\']).*(?:request\.|input)', "HIGH", 0.80),
    ("path_traversal_join",
     r'(?i)os\.path\.join\s*\([^)]*(?:filename|file_name|file_path|path)\b', "HIGH", 0.70),
    ("path_traversal_send_file",
     r'(?i)send_file\s*\(\s*[a-zA-Z_]\w*\s*\)', "HIGH", 0.65),

    # --- SQL Injection ---
    ("sql_injection_format",
     r'(?i)(?:\.execute|\.executemany)\s*\(\s*f["\'].*(?:request\.|input)', "CRITICAL", 0.90),
    ("sql_injection_percent",
     r'(?i)(?:\.execute|cursor\.execute)\s*\(\s*["\'].*%\s*(?:request\.|input\b)', "CRITICAL", 0.85),

    # --- Insecure Temp ---
    ("insecure_tempfile",
     r'tempfile\.mktemp\s*\(', "MEDIUM", 0.60),

    # --- Debug Mode ---
    ("debug_true",
     r'(?i)(?:DEBUG|debug)\s*=\s*True', "MEDIUM", 0.55),

    # --- XXE ---
    ("xxe_lxml",
     r'(?i)(?:etree\.parse|etree\.fromstring|etree\.XML)\s*\(', "HIGH", 0.60),
    ("xxe_sax",
     r'(?i)feature_external_(?:ges|entities)\s*[,\s]+True', "HIGH", 0.85),

    # --- marshal RCE ---
    ("marshal_rce",
     r'(?i)marshal\.loads?\s*\(\s*(?:request\.|input)', "CRITICAL", 0.91),
]


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
    r'(?:/|$)', re.IGNORECASE)


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key, "rule_id": rule_id, "title": title,
        "severity": severity, "category": severity, "confidence": confidence,
        "file_path": file_path, "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS037", "pattern_id": rule_id.replace("GS037-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


def _mask_docstrings(content: str) -> str:
    """Mask triple-quoted docstrings to spaces (preserve line numbers).

    Regex rules like pickle_load_any match code inside docstring examples
    (e.g. ``>>> record = pickle.loads(pipe.read())`` in a docstring), which is
    documentation, not executable code. Masking keeps line numbers intact so
    snippet/line reporting still points at the real location.
    """
    chars = list(content)
    n = len(chars)
    i = 0
    while i < n:
        # docstring open: ''' or """
        if i + 2 < n and ''.join(chars[i:i + 3]) in ('"""', "'''"):
            chars[i:i + 3] = '   '
            i += 3
            while i < n:
                # closing delimiter
                if i + 2 < n and ''.join(chars[i:i + 3]) in ('"""', "'''"):
                    chars[i:i + 3] = '   '
                    i += 3
                    break
                if chars[i] != '\n':
                    chars[i] = ' '
                i += 1
            continue
        i += 1
    return ''.join(chars)



class GS037PythonDetector:
    rule_id = "GS037"
    name = "Python Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.py':
            return findings
        hits = 0
        masked = _mask_docstrings(content)
        for pattern_id, regex, severity, base_conf in PYTHON_RULES:
            for match in re.finditer(regex, masked, re.MULTILINE):
                line_no = masked[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS037-{pattern_id}", severity,
                    f"Python security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS037-high_risk", "INFO",
                f"Python file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.40))
        return findings


RULE_ID = "GS037"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS037: Python Vulnerability Detection — pickle, eval, SSTI, command injection, deserialization"


def detect(ctx) -> list[dict]:
    det = GS037PythonDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.py': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS038 — `gs038_go.py` (echelon 1, noise_tier `sensitive`, 178 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS038 — Go Vulnerability Detector.

Detects:
  - SSTI in html/template (user input in template)
  - SQL injection (fmt.Sprintf in queries)
  - Command injection (os/exec with user input)
  - Hardcoded secrets (API keys, passwords, JWT secrets)
  - Insecure crypto (MD5, SHA1, DES, weak RSA)
  - Path traversal (filepath.Join with user input)
  - SSRF (http.Get with user input)
  - Insecure deserialization (encoding/gob with untrusted data)
  - Race conditions (unsynchronized shared state)
  - Debug endpoints in production (pprof exposed)
  - TLS verification disabled (InsecureSkipVerify=true)
  - Hardcoded JWT secrets
  - unsafe pointer usage
"""

from __future__ import annotations

import re, hashlib
from typing import Any


GO_RULES: list[tuple[str, str, str, float]] = [
    # --- SSTI ---
    ("ssti_template",
     r'(?i)(?:template\.Must|template\.New|tmpl\.Execute)\s*\(',
     "HIGH", 0.60),
    ("ssti_html_template",
     r'(?i)html/template.*\.Execute\s*\([^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query))',
     "CRITICAL", 0.85),

    # --- SQL Injection ---
    ("sql_injection_fmt",
     r'(?i)fmt\.Sprintf\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*[\'"]',
     "CRITICAL", 0.90),
    ("sql_injection_concat",
     r'(?i)(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*["\'].*%[svq].*[\'"]',
     "CRITICAL", 0.85),

    # --- Command Injection ---
    ("command_injection_exec",
     r'(?i)exec\.Command\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query)|os\.Args)',
     "CRITICAL", 0.95),
    ("command_injection_bash",
     r'(?i)exec\.Command\s*\(\s*["\'](?:bash|sh|zsh)["\']',
     "HIGH", 0.75),

    # --- Hardcoded Secrets ---
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_api_key",
     r'(?i)(?:ApiKey|API_KEY|apiKey|api_key|SecretKey|SECRET_KEY)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.90),
    ("hardcoded_jwt_secret",
     r'(?i)(?:jwtSecret|JWT_SECRET|jwt_secret|signingKey)\s*=\s*["\']',
     "HIGH", 0.80),

    # --- Weak Crypto ---
    ("weak_crypto_md5",
     r'(?i)(?:md5\.New|md5\.Sum|crypto/md5)', "HIGH", 0.70),
    ("weak_crypto_sha1",
     r'(?i)(?:sha1\.New|sha1\.Sum|crypto/sha1)', "MEDIUM", 0.55),
    ("weak_crypto_des",
     r'(?i)crypto/des', "MEDIUM", 0.50),

    # --- TLS ---
    ("tls_skip_verify",
     r'InsecureSkipVerify\s*:\s*true', "HIGH", 0.80),

    # --- SSRF ---
    ("ssrf_http_get",
     r'(?i)http\.Get\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query)|fmt\.Sprintf)',
     "HIGH", 0.85),
    ("ssrf_http_client",
     r'(?i)(?:http\.Client|http\.NewRequest).{0,100}(?:r\.(?:FormValue|URL\.Query))',
     "HIGH", 0.80),

    # --- Path Traversal ---
    ("path_traversal",
     r'(?i)(?:os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*filepath\.Join',
     "HIGH", 0.75),

    # --- Debug ---
    ("pprof_exposed",
     r'(?i)net/http/pprof', "MEDIUM", 0.55),

    # --- Unsafe ---
    ("unsafe_pointer",
     r'unsafe\.Pointer\s*\(',
     "MEDIUM", 0.50),

    # --- GORM injection risk ---
    ("gorm_raw_sql",
     r'(?i)\.Raw\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue)|fmt\.Sprintf)',
     "CRITICAL", 0.80),
]


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
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
        "metadata": {"detector": "GS038", "pattern_id": rule_id.replace("GS038-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS038GoDetector:
    rule_id = "GS038"
    name = "Go Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.go':
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in GO_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS038-{pattern_id}", severity,
                    f"Go security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS038-high_risk", "CRITICAL",
                f"Go file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.95))
        return findings


RULE_ID = "GS038"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS038: Go Vulnerability Detection — SSTI, SQLi, command injection, hardcoded secrets, weak crypto"


def detect(ctx) -> list[dict]:
    det = GS038GoDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.go': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS039 — `gs039_ruby.py` (echelon 1, noise_tier `sensitive`, 190 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS039 — Ruby Vulnerability Detector.

Detects:
  - YAML deserialization RCE (YAML.load/Psych.load with untrusted data)
  - Mass assignment (params.permit! / without strong params)
  - SSTI in ERB (ERB.new with user input)
  - Command injection (system/exec/backticks with user input)
  - SQL injection (string interpolation in ActiveRecord queries)
  - Hardcoded secrets (API keys, passwords, secret_key_base)
  - Open redirect (redirect_to with params)
  - Insecure deserialization (Marshal.load with untrusted data)
  - eval() with user input
  - SSRF (Net::HTTP/open-uri with user-provided URL)
  - Session fixation / cookie security
  - Dangerous send() with user-controlled method name
  - File disclosure (send_file with params[:file])
"""

from __future__ import annotations

import re, hashlib
from typing import Any


RUBY_RULES: list[tuple[str, str, str, float]] = [
    # --- YAML Deserialization ---
    ("yaml_load",
     r'(?i)YAML\.load\s*\(\s*(?!.*safe_load)',
     "CRITICAL", 0.90),
    ("yaml_unsafe",
     r'(?i)(?:YAML\.unsafe_load|Psych\.load|YAML\.load_file)\s*\(',
     "CRITICAL", 0.90),

    # --- Mass Assignment ---
    ("mass_assignment_permit_all",
     r'(?i)(?:\.permit!|params\.permit\s*\(\s*\)\s*(?!.*require))',
     "HIGH", 0.75),

    # --- SSTI (ERB) ---
    ("ssti_erb",
     r'(?i)ERB\.new\s*\(\s*[^)]*\#\{',
     "CRITICAL", 0.90),
    ("ssti_erb_user_input",
     r'(?i)ERB\.new\s*\(\s*params\[',
     "CRITICAL", 0.95),

    # --- Command Injection ---
    ("command_injection_system",
     r'(?i)(?:system|exec|spawn)\s*\(\s*[^)]*params\[',
     "CRITICAL", 0.95),
    ("command_injection_backtick",
     r'`[^`]*\#\{[^\}]*params\[[^\}]*\}[^`]*`',
     "CRITICAL", 0.90),
    ("command_injection_io",
     r'(?i)IO\.popen\s*\(\s*[^)]*params\[',
     "CRITICAL", 0.90),

    # --- SQL Injection ---
    ("sql_injection_where",
     r'(?i)\.where\s*\(\s*["\'].*\#\{',
     "CRITICAL", 0.85),
    ("sql_injection_find_by_sql",
     r'(?i)(?:find_by_sql|execute|select_all|select_rows)\s*\(\s*["\'].*\#\{',
     "CRITICAL", 0.90),

    # --- Hardcoded Secrets ---
    ("hardcoded_secret_key_base",
     r'(?i)secret_key_base\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.92),
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_api_key",
     r'(?i)(?:api_key|API_KEY|api_secret|API_SECRET)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.90),

    # --- Open Redirect ---
    ("open_redirect",
     r'(?i)redirect_to\s+params\[',
     "HIGH", 0.80),

    # --- Marshal Deserialization ---
    ("marshal_load",
     r'(?i)Marshal\.load\s*\(\s*(?:params|request|cookies)', "CRITICAL", 0.90),

    # --- eval ---
    ("eval_user_input",
     r'(?i)eval\s*\(\s*params\[', "CRITICAL", 0.95),

    # --- Dangerous send ---
    ("dangerous_send",
     r'(?i)\.send\s*\(\s*params\[', "HIGH", 0.75),

    # --- SSRF ---
    ("ssrf_open_uri",
     r'(?i)(?:open|URI\.open|open-uri)\s*\(\s*params\[', "HIGH", 0.80),
    ("ssrf_net_http",
     r'(?i)Net::HTTP\.(?:get|post|get_response)\s*\([^)]*params\[', "HIGH", 0.80),

    # --- File Disclosure ---
    ("file_disclosure_send_file",
     r'(?i)send_file\s+params\[', "HIGH", 0.80),

    # --- Session ---
    ("session_secret_weak",
     r'(?i)Rails\.application\.config\.secret_key_base', "LOW", 0.40),

    # --- Regex DoS ---
    ("regex_dos",
     r'(?i)\.(?:match|match\?|=~)\s*\/.*[\+\*]{2,}.*\/', "LOW", 0.40),
]


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
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
        "metadata": {"detector": "GS039", "pattern_id": rule_id.replace("GS039-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS039RubyDetector:
    rule_id = "GS039"
    name = "Ruby Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.rb':
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in RUBY_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS039-{pattern_id}", severity,
                    f"Ruby security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS039-high_risk", "CRITICAL",
                f"Ruby file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.95))
        return findings


RULE_ID = "GS039"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS039: Ruby Vulnerability Detection — YAML RCE, mass assignment, SSTI, SQLi, Marshal"


def detect(ctx) -> list[dict]:
    det = GS039RubyDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.rb': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### GS040 — `gs040_pii_disclosure.py` (echelon 1, noise_tier `normal`, 418 lines)
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""
GS040 — PII & Information Disclosure Detector.

Static analogue of OWASP ZAP passive scan rules adapted to source code:
  - PiiScanRule                              → hardcoded email addresses (PII)
  - InformationDisclosureSuspiciousCommentsScanRule → secrets left in comments
  - XDebugTokenScanRule / debug artifacts    → XDEBUG_*, adminer.php, phpinfo()
  - InfoPrivateAddressDisclosureScanRule     → private IPs in config files

Precision-first design (mirroring GS001's IBAN mod-97 validation): every
pattern carries an exclusion/validation gate, and whole categories of files
that can never be a real disclosure are skipped up front:

  - benchmark / test / fixture / example / vendor / node_modules trees
  - documentation (.md/.rst/.txt/.adoc) and README/CHANGELOG/LICENSE/...
  - package metadata (pyproject.toml, package.json, Cargo.toml, ...) where
    author/maintainer emails are legitimate public metadata, not PII

CWEs (per-pattern, in metadata):
  - pii_email         → CWE-359 (Exposure of Private Personal Information)
  - suspicious_comment → CWE-540 (Sensitive info in source code)
  - debug_token       → CWE-489 (Active Debug Code)
  - private_ip_config → CWE-200 (Exposure of Sensitive Information)
  - pii_in_log        → CWE-532 (Insertion of Sensitive Information into Log)
  - pii_to_third_party → CWE-359 (Exposure of Private Personal Information)

The two data-flow patterns (pii_in_log, pii_to_third_party) are the Bearer-
inspired extension: instead of only flagging a PII literal, they flag a
validated hardcoded PII literal *flowing into a sink* — a logging call or an
external HTTP request. This mirrors Bearer's sensitive-data-flow rules
(python_lang_logger / third_parties_*) in a precision-first, single-pass
regex form (hardcoded literals only; taint across assignments is out of scope
for this detector and belongs to the AST dataflow engine).
"""

from __future__ import annotations

import re
import hashlib
from typing import Any


# ── Patterns ─────────────────────────────────────────────────────────────────

# Strict RFC-ish email, negative-lookbehind so it never matches inside a longer
# token (e.g. a URL userinfo or a filename). Capture group 1 = full address.
_EMAIL_RE = re.compile(
    r'(?<![\w.%+-])'
    r'([A-Za-z0-9._%+-]+@'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)'
)

# Domains that are placeholders / test / disposable — never real PII.
_EMAIL_DOMAIN_BLOCK = frozenset({
    "example.com", "example.org", "example.net", "example.io", "example.co",
    "example.test", "test.com", "test.org", "test.net", "test.io",
    "localhost", "local", "invalid", "localhost.localdomain",
    "yourdomain.com", "your-domain.com", "domain.com", "mydomain.com",
    "email.com", "mail.com", "site.com", "website.com",
    "foo.com", "bar.com", "foo.org", "bar.org", "acme.com", "acme.org",
    "mailinator.com", "yopmail.com", "tempmail.com", "10minutemail.com",
    "guerrillamail.com", "dispostable.com", "fakemail.com",
    "example.local", "example.dev", "example.me", "sample.com",
    "ex.com", "example.co.uk", "example.test", "test.example.com",
})

# Non-PII local-parts (role accounts that are never a person's address).
_EMAIL_LOCAL_BLOCK = frozenset({
    "noreply", "no-reply", "no_reply", "donotreply", "do-not-reply",
    "support", "info", "contact", "help", "sales", "admin", "test",
    "user", "dev", "devnull", "null", "root", "postmaster", "webmaster",
    "abuse", "security", "privacy", "hello", "team", "office",
})

# An email is only a disclosure when it sits next to a context marker
# (email/contact/admin/... variable, SMTP config, etc.) OR inside a config
# file. A bare email in random code is almost always a test value.
# NOTE: `e-?mail` is intentionally NOT \b-bounded — snake_case identifiers
# like ADMIN_EMAIL / contact_email embed it after `_`, which `\b` misses
# (underscore is a word char, so there's no boundary before "email").
_EMAIL_CONTEXT_RE = re.compile(
    r'(?i)(?:e-?mail|smtp|mailto|notify|recipient|sender|\bcontact\b|\badmin\b)'
)

# Comment markers → languages where a secret-in-comment is meaningful.
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";", "%", "REM ")

# Secret keywords that make a comment suspicious when paired with a value.
_SECRET_KEYWORDS = (
    r"password", r"passwd", r"pwd", r"secret", r"token", r"api[_-]?key",
    r"apikey", r"credential", r"access[_-]?key", r"secret[_-]?key",
    r"private[_-]?key", r"auth[_-]?token", r"bearer", r"client[_-]?secret",
    r"db[_-]?pass", r"passphrase",
)

# Negative phrases / contexts that turn a comment into a warning or an
# explanation rather than a real leftover secret.
_COMMENT_NEGATIVE_RE = re.compile(
    r"(?i)\b(?:do\s*not|don'?t|never|avoid|should\s*not|must\s*not|"
    r"example|sample|placeholder|dummy|mock|fake|insert|change\s*me|"
    r"your[_-]?(?:password|key|token)|generate|openssl|rand|"
    r"enum|constant|not\s+a\s+secret|flood|reset[_-]?password)\b"
)

_COMMENT_SECRET_RE = re.compile(
    r'(?:#|//|/\*|\*|<!--|--|;|%)\s*'
    r'(?:TODO|FIXME|HACK|XXX|NOTE|REMOVE|TEMP|DEBUG|WARNING|DEPRECATED)?'
    r'[^\n]{0,40}?'
    r'(?:' + r"|".join(_SECRET_KEYWORDS) + r')\s*[:=]\s*'
    r'[\'"]?([^\s\'"]{4,})',
    re.IGNORECASE,
)
# Enum / error constants like TOKEN = "RESET_PASSWORD_BAD_TOKEN" are not
# secrets (same heuristic GS001 uses).
_CONSTANT_VALUE_RE = re.compile(r'^[A-Z][A-Z0-9_]{3,}$')
# Placeholder / template values are not secrets either: ${ENV_VAR}, $VAR,
# <token>, {{ .Values.x }}, %PLACEHOLDER%.
_PLACEHOLDER_VALUE_RE = re.compile(r'^[\$<{%%]')

# XDEBUG session/profile/config tokens + leftover debug artifacts.
_DEBUG_TOKEN_RE = re.compile(
    r'(?i)\b(?:XDEBUG_SESSION|XDEBUG_PROFILE|XDEBUG_CONFIG|XDEBUG_TRACE|'
    r'XDEBUG_SESSION_START)'
    r'(?:=|:|\s)\s*[\'"]?[^\s\'"]+'
)
_DEBUG_ARTIFACT_RE = re.compile(
    r'(?i)\b(?:adminer(?:-\d+(?:\.\d+)*)?\.php|phpinfo\.php|'
    r'phpinfo\s*\(\s*\)|webgrind|opcache-gui)\b'
)

# Private IPv4 ranges (RFC 1918 + link-local). Loopback/bind-all are excluded
# on purpose — 127.0.0.1 and 0.0.0.0 are never a disclosure.
_PRIVATE_IP_RE = re.compile(
    r'(?i)(?:host|server|ip|addr(?:ess)?|endpoint|url|'
    r'db[_-]?host|redis[_-]?host|api[_-]?host|'
    r'internal[_-]?(?:host|ip|url)?|gateway|proxy|bind)'
    r'\s*[:=]\s*[\'"]?(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3}'
    r')'
)

# URL-form connection strings (redis://, postgres://, ...) carrying a
# private IP in the authority — common in .env / docker-compose.
_PRIVATE_IP_URL_RE = re.compile(
    r'(?i)\b(?:redis|postgres(?:ql)?|mysql|mariadb|mongodb|amqp|rabbitmq|'
    r'http|https|ftp|smtp|ldap|elasticsearch|kafka|memcached)'
    r'://(?:[^@\s/]*@)?'
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3})'
)

# ── PII data-flow (hardcoded PII flowing into a sink) ──────────────────────
# Logging sinks across languages. A validated hardcoded PII literal inside
# one of these calls is CWE-532 (Insertion of Sensitive Information into Log).
_LOG_SINK_RE = re.compile(
    r'(?i)(?:'
    r'\b(?:logger|logging|log|LOGGER|console)\s*\.\s*'
    r'(?:info|debug|error|warn|warning|fatal|critical|exception|trace|log)\s*\(|'
    r'\b(?:System\.out\.println|System\.err\.println|'
    r'fmt\.Print(?:f|ln)?|log\.Print(?:f|ln)?|slog\.[A-Za-z]+|'
    r'error_log|Log::(?:info|debug|error|warning)|Rails\.logger\.[a-z_]+)\s*\('
    r')'
)

# HTTP sinks — a hardcoded PII literal sent to an external party (CWE-359).
_HTTP_SINK_RE = re.compile(
    r'(?i)(?:'
    r'\b(?:requests|httpx|aiohttp|urllib\.request|urllib)\s*\.\s*'
    r'(?:get|post|put|patch|delete|request|urlopen)\s*\(|'
    r'\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\.ajax)\s*\(|'
    r'\b(?:http\.Client|client\.(?:get|post|put|delete)|curl_exec)\s*\('
    r')'
)

# Credit-card PAN — 13-19 digits, Luhn-gated, plus a card-context keyword.
_CC_RE = re.compile(r'(?<!\d)(?:[0-9][ -]?){13,19}(?!\d)')
_CC_CONTEXT_RE = re.compile(
    r'(?i)(?:credit[_-]?card|card[_-]?number|cc[_-]?num|\bcard\b|'
    r'\bpan\b|cvv|cvc|cardnum)'
)

# US SSN — XXX-XX-XXXX, gated by a context keyword.
_SSN_RE = re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)')
_SSN_CONTEXT_RE = re.compile(r'(?i)(?:ssn|social[_-]?security|tax[_-]?id)')

# Config files where a private IP is a real disclosure (not app code where
# service mesh / local networking makes them legitimate).
_CONFIG_EXTS = frozenset({
    ".env", ".yaml", ".yml", ".json", ".conf", ".toml", ".ini",
    ".properties", ".cfg", ".cnf", ".config",
})

# Package metadata files — author/maintainer emails are legitimate public
# metadata here, never a PII disclosure.
_METADATA_NAMES = frozenset({
    "pyproject.toml", "setup.py", "setup.cfg", "package.json",
    "cargo.toml", "go.mod", "composer.json", "gemfile", "pom.xml",
    "build.gradle", "requirements.txt", "manifest.in", "pkginfo",
})

_EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:benchmark|tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build|docs?)'
    r'(?:/|$)', re.IGNORECASE)

_DOC_NAMES_PREFIX = (
    "readme", "changelog", "license", "contributing", "code_of_conduct",
    "code-of-conduct", "authors", "notice", "history", "security", "support",
)
_DOC_EXTS = (".md", ".rst", ".txt", ".adoc", ".markdown", ".textile")


def _excluded(file_path: str) -> bool:
    """True if the file can never be a real disclosure (bench/deps/docs/meta)."""
    if _EXCLUDE_PATH_RE.search(file_path):
        return True
    # Build/dist artifacts and package metadata: *.egg-info, SBOM exports.
    if ".egg-info" in file_path or file_path.endswith((".cdx.json", ".spdx.json")):
        return True
    name = file_path.rsplit("/", 1)[-1].lower()
    if name.startswith(_DOC_NAMES_PREFIX) or name.startswith("sbom"):
        return True
    if name.endswith(_DOC_EXTS):
        return True
    if name in _METADATA_NAMES or name == "pkg-info":
        return True
    return False


# ── Helpers ──────────────────────────────────────────────────────────────

def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float,
             cwe: str = "") -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    meta: dict[str, Any] = {"detector": "GS040",
                            "pattern_id": rule_id.replace("GS040-", "")}
    if cwe:
        meta["cwe"] = cwe
    return {
        "finding_key": key, "rule_id": rule_id, "title": title,
        "severity": severity, "category": severity, "confidence": confidence,
        "file_path": file_path, "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": meta,
    }


def _snippet(content: str, line_no: int, window: int = 1) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


def _valid_email(email: str) -> bool:
    local, _, domain = email.partition("@")
    dom = domain.lower().rstrip(".")
    if dom in _EMAIL_DOMAIN_BLOCK:
        return False
    if local.lower() in _EMAIL_LOCAL_BLOCK:
        return False
    if "." not in domain:  # bare hostname, not an address
        return False
    return True


def _luhn_valid(num: str) -> bool:
    """Luhn checksum for a candidate PAN (13-19 digits)."""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total > 0 and total % 10 == 0


def _has_pii_literal(line: str) -> bool:
    """True when the line carries a validated hardcoded PII literal."""
    for m in _EMAIL_RE.finditer(line):
        if _valid_email(m.group(1)):
            return True
    for m in _CC_RE.finditer(line):
        if _luhn_valid(m.group(0)) and _CC_CONTEXT_RE.search(line):
            return True
    if _SSN_RE.search(line) and _SSN_CONTEXT_RE.search(line):
        return True
    return False


# ── Detector ─────────────────────────────────────────────────────────────

class GS040PiiDisclosureDetector:
    rule_id = "GS040"
    name = "PII & Information Disclosure Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str,
               language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or _excluded(file_path):
            return findings

        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        lines = content.splitlines()
        is_config = ext in _CONFIG_EXTS

        for idx, raw in enumerate(lines):
            line_no = idx + 1
            line = raw.strip()

            # 1) PII email — precision gate: context marker OR config file.
            for m in _EMAIL_RE.finditer(line):
                email = m.group(1)
                if not _valid_email(email):
                    continue
                if is_config or _EMAIL_CONTEXT_RE.search(line):
                    findings.append(_finding(
                        "GS040-pii_email", "LOW",
                        "PII email address hardcoded in source",
                        file_path, line_no, _snippet(content, line_no),
                        0.70, "CWE-359"))
                    break  # one finding per line

            # 2) Secret left in a comment.
            if line and (line.startswith(_COMMENT_PREFIXES)
                         or line.startswith("/*") or line.startswith("<!--")):
                m = _COMMENT_SECRET_RE.search(raw)
                if m and not _COMMENT_NEGATIVE_RE.search(raw):
                    val = m.group(1)
                    if not _CONSTANT_VALUE_RE.match(val) \
                            and not _PLACEHOLDER_VALUE_RE.match(val):
                        findings.append(_finding(
                            "GS040-suspicious_comment", "MEDIUM",
                            "Sensitive value left in a comment",
                            file_path, line_no, _snippet(content, line_no),
                            0.80, "CWE-540"))

            # 3) Debug token / leftover debug artifact.
            if _DEBUG_TOKEN_RE.search(line) or _DEBUG_ARTIFACT_RE.search(line):
                findings.append(_finding(
                    "GS040-debug_token", "LOW",
                    "Debug token or debug artifact left in source",
                    file_path, line_no, _snippet(content, line_no),
                    0.75, "CWE-489"))

            # 4) Private IP in a config file (disclosure of internal topology).
            if is_config and (_PRIVATE_IP_RE.search(line)
                              or _PRIVATE_IP_URL_RE.search(line)):
                findings.append(_finding(
                    "GS040-private_ip_config", "LOW",
                    "Private/internal IP address hardcoded in config",
                    file_path, line_no, _snippet(content, line_no),
                    0.65, "CWE-200"))

            # 5) Hardcoded PII flowing into a logging sink (CWE-532).
            if _LOG_SINK_RE.search(line) and _has_pii_literal(line):
                findings.append(_finding(
                    "GS040-pii_in_log", "MEDIUM",
                    "Hardcoded PII value passed to a logging call",
                    file_path, line_no, _snippet(content, line_no),
                    0.75, "CWE-532"))

            # 6) Hardcoded PII transmitted to a third-party HTTP endpoint
            #    (CWE-359).
            elif _HTTP_SINK_RE.search(line) and _has_pii_literal(line):
                findings.append(_finding(
                    "GS040-pii_to_third_party", "MEDIUM",
                    "Hardcoded PII value sent to a third-party HTTP endpoint",
                    file_path, line_no, _snippet(content, line_no),
                    0.70, "CWE-359"))

        return findings


# ── Registry bridge ──────────────────────────────────────────────────────

RULE_ID = "GS040"
ECHELON = 1
NOISE_TIER = "normal"
description = ("GS040: PII & Information Disclosure — hardcoded emails, "
               "secrets in comments, debug tokens, private IPs in config")


def detect(ctx) -> list[dict]:
    det = GS040PiiDisclosureDetector()
    findings: list[dict] = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if _excluded(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings

```

---

### YAML custom rules

#### yaml_rules/ssti_injection.py
```python
# SSTI-001 — Server-Side Template Injection
# Based on: OWASP SSTI, PortSwigger SSTI labs, pentesting cheatsheet

from ..base import RegexDetector

RULE_ID = "YAML-SSTI001"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "Server-Side Template Injection (SSTI): user input flowing into "
    "template render without sanitization — can lead to RCE"
)

patterns = [
    # Flask/Jinja2: render_template_string with request data
    [r"render_template_string\s*\(\s*(?:request\.(?:args|form|values|data|json|get_json))",
     "Flask SSTI: render_template_string with user input — RCE risk"],

    # Flask/Jinja2: render_template with user-controlled template name
    [r"render_template\s*\(\s*(?:request\.(?:args|form|values)\.get)",
     "Flask SSTI: user-controlled template name — potential SSTI"],

    # Jinja2: direct template compilation from user input
    [r"jinja2\.(?:Template|Environment)\s*\(\s*(?:request\.|user_input|input_data)",
     "Jinja2 SSTI: Template/Environment from user input — RCE risk"],

    # Jinja2: env.from_string with request data
    [r"\.from_string\s*\(\s*(?:request\.(?:args|form|values|data))",
     "Jinja2 SSTI: from_string() with user input — RCE risk"],

    # Django: Template() with request.GET/POST
    [r"Template\s*\(\s*request\.(?:GET|POST)\b",
     "Django SSTI: Template() with request data — code execution risk"],

    # Generic: template rendering with string formatting of user input
    [r"\.render\s*\(\s*\*\*\s*(?:request\.(?:args|form|values))",
     "SSTI: .render(**request data) — template context injection"],

    # SSTI exploit payloads in code (pentest tools/debug endpoints)
    [r"\{\{\s*(?:config|self\._TemplateReference__context|''\.__class__\.__mro__)",
     "SSTI exploit payload: {{ config }} or MRO traversal — backdoor indicator"],

    # f-string in render_template_string (double injection)
    [r"render_template_string\s*\(\s*f['\"]",
     "SSTI + f-string: template rendered from Python f-string — critical"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="ssti-injection",
    patterns=patterns,
    severity="CRITICAL",
    confidence=0.92,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)

```

#### yaml_rules/reverse_shell.py
```python
# Auto-generated from pentesting-cheatsheet
# Rule: reverse-shell — Reverse shell one-liners in code = definitive backdoor

from ..base import RegexDetector

RULE_ID = "YAML-A7E2F001"
ECHELON = 2
NOISE_TIER = "precise"
description = "Reverse shell one-liner detected — definitive backdoor indicator"

patterns = [
    # Netcat reverse shells
    [r"\bnc\s+.*-e\s+/bin/(?:sh|bash)", "nc -e /bin/sh — netcat reverse shell"],
    [r"/bin/sh\s*\|\s*nc\s+", "/bin/sh | nc — piped netcat reverse shell"],
    [r"mknod\s+/tmp/p\s+p\s+&&\s+nc\s+", "mknod + nc — named pipe reverse shell"],
    [r"\btelnet\s+.*\|.*(/bin/sh|/bin/bash)\b", "telnet piped to shell — reverse shell"],

    # Bash TCP reverse shells
    [r"bash\s+-i\s*>&\s*/dev/tcp/", "bash -i >& /dev/tcp — interactive reverse shell"],
    [r"exec\s+\d+<>/dev/tcp/", "exec <> /dev/tcp — bash TCP reverse shell"],
    [r"/dev/tcp/.*\b(?:sh|bash)\b", "/dev/tcp with shell — bash reverse shell"],

    # Python reverse shells
    [r"pty\.spawn\s*\(\s*['\"]/bin/(?:sh|bash)['\"]", "pty.spawn('/bin/bash') — Python reverse shell"],
    [r"socket\.socket.*connect.*dup2.*execve?\s*\(['\"]/bin/(?:sh|bash)", "Python socket dup2 exec — reverse shell"],
    [r"subprocess\.call\s*\(\s*\[.*['\"]/bin/(?:sh|bash)['\"].*shell\s*=\s*True", "subprocess /bin/sh shell=True — reverse shell"],

    # PHP reverse shells
    [r"\bexec\s*\(\s*['\"]/bin/(?:sh|bash)\b", "exec('/bin/sh') — PHP reverse shell"],
    [r"\bshell_exec\s*\(\s*.*(?:nc\s+|/dev/tcp|/bin/sh)", "shell_exec with shell command — PHP reverse shell"],

    # Perl reverse shells
    [r"\bperl\b.*socket.*PF_INET.*SOCK_STREAM.*exec\s*['\"]/bin/sh", "Perl socket + exec — reverse shell"],

    # Ruby reverse shells
    [r"ruby\s+.*TCPSocket.*exec.*/bin/sh", "Ruby TCPSocket + exec — reverse shell"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="reverse-shell",
    patterns=patterns,
    severity="CRITICAL",
    confidence=0.95,
    languages=('python', 'javascript', 'shell', 'php', 'ruby', 'perl'),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)

```

#### yaml_rules/no_print_secrets.py
```python
# Auto-generated from gsc-rules/sample.yml
# Rule: no-print-secrets — Printing potentially sensitive data to stdout

from ..base import RegexDetector

RULE_ID = "YAML-B39DC08C"
ECHELON = 2
NOISE_TIER = "custom"
description = """Printing potentially sensitive data to stdout"""

patterns = [["\\bprint\\s*\\(.*(?:password|secret|token|key|api_key)", "print() with sensitive variable"], ["\\blogging\\.\\w+\\(.*(?:password|secret|token|key|api_key)", "logging sensitive data"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-print-secrets",
    patterns=patterns,
    severity="HIGH",
    confidence=0.75,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)

```

#### yaml_rules/no_eval_exec.py
```python
# Auto-generated from gsc-rules/sample.yml
# Rule: no-eval-exec — Use of eval() or exec() with dynamic input can lead to code injection

from ..base import RegexDetector

RULE_ID = "YAML-36ACF0AD"
ECHELON = 2
NOISE_TIER = "custom"
description = """Use of eval() or exec() with dynamic input can lead to code injection"""

patterns = [["\\beval\\s*\\(", "eval() call — potential code injection"], ["\\bexec\\s*\\(", "exec() call — potential code injection"], ["\\bcompile\\s*\\([^,]+,\\s*['\\\"](eval|exec|single)['\\\"]", "compile() in exec/eval mode"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-eval-exec",
    patterns=patterns,
    severity="HIGH",   # exec() without user-input check → not CRITICAL
    confidence=0.6,    # pattern-only, no taint analysis
    languages=('python', 'javascript'),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)

```

#### yaml_rules/no_debug_true.py
```python
# Auto-generated from gsc-rules/sample.yml
# Rule: no-debug-true — DEBUG=True in production Django/Flask config

from ..base import RegexDetector

RULE_ID = "YAML-ECB85AD8"
ECHELON = 2
NOISE_TIER = "custom"
description = """DEBUG=True in production Django/Flask config"""

patterns = [["\\bDEBUG\\s*=\\s*True\\b", "DEBUG=True — should be False in production"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-debug-true",
    patterns=patterns,
    severity="MEDIUM",
    confidence=0.85,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)

```


---

## 5. Constraints — what you may / may not change

### MAY change
- `*_PATTERNS` / `*_RULES` lists and their regexes.
- Local helper functions (`_has_sanitizer`, `_is_placeholder`, `_mask_*`, ...).
- Add **new** local skip/downgrade filters inside `detect()`.

### MUST NOT change
- `RULE_ID`, `ECHELON`, `NOISE_TIER` (unless explicitly argued + approved).
- The `Finding` / `AuditContext` contract.
- `description` strings (cosmetic only).
- The module's public signature `detect(ctx)`.

### Recall is non-negotiable
- Before suppressing a pattern, prove the real-vulnerability cases still match.
- Downgrade (`CRITICAL`→`HIGH`/`MEDIUM`) is preferred over deletion when the
  pattern is ambiguous. Only **delete** a pattern when it has **zero TP value**
  (name-only matches, fake CVEs, aggregate markers).

### Already fixed (do NOT re-propose)
- GS037: docstring masking + aggregate `GS037-high_risk` demoted to INFO.
- GS019: placeholder/test-secret markers (`0x0000…`, `10000000-…`, `6LeI…`).
- GS005: removed `execute with <collection>[idx]` unpacking patterns.
- DB seed `Hardcoded encryption key`: narrowed (bare `key` removed).
- DB pattern `pickle.load()`: deactivated (duplicate of GS037).

---

## 6. ANTI-HALLUCINATION guardrails (from past agent failures)

1. **Do not invent signatures.** A past agent rewrote `load_patterns()` with a
   non-existent `cursor.execute(...)` + `ORDER BY priority`. → Only diff code
   that appears verbatim in §3.
2. **Do not invent a DB layer.** If a detector is a plain regex module (no
   `sqlite3`, no `load_patterns`, no `rule_id` column), say so — do not add one.
3. **Trace the FP to its exact pattern.** A past agent "fixed" the OWASP `chmod`
   pattern while the FP actually came from `_perm_finding()`. → For every FP you
   cite, give `file:line` and the exact pattern/loop that produced it.
4. **Check for mirrors.** Some rules live in more than one file (e.g. a regex in
   a detector AND in the DB `patterns` table). State whether the file is unique
   or list every mirror.

Additional rules:
- If you need a symbol not in §3 → `UNKNOWN:<name>` and ask. Never fabricate.
- No vague "add a filter" answers — give the exact regex and insertion point.
- Never claim a "TP" on a vulnerable benchmark project without showing the
  snippet and arguing why it is genuinely exploitable (a `HOST="localhost"`
  default or a `!= '127.0.0.1'` comparison is NOT an SSRF TP).

---

## 7. Response format

For each detector you touch, emit a block:

```
## <GS0xx> <detector-name>
Type: <suppress | downgrade | narrow-regex | delete-pattern | add-taint-check>
File: <path.py>
Pattern/loop: <the exact _PATTERNS entry or loop that produces the FP>
FP evidence: <project file:line → snippet → why not a vuln>
Before:
    <current code>
After:
    <proposed code>
Rationale: <1-2 sentences>
FP-removed: <clean-project: N → 0>
TP-impact: <vuln-project: still N/N detected — with snippet proof>
Verification: <exact scan command + expected result>
```

Rank proposals by FP volume (biggest noise first). End with a summary table:

```
| Detector | Change | FP-removed | TP-impact |
```

---

## 8. Verification commands

```bash
cd ~/gsc
# Full test suite (must stay green — 461 passed, 5 skipped)
python3 -m pytest -q

# Clean projects (FP should drop)
python3 gsc.py scan benchmark/real_world/loguru --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/pendulum --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/piccolo-api --ci --json | grep -c CRITICAL

# Vulnerable projects (TP must NOT drop)
python3 gsc.py scan /tmp/gsc-calibration/pygoat --ci --json | grep -c CRITICAL
python3 gsc.py scan /tmp/gsc-calibration/dvpwa --ci --json | grep -c CRITICAL
```

Expected after a correct fix: clean-project CRITICAL drops toward 0 while
vuln-project CRITICAL stays ≥ its current baseline. Always report the exact
before/after numbers.
