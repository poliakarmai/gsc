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
        if re.search(r'(?:^|/)(?:tests?|fixtures?|examples?|samples?|e2e|__tests__)/', str(fp), re.I):
            continue
        if re.search(r'(?:^test_|_test\.|tests?\.py|testing\.py|conftest\.)', fp.name, re.I):
            continue
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
            m = match.group(0)
            # Enum member like `ADMIN = "admin"` (UPPER lhs, self-referential value)
            # inside `class X(Enum)` is a role name, not a credential pair — skip.
            # Lowercase `admin = "admin"` stays a real default-credential pair.
            lhs = re.search(r'(?:^|\n)\s*(\w+)\s*[:=]', m)
            rhs = re.search(r'["\'](\w+)["\']', m)
            if lhs and rhs and lhs.group(1).isupper() and lhs.group(1).lower() == rhs.group(1).lower():
                continue
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
