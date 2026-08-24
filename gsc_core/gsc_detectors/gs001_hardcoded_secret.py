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
    (r'(?:secret(?:[_-]?key)?|jwt[_-]?secret[_-]?key)["\']?\s*\]?\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}["\']', "Hardcoded secret"),
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
    (r'(?:mongodb|mysql|postgres(?:ql)?|redis)://[^"\'\\s]{10,}', "Hardcoded connection string"),
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


# Template/interpolation artifacts that the loose password regex can match but
# are never literal secrets: HTML tags (<b>anything), SQL params (%(user)s),
# shell/env refs ($pass), mustache/handlebars ({{ lookup }}). Live FP cluster
# from clean repos (django `alter user %(user)s...`, pygoat `<b>anything`).
_TEMPLATE_ARTIFACT_RE = re.compile(r'[<>]|\$\(|%\(')


# Famous demo/example password VALUES (never real secrets in clean code).
# Data-driven from the 100-project benchmark: ruff `s3cr3t`×301, sqlalchemy
# `tiger`, fabric `jack`, plus canonical demo creds. Deliberately excludes
# weak-but-real teaching creds (admin123, admin, root, guest, test) that the
# vuln calibration set (vuln-flask `admin123`, pygoat) exercises as TP.
_DEMO_PASSWORD_VALUES = frozenset({
    "s3cr3t", "tiger", "hunter2", "letmein", "qwerty", "qwerty123",
    "monkey", "dragon", "iloveyou", "abc123", "abcd", "password1",
    "password123", "passw0rd", "p@ssw0rd", "iamusedfortesting",
    "my-super-secret-password", "mysekretpa$$word", "test-pass-123",
    "changeme", "changeit", "changethis", "jack", "default",
    # Python parameter-kind markers caught by the loose `password[:=]"..."` regex
    "kwonly", "posonly",
    # Library/context markers, not passwords
    "py-polars", "crates", "twisted@twistedmatrix.com",
})


def _is_template_artifact(matched: str) -> bool:
    """True when the matched text is a template/interpolation fragment, not a
    literal secret value."""
    return bool(_TEMPLATE_ARTIFACT_RE.search(matched))


def _extract_quoted_value(matched: str) -> str:
    """Extract the string-literal value from a `key="value"` match."""
    m = re.search(r'["\']([^"\']*)["\']', matched)
    return m.group(1) if m else ""


def _is_demo_password(matched: str) -> bool:
    """True when the password value is a well-known demo/example credential."""
    return _extract_quoted_value(matched).strip().lower() in _DEMO_PASSWORD_VALUES


def _is_public_key_material(matched: str) -> bool:
    """True if the value starts with a PEM public key header (not a secret)."""
    return _extract_quoted_value(matched).startswith("-----BEGIN")


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
    r'(?:^test_|_test\.|tests?\.py|testing\.py|conftest\.|setup\.cfg|\.ini$)', re.IGNORECASE)


# Internal dev connection hosts (docker-compose services, localhost) without
# credentials are config, not secrets.
_INTERNAL_CONN_HOSTS = re.compile(
    r'(?:://|@)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|'
    r'cache|db|redis|postgres|mysql|mongo|rabbitmq|elasticsearch)[:/]',
    re.IGNORECASE,
)


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
                # input()/getpass() prompt — value is user-entered, not hardcoded
                prefix = content[max(0, m.start() - 40):m.start()]
                if "input(" in prefix or "getpass" in prefix:
                    continue
                # Internal dev connection string (localhost/docker service) → config
                if "onnection" in label and _INTERNAL_CONN_HOSTS.search(matched):
                    continue
                if _is_placeholder(matched):
                    continue
                # Template/interpolation artifacts (HTML tags, SQL params, env refs)
                if _is_template_artifact(matched):
                    continue
                # Pure-numeric passwords (12345678, 111111) are weak defaults —
                # GS017's job, not a leaked secret. Deliberately NOT suppressing
                # alphanumeric teaching creds (admin123, admin, root, test): those
                # are TP in vuln-flask/pygoat calibration.
                if "assword" in label:
                    val = _extract_quoted_value(matched).strip().lower()
                    if val.isdigit():
                        continue
                # Connection strings with placeholder passwords (user:password@,
                # user:test@) are config examples, not production leaks.
                if "onnection" in label:
                    if re.search(r'://[^:]*:(?:password|test|changeme|admin|root|123456|qwerty|placeholder|example|dummy|fake|pass)@', matched, re.I):
                        continue
                # Demo/example credential values (scoped to password/secret labels)
                if _is_demo_password(matched) and ("assword" in label or "secret" in label):
                    continue
                # PEM public key material (certificates, not secrets)
                if _is_public_key_material(matched):
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
