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

from gsc_detectors import AuditContext, Finding

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
                    )
    return any(p in value.lower() for p in placeholders)


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
