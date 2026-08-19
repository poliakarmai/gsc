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
