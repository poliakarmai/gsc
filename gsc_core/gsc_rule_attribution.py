#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Unified title/category → rule_id attribution for legacy findings.

Single source of truth for mapping legacy pattern titles and legacy category
values (from scans that predate the rule_id migration) to GS0XX detector codes,
and for flagging code-quality noise so it stops polluting security metrics.

Consumers:
  - gsc_cli.main._derive_rule_id       (runtime attribution, legacy patterns)
  - scripts/gsc_backfill_rule_ids.py   (historical DB normalization)
  - scripts/gsc_remap_legacy.py        (one-shot GS000-LEGACY remap)

Attribution is deliberately conservative: a title naming a vulnerability family
is attributed to that family's detector; anything ambiguous falls through to the
GS000-LEGACY sentinel rather than being force-attributed to the wrong rule.
"""

from __future__ import annotations

import re

LEGACY_SENTINEL = "GS000-LEGACY"
QUALITY_TIER = "quality"

# ── Legacy category values → rule_id ────────────────────────────────────────
# Pre-severity-migration scans stored a coarse vulnerability family in the
# category column instead of a severity. These are unambiguous enough to remap.
CATEGORY_RULES: dict[str, str] = {
    "redirect": "GS022",
    "ssrf": "GS021",
    "csrf": "GS021",
    "jwt": "GS011",
    "command-injection": "GS004",
    "supply-chain": "GS009",
    # Left as sentinel (too ambiguous): injection, buffer-overflow,
    # path-traversal.
}

# ── Title keywords → rule_id (ordered, first match wins) ────────────────────
SECURITY_RULES: list[tuple[re.Pattern[str], str]] = [
    # File permissions / world-readable
    (re.compile(r"world[- ]readable|chmod:?\s*world|\(6\d{2}\)", re.I), "GS002"),
    # SQL / NoSQL injection (broad family)
    (re.compile(
        r"sql\s*injection|sql_injection|nosql|rawsql|where\s*raw|mysqli|pdo\b|"
        r"union\s*select|stacked\s*quer|time[- ]based|boolean[- ]based|\$where|"
        r"find_by_sql|read_sql|interpolat|in\s+query\b|\.text\(|db::select|raw\s*\(",
        re.I), "GS005"),
    # XSS
    (re.compile(r"xss|cross[- ]site\s+scripting|innerhtml|dangerouslysetinnerhtml",
                re.I), "GS020"),
    # Open redirect
    (re.compile(r"open\s+redirect|\bredirect\b", re.I), "GS022"),
    # SSRF / CSRF
    (re.compile(r"ssrf|server[- ]side\s+request\s+forgery", re.I), "GS021"),
    (re.compile(r"\bcsrf\b", re.I), "GS021"),
    # Secrets / hardcoded credentials (incl. legacy Cyrillic "Хардкод")
    (re.compile(
        r"hardcoded(?!\s*ip\b)|hard[- ]coded(?!\s*ip\b)|хардкод(?!\s*ip\b)|"
        r"credential|secret|\bapi\s*key\b|access\s*key|personal\s+access\s+token|"
        r"connection\s+string|database\s+url|encryption\s+key|session[/ ]?secret|"
        r"jwt\s*secret|\btoken\b",
        re.I), "GS029"),
    # PII / financial data exposure
    (re.compile(r"\biban\b|bank\s+account|\bpan\b|pci[- ]dss|\bpii\b|financial\s+data",
                re.I), "GS040"),
    # Weak / short passwords
    (re.compile(r"weak\s+password|short\s+password", re.I), "GS017"),
    # Insecure deserialization
    (re.compile(r"pickle|deseriali[sz]|unserialize|yaml_unsafe_load|yaml\.load",
                re.I), "GS037"),
    # Dynamic code execution
    (re.compile(r"eval\(|exec\(|compile\(", re.I), "GS037"),
    # Dangerous subprocess / command injection
    (re.compile(
        r"subprocess|os\.system|os\.popen|shell\s*=\s*true|command\s+injection|"
        r"getoutput|reverse\s+shell|nc\s+-e|pty\.spawn",
        re.I), "GS004"),
    # Mass assignment
    (re.compile(r"mass\s+assignment|permit_all|params\s+without\s+permit|"
                r"params\s+without\s+require", re.I), "GS012"),
    # Auth / session weaknesses
    (re.compile(r"session\s+fixation|session\s+regeneration|login\s+without\s+session|"
                r"without\s+mfa|reset_password|change_password|brute[- ]force",
                re.I), "GS019"),
    # JWT
    (re.compile(r"\bjwt\b|verify\s*=\s*false|hs256", re.I), "GS011"),
    # Prompt injection
    (re.compile(r"prompt\s+injection", re.I), "GS032"),
    # Debug prints / leftovers
    (re.compile(r"\bprint\(|\bconsole\.log\b|\bpdb\b|println|debugger\s+statement|"
                r"debug\s+leftover", re.I), "GS003"),
    # Payment abuse / business-logic
    (re.compile(r"payment|idempotency|refund|promo\s+code|without\s+state\s+validation|"
                r"send_sms|verify_code|apply_plan_discount", re.I), "GS018"),
    # GraphQL
    (re.compile(r"graphql", re.I), "GS013"),
    # IDOR / enumeration
    (re.compile(r"idor|direct\s+pk\s+lookup|ownership\s+check|id\s+enumeration|"
                r"sequential\s+id", re.I), "GS007"),
    # Linux privilege escalation
    (re.compile(r"sudo|nopasswd|privilege\s+escalation|priv\s+esc|chmod\s*\+s|"
                r"linux\s+priv", re.I), "GS016"),
    # SCA / CVE references
    (re.compile(r"cve-\d{4}", re.I), "GS030"),
    # IaC / systemd hardening
    (re.compile(r"systemd|terraform|security\s+group|0\.0\.0\.0/0", re.I), "GS031"),
    # Go-specific secrets / crypto
    (re.compile(r"go:?\s+hardcoded|go:?\s+insecure\s+tls|crypto/md5|crypto/sha1|"
                r"math/rand\s+for\s+security", re.I), "GS038"),
]

# ── Code-quality titles (non-security) → noise_tier='quality' ───────────────
QUALITY_RULES: list[re.Pattern[str]] = [
    re.compile(r"assert\s+in\s+production", re.I),
    re.compile(r"\.clone\(\)\s+in\s+hot\s+path", re.I),
    re.compile(r"unwrap\(\)\s+in\s+non[- ]test|expect\(\)\s+without", re.I),
    re.compile(r"bare\s+except", re.I),
    re.compile(r"dead\s+constant", re.I),
    re.compile(r"generic\s+code\s+smell", re.I),
    re.compile(r"any\s+type\s+escape\s+hatch", re.I),
    re.compile(r"process\.env\s+without\s+fallback", re.I),
    re.compile(r"unhandled\s+error", re.I),
    re.compile(r"panic\s+in\s+library", re.I),
    re.compile(r"goroutine\s+leak", re.I),
    re.compile(r"mutex\s+copy", re.I),
    re.compile(r"ioutil\s+deprecated", re.I),
    re.compile(r"printstacktrace", re.I),
    re.compile(r"instead\s+of\s+logging", re.I),
    re.compile(r"declared\s+but\s+never\s+read", re.I),
    re.compile(r"file\s+has\s+\d+\s+security\s+issues", re.I),
    re.compile(r"entry[- ]point\s+directory|route\s+handler|application\s+entry", re.I),
    # Legacy Cyrillic code-quality titles (Russian-language scans).
    re.compile(r"f401\s+ошибок|неиспользуемых\s+импорт", re.I),
    re.compile(r"import\s+\w+\s+в\s+середине|импорты\s+внутри\s+функций", re.I),
    re.compile(r"дублирующийся\s+docstring|копипаст\s+в\s+лог", re.I),
    re.compile(r"мёртвый\s+код", re.I),
    re.compile(r"logging\s+без\s+basicconfig", re.I),
    re.compile(r"dict\s+вместо\s+typeddict", re.I),
    re.compile(r"синхронный\s+код\s+в\s+async", re.I),
    # Hardcoded-IP legacy patterns (patterns DB id=21/40, already active=0) —
    # a removed regex that matched version strings, URLs, SVG viewBox coords and
    # DOIs as if they were IPs. Not secrets (GS029) and not code-quality per se;
    # bucket as quality so they stop polluting security metrics.
    re.compile(r"IP\s*адрес|IP\s*address|hardcoded\s+IP|IP[- ]whitelist", re.I),
]


def attribute_rule_id(title: str, category: str = "") -> str:
    """Return the GS0XX rule_id for a legacy finding, or the sentinel.

    Category takes precedence (legacy category values are unambiguous), then
    title keywords.
    """
    cat = (category or "").strip().lower()
    if cat in CATEGORY_RULES:
        return CATEGORY_RULES[cat]
    if not title:
        return LEGACY_SENTINEL
    for regex, rule_id in SECURITY_RULES:
        if regex.search(title):
            return rule_id
    return LEGACY_SENTINEL


def is_quality(title: str) -> bool:
    """True when a title denotes a code-quality (non-security) finding."""
    if not title:
        return False
    return any(r.search(title) for r in QUALITY_RULES)


def attribute(title: str, category: str = "") -> tuple[str, str]:
    """Return (rule_id, noise_tier) for a legacy finding.

    noise_tier is 'quality' for code-quality findings, 'normal' otherwise.
    Code-quality wins over security attribution: a "print()" debug leftover is
    quality, not a GS003 security signal.
    """
    if is_quality(title or ""):
        return LEGACY_SENTINEL, QUALITY_TIER
    return attribute_rule_id(title, category), "normal"
