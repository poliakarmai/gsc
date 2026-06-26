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
]


# ── False positive filters ──────────────────────────────────────────────────

def _is_placeholder(value: str) -> bool:
    """Filter out obvious placeholder values."""
    placeholders = ("***", "your-", "xxxx", "changeme", "replace_me", "TODO",
                    "{}{}", "%s%s", "__yt_dlp_token__")
    return any(p in value.lower() for p in placeholders)


# ── Main detector ───────────────────────────────────────────────────────────

def detect(ctx: AuditContext) -> list[Finding]:
    """Scan all source files for hardcoded secrets."""
    if "GS001" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_source_files():
        content = ctx.read_file(fp)
        for pattern, label in _SECRET_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched = m.group(0)
                if _is_placeholder(matched):
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
