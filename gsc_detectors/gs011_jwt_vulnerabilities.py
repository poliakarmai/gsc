# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

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
from gsc_detectors import AuditContext, Finding
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
                    references=["Hacking APIs Ch.8 Attacking Authentication"]
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
