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
