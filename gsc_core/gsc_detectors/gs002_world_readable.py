# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS002 — World-readable files.

Detects files with overly permissive permissions (644+ on sensitive files).
Inspired by CVE Lite OA002-floating-tag pattern.
"""

import os
import stat
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS002"
ECHELON = 2

# Sensitive file patterns to check
_SENSITIVE_PATTERNS = [
    "*.pem", "*.key", "*.crt", "*.cer",
    "*.pkcs12", "*.pfx", "*.p12",
    ".env", ".env.*",
    "*.conf", "*.config",
    "id_rsa*", "id_ed25519*", "id_ecdsa*",
    "authorized_keys", "known_hosts",
    "credentials*", "secrets*",
]


def _is_sensitive(filepath: Path) -> bool:
    """Check if file matches sensitive patterns."""
    name = filepath.name
    for p in _SENSITIVE_PATTERNS:
        if filepath.match(p):
            return True
    # Also check: files with mode 0o777, 0o666 (world-read/write)
    return False


def detect(ctx: AuditContext) -> list[Finding]:
    """Check file permissions for sensitive files."""
    if "GS002" in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []
    for fp in ctx.get_files():
        if not _is_sensitive(fp):
            continue
        # Skip test certs/keys — expected to be world-readable for CI/CD
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
