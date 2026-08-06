# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

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
from gsc_detectors import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS014"
ECHELON = 2
description = "Credential exposure — stored credentials, backup auth files, weak sudoers"


# Files that indicate credential exposure
CREDENTIAL_FILE_PATTERNS = [
    # Windows-like credential files
    (["*.sam", "*.sam.bak", "SYSTEM", "SYSTEM.bak", "ntds.dit"],
     "Potential SAM/SYSTEM backup — Windows credential database",
     "CRITICAL", "SAM/SYSTEM backups allow offline credential extraction."),

    # DPAPI master keys
    (["*/DPAPI/*", "*/Microsoft/Protect/*"],
     "DPAPI master key file — encrypted credential storage",
     "MEDIUM", "DPAPI keys may contain decryptable credentials if user password is known."),

    # Credential manager files
    (["*.rdp", "*.rdg", "credentials.xml", "SiteList.xml"],
     "Stored credential file (RDP/MacAfee/credential manager)",
     "HIGH", "RDP and credential manager files may contain saved passwords."),

    # SSH keys with weak paths
    (["id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key"],
     "Private key file — verify proper permissions and no passphrase",
     "MEDIUM", "Private keys should have 600 permissions and passphrase protection."),

    # Config files with potential credentials
    (["*.env", ".env.*", "*.envrc", ".credentials", "*credentials*"],
     "Environment/credential file — check for hardcoded secrets",
     "LOW", "These files should be gitignored. Verify no secrets are committed."),

    # Unattended installation files
    (["autounattend.xml", "unattend.xml", "Unattend.xml",
      "*.kickstart", "preseed.cfg", "answerfile*"],
     "Unattended installation file — may contain encoded passwords",
     "CRITICAL", "Unattended files often contain base64-encoded admin passwords."),

    # Shell history files (shouldn't be in repo)
    ([".bash_history", ".zsh_history", ".fish_history", ".psql_history", ".mysql_history"],
     "Shell history file in repo — may contain credentials in command lines",
     "MEDIUM", "Shell history files may contain passwords passed as command arguments."),
]

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

    # PostgreSQL connection strings with password
    (re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@', re.I),
     "PostgreSQL connection string with embedded password", "HIGH",
     "Database URL contains password in plaintext. Use environment variable."),

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


def _match_glob(path: Path, pattern: str) -> bool:
    """Simple glob matching for credential file patterns."""
    import fnmatch
    # Handle path patterns like */DPAPI/*
    if "/" in pattern or "\\" in pattern:
        return fnmatch.fnmatch(str(path).replace("\\", "/"), pattern)
    return fnmatch.fnmatch(path.name, pattern)


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS014" in ctx.skipped_detectors:
        return []
    findings = []

    # Get ALL files (not just source — credential files may be in any location)
    all_files = ctx.get_files()

    for fp in all_files:
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Check filename patterns
        for patterns, title, severity, detail in CREDENTIAL_FILE_PATTERNS:
            for pat in patterns:
                if _match_glob(fp, pat):
                    # Don't flag SSH keys in .ssh/ directories (user home)
                    if fp.suffix in (".pem", ".key") or fp.name.startswith("id_"):
                        if ".ssh/" in str(fp):
                            continue  # Expected location for SSH keys

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
                    break  # One finding per file

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

    return findings
