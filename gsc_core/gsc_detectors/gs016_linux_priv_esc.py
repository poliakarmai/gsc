# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS016 — Linux Privilege Escalation Paths Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects privilege escalation vectors learned from:
- OverTheWire Bandit levels 0-12
- Common Linux misconfigurations
- SUID/GUID/capability abuse patterns
- Writable cron/systemd paths
- World-readable sensitive configs
- Command obfuscation techniques (spaces, dashes, hidden files)

Sources: Bandit wargame, CIS Benchmarks, OWASP Linux Hardening
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS016"
ECHELON = 2
NOISE_TIER = "normal"
description = "Linux privilege escalation paths — SUID, cron, sudo, capabilities, world-readable secrets"

# ── Regex patterns ──────────────────────────────────────────────────────────

# SUID/GUID binaries that shouldn't have it
SUID_BINARIES = re.compile(
    r'chmod\s+[47]\d{2,3}\s+/(?!usr/local|tmp/).*'
    r'|chmod\s+u\+s\s+/(?!usr/local|tmp/).*'
    r'|-rwsr-xr-x.*/(?!usr/(bin|lib|libexec|sbin)|sbin/|bin/).*',
    re.MULTILINE,
)

# Sudo NOPASSWD for non-root users
SUDO_NOPASSWD = re.compile(
    r'^\s*[^#\s]+\s+ALL\s*=\s*\(ALL\)\s*NOPASSWD\s*:\s*ALL',
    re.MULTILINE,
)

# World-readable files matching password/shadow/key patterns
WORLD_READABLE_SECRETS = re.compile(
    r'^-r..r..r[-x].*\s+(/etc/(?:shadow|gshadow)\b'
    r'|/home/[^/]+/\.(ssh|gnupg|aws|config/gcloud)/\S+'
    r'|.*\.(pem|key|p12|pfx|jks|keystore)$)',
    re.MULTILINE,
)

# Cron jobs or systemd timers with writable scripts
WRITABLE_CRON = re.compile(
    r'^\s*[^#].*\s+(/home/|/tmp/|/var/tmp/|/opt/)\S+\.(sh|py|rb|pl)\b',
    re.MULTILINE,
)

# Files with leading dashes or special characters (Bandit L2 obfuscation)
OBFUSCATED_FILENAMES = re.compile(
    r'^\s*(-[rwx-]{9}|[rwx-]{9})\s+.*\s+'
    r'(--[\w\s-]+|\.\.\.[\w-]+|[^\w./-][^\w./-][\w\s.-]+)\s*$',
    re.MULTILINE,
)

# Dangerous capabilities on binaries (cap_setuid, cap_sys_admin, etc.)
DANGEROUS_CAPABILITIES = re.compile(
    r'cap_setuid\+e[ip]|cap_sys_admin\+e[ip]|cap_dac_override\+e[ip]'
    r'|cap_net_raw\+e[ip]|cap_sys_ptrace\+e[ip]',
)

# PATH hijack — writable directories early in PATH
WRITABLE_PATH = re.compile(
    r'(export\s+)?PATH\s*=\s*["\']?(\.:?|/tmp|/var/tmp|/dev/shm)[^"\']*["\']?',
)

# Python eval/exec with user input (Bandit-style code injection)
DANGEROUS_EVAL = re.compile(
    r'\b(eval|exec|__import__)\s*\(\s*(input|sys\.argv|request\.\w+|raw_input)',
)

# Password in command line arguments (visible in ps)
PASSWORD_IN_CMD = re.compile(
    r'(passwd|password|pass|pwd|secret|token|key)\s*=\s*["\'][^\s]{4,}["\']'
    r'\s+(ssh|mysql|psql|curl|wget|aws|gcloud)\b',
)


def _check_line(line: str, lineno: int, file_path: str) -> list[Finding]:
    """Check a single line against all patterns."""
    findings = []

    checks = [
        (SUID_BINARIES, "CRITICAL", "SUID binary outside standard system paths — potential privilege escalation"),
        (SUDO_NOPASSWD, "CRITICAL", "Sudo NOPASSWD:ALL — unrestricted root access without password"),
        (WORLD_READABLE_SECRETS, "CRITICAL", "World-readable credential file — secrets exposed to all users"),
        (DANGEROUS_CAPABILITIES, "HIGH", "Dangerous Linux capability on binary — container escape or privilege escalation"),
        (WRITABLE_CRON, "HIGH", "Writable script in user directory executed by cron — privilege escalation via cron hijack"),
        (DANGEROUS_EVAL, "HIGH", "eval/exec with untrusted input — arbitrary code execution"),
        (WRITABLE_PATH, "MEDIUM", "Writable directory in PATH early entry — PATH hijacking risk"),
        (PASSWORD_IN_CMD, "MEDIUM", "Password in command-line argument — visible in /proc and ps output"),
        (OBFUSCATED_FILENAMES, "LOW", "Obfuscated filename (leading dashes, triple dots) — anti-forensics or hiding technique"),
    ]

    for pattern, severity, message in checks:
        if pattern.search(line):
            findings.append(Finding(
                rule_id=RULE_ID,
                severity=severity,
                file_path=file_path,
                line=lineno,
                detail=message,
                fix_suggestion=f"Review and remove the privilege escalation vector: {line.strip()[:100]}",
                cwe="CWE-269" if severity == "CRITICAL" else "CWE-732" if severity == "HIGH" else "CWE-668",
            ))

    return findings


def detect(ctx: AuditContext) -> list[Finding]:
    """Detect privilege escalation paths in shell scripts, configs, playbooks."""
    if RULE_ID in ctx.skipped_detectors:
        return []

    findings = []
    target_extensions = {'.sh', '.bash', '.py', '.rb', '.pl',
                         '.conf', '.cfg', '.ini', '.service',
                         '.yaml', '.yml', '.toml',
                         'sshd_config', 'sudoers', 'crontab',
                         'Dockerfile', 'Makefile'}

    for fp in ctx.get_source_files():
        # Check by extension or filename
        ext = fp.suffix.lower()
        name = fp.name.lower()
        if ext not in target_extensions and name not in target_extensions:
            continue
        if ext in ('.md', '.txt', '.org', '.rst'):
            continue

        try:
            content = fp.read_text()
        except Exception:
            continue

        for lineno, line in enumerate(content.split('\n'), 1):
            if not line.strip() or line.strip().startswith('#'):
                continue
            findings.extend(_check_line(line, lineno, str(fp)))

    return findings
