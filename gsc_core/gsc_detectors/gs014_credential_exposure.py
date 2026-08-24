# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

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
from . import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS014"
ECHELON = 2
description = "Credential exposure — stored credentials, backup auth files, weak sudoers"


# Files that indicate credential exposure.
# Entry shape: (patterns, title, severity, detail, fixture_sensitive).
# `fixture_sensitive=True` → skip test/fixture paths (vectors/, test/, tests/,
# fixtures/, dummyserver/, *.example/*.sample/*.template/*.test) — those are
# test fixtures / public materials, not real committed credentials.
CREDENTIAL_FILE_PATTERNS = [
    # Windows-like credential files
    (["*.sam", "*.sam.bak", "SYSTEM", "SYSTEM.bak", "ntds.dit"],
     "Potential SAM/SYSTEM backup — Windows credential database",
     "CRITICAL", "SAM/SYSTEM backups allow offline credential extraction.", False),

    # DPAPI master keys
    (["*/DPAPI/*", "*/Microsoft/Protect/*"],
     "DPAPI master key file — encrypted credential storage",
     "MEDIUM", "DPAPI keys may contain decryptable credentials if user password is known.", False),

    # Credential manager files
    (["*.rdp", "*.rdg", "credentials.xml", "SiteList.xml"],
     "Stored credential file (RDP/MacAfee/credential manager)",
     "HIGH", "RDP and credential manager files may contain saved passwords.", False),

    # SSH keys with weak paths
    (["id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key"],
     "Private key file — verify proper permissions and no passphrase",
     "MEDIUM", "Private keys should have 600 permissions and passphrase protection.", True),

    # Config files with potential credentials
    (["*.env", ".env.*", "*.envrc", ".credentials", "credentials.yml",
      "credentials.json", "credentials.ini", ".netrc"],
     "Environment/credential file — check for hardcoded secrets",
     "LOW", "These files should be gitignored. Verify no secrets are committed.", True),

    # Unattended installation files
    (["autounattend.xml", "unattend.xml", "Unattend.xml",
      "*.kickstart", "preseed.cfg", "answerfile*"],
     "Unattended installation file — may contain encoded passwords",
     "CRITICAL", "Unattended files often contain base64-encoded admin passwords.", False),

    # Shell history files (shouldn't be in repo)
    ([".bash_history", ".zsh_history", ".fish_history", ".psql_history", ".mysql_history"],
     "Shell history file in repo — may contain credentials in command lines",
     "MEDIUM", "Shell history files may contain passwords passed as command arguments.", False),
]

# PostgreSQL connection strings, extracted from CONTENT_PATTERNS so they get
# dedicated FP filters (self-reference, variable interpolation, placeholder
# passwords, documentation/docstring) instead of the old single-lookahead.
POSTGRES_CONN_RE = re.compile(
    r'postgres(?:ql)?://(?P<pg_user>[^:@]+):(?P<pg_pass>[^@]+)@',
    re.I,
)

# Placeholder/example passwords — PREFIX match, not exact token: password123@,
# your_password@, test_password@ are all documentation, not real creds. The old
# lookahead `(?!token@)` only matched the exact token@ and let these slip.
PG_PLACEHOLDER_RE = re.compile(
    r'(?:\*\*\*|passw(?:or)?d|pass|pwd|secret|change[_-]?me|example|your|xxx|'
    r'scott|tiger|user|test|admin|postgres(?:ql)?|demo|sample|dummy|'
    r'foo|bar|baz|redacted|placeholder)',
    re.I,
)

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

# Public cert/key PEM headers — these are NOT private keys and must not be flagged.
PUBLIC_KEY_MARKERS = (
    "BEGIN CERTIFICATE", "BEGIN PUBLIC KEY", "BEGIN X509",
    "BEGIN TRUSTED CERTIFICATE", "BEGIN RSA PUBLIC KEY",
    "BEGIN EC PUBLIC KEY", "BEGIN DSA PUBLIC KEY",
)

# Directory components that mark a test/fixture path (not real credentials).
TEST_FIXTURE_COMPONENTS = {
    "vectors", "testdata", "fixtures", "__fixtures__", "tests", "test", "dummyserver",
}


def _match_glob(path: Path, pattern: str) -> bool:
    """Simple glob matching for credential file patterns."""
    import fnmatch
    # Handle path patterns like */DPAPI/*
    if "/" in pattern or "\\" in pattern:
        return fnmatch.fnmatch(str(path).replace("\\", "/"), pattern)
    return fnmatch.fnmatch(path.name, pattern)


def _is_test_fixture_path(rel_path: str) -> bool:
    """True if rel_path is a test vector / fixture / example file, not a real credential."""
    p = rel_path.replace("\\", "/").lower()
    parts = p.split("/")
    for comp in parts[:-1]:                     # directory components only
        if comp in TEST_FIXTURE_COMPONENTS:
            return True
    name = parts[-1]
    if name == "test.env":
        return True
    return name.endswith((".example", ".sample", ".template", ".test"))


def _in_docstring(content: str, pos: int) -> bool:
    """True if `pos` sits inside a \"\"\"...\"\"\" / '''...''' docstring block.

    Quote-parity is an approximation (acceptable per the brief's "context
    analysis" tool): a URL inside a string literal is an example, not a real
    credential, so a false "in docstring" only ever suppresses an FP.
    """
    for quote in ('"""', "'''"):
        if content[:pos].count(quote) % 2 == 1:
            return True
    return False


def _is_public_key_material(fp: Path) -> bool:
    """True if a .pem/.key file is a public certificate/key (not a private key).

    Covers three cases:
    1. binary (DER) content — a PEM private key is always ASCII/base64, so a
       binary .pem/.key is a DER certificate/public key;
    2. PEM headers that mark a public cert/key (BEGIN CERTIFICATE / PUBLIC KEY);
    3. raw OpenSSH public keys (ssh-rsa AAAA…, ssh-ed25519 …) stored in *.key.
    """
    try:
        head = fp.read_bytes()[:2048]
    except Exception:
        return False
    if not head:
        return False
    # Binary (DER) content cannot be a PEM private key (those are always ASCII).
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    if printable / len(head) < 0.9:
        return True
    text = head.decode("utf-8", errors="ignore")
    if any(m in text for m in PUBLIC_KEY_MARKERS):
        return True
    # OpenSSH public key without a PEM header (sometimes stored in *.key)
    stripped = text.lstrip()
    return stripped.startswith(("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ",
                                "ecdsa-sha2-", "sk-ssh-ed25519 ", "sk-ecdsa-"))


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS014" in ctx.skipped_detectors:
        return []
    findings = []

    # Get ALL files (not just source — credential files may be in any location)
    all_files = ctx.get_files()

    for fp in all_files:
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Check filename patterns
        for patterns, title, severity, detail, fixture_sensitive in CREDENTIAL_FILE_PATTERNS:
            if not any(_match_glob(fp, pat) for pat in patterns):
                continue

            # Don't flag SSH keys in .ssh/ directories (user home)
            if (fp.suffix in (".pem", ".key") or fp.name.startswith("id_")) and ".ssh/" in str(fp):
                continue

            # Skip test vectors / fixtures / examples (not real credentials)
            if fixture_sensitive and _is_test_fixture_path(rel_path):
                continue

            # .pem/.key that are public certs/keys — not private keys
            if fp.suffix in (".pem", ".key") and _is_public_key_material(fp):
                continue

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

            # 3. PostgreSQL connection strings — dedicated FP filters.
            # Skip documentation files (examples, not real creds).
            if fp.suffix.lower() not in (".md", ".txt", ".rst"):
                for match in POSTGRES_CONN_RE.finditer(content):
                    pg_user = match.group("pg_user").strip()
                    pg_pass = match.group("pg_pass").strip()
                    # user:user@ / postgres:postgres@ / remnawave:remnawave@ — stub self-reference
                    if pg_pass.lower() == pg_user.lower():
                        continue
                    # ${ENV} / %(VAR) / {vault} / <password> — variable reference, no secret
                    if pg_pass.startswith(("$", "%", "{", "<")):
                        continue
                    # placeholder/example passwords (prefix match)
                    if PG_PLACEHOLDER_RE.match(pg_pass):
                        continue
                    # regex-pattern self-flagging: a password containing regex
                    # alternation/groups is a detector's own pattern, not a URL
                    if "|" in pg_pass or "(?:" in pg_pass:
                        continue
                    # URL in a commented-out line (example, not a live credential)
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    if content[line_start:match.start()].lstrip().startswith(("#", "//", "--")):
                        continue
                    # URL inside a docstring (example, not a credential)
                    if fp.suffix.lower() == ".py" and _in_docstring(content, match.start()):
                        continue
                    # URL inside a log/debug/print statement (diagnostic, not a live credential)
                    line_start = content.rfind("\n", 0, match.start()) + 1
                    line_end = content.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(content)
                    line_text = content[line_start:line_end]
                    if re.search(r'\b(?:logger|logging|log|print|debug|sys\.stdout|app\.logger)\b', line_text, re.I):
                        continue
                    lineno = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity="HIGH",
                        title="PostgreSQL connection string with embedded password",
                        detail="Database URL contains password in plaintext. Use environment variable.",
                        fix_suggestion="Remove hardcoded credential. Use environment variables "
                                       "or secrets manager. Rotate exposed secrets.",
                        references=["Redteam Kit", "2025 Playbooks - Credential Stuffing"]
                    ))

    return findings
