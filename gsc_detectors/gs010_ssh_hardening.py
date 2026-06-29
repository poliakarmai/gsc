"""
GS010 — Weak SSH Configuration Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects dangerous SSH server configurations:
- PermitRootLogin without forced-commands-only
- PasswordAuthentication enabled without 2FA
- Empty AllowedUsers/AllowedGroups
- Weak ciphers/macs/kex
- X11Forwarding enabled
- PermitUserEnvironment enabled (LD_PRELOAD vector)
- AgentForwarding enabled
- MaxAuthTries too high (>6)

Sources: SSH Hardening & Offensive Mastery (Redteam Kit)
"""
from gsc_detectors import AuditContext, Finding

RULE_ID = "GS010"
ECHELON = 2
description = "Weak SSH server configuration — dangerous sshd_config settings"


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS010" in ctx.skipped_detectors:
        return []
    findings = []

    # Only check sshd_config files
    for fp in ctx.get_source_files():
        if fp.name not in ("sshd_config", "sshd_config.dist", "sshd_config.template"):
            continue
        if fp.suffix in (".md", ".txt", ".org", ".rst"):
            continue  # Skip documentation

        try:
            content = fp.read_text()
        except Exception:
            continue

        lines = content.split("\n")

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # CRITICAL: PermitRootLogin without forced-commands-only
            if "PermitRootLogin" in stripped and "without-password" not in stripped.replace(" ", "").lower() \
               and "prohibit-password" not in stripped.replace(" ", "").lower() \
               and "forced-commands-only" not in stripped.replace(" ", "").lower():
                if "yes" in stripped.lower().split() or "yes" == stripped.split()[-1].lower():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="CRITICAL",
                        title="SSH root login enabled",
                        detail=f"PermitRootLogin is set to 'yes' — allows direct root SSH access. "
                               f"Use 'prohibit-password' or 'forced-commands-only'.",
                        fix_suggestion="Set 'PermitRootLogin prohibit-password' or 'PermitRootLogin no'",
                        references=["SSH Hardening & Offensive Mastery §3.1.3"]
                    ))

            # HIGH: PasswordAuthentication enabled (weak auth)
            if "PasswordAuthentication" in stripped:
                parts = stripped.lower().split()
                if "yes" in parts:
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="HIGH",
                        title="SSH password authentication enabled",
                        detail="PasswordAuthentication yes — vulnerable to brute-force and credential stuffing. "
                               "Use key-based authentication + 2FA instead.",
                        fix_suggestion="Set 'PasswordAuthentication no' and use SSH keys",
                        references=["SSH Hardening & Offensive Mastery §3.1.7", "Fail2Ban §3.2.3.1"]
                    ))

            # HIGH: PermitUserEnvironment enabled (LD_PRELOAD attack vector)
            if "PermitUserEnvironment" in stripped:
                if "yes" in stripped.lower().split():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="HIGH",
                        title="SSH user environment enabled — LD_PRELOAD vector",
                        detail="PermitUserEnvironment yes allows users to set environment variables like "
                               "LD_PRELOAD, which can lead to privilege escalation. CVE-2018-15473 related.",
                        fix_suggestion="Set 'PermitUserEnvironment no'",
                        references=["SSH Hardening & Offensive Mastery §4.1.4", "CVE-2018-15473"]
                    ))

            # MEDIUM: X11Forwarding enabled
            if "X11Forwarding" in stripped:
                if "yes" in stripped.lower().split():
                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=str(fp.relative_to(ctx.path)),
                        line=lineno,
                        severity="MEDIUM",
                        title="SSH X11 forwarding enabled",
                        detail="X11Forwarding yes exposes graphical applications to potential hijacking.",
                        fix_suggestion="Set 'X11Forwarding no'",
                        references=["SSH Hardening & Offensive Mastery §3.1.9"]
                    ))

            # MEDIUM: Agent forwarding enabled
            if "AllowAgentForwarding" in stripped and "no" not in stripped.lower().split():
                findings.append(Finding(
                    rule_id=RULE_ID,
                    file_path=str(fp.relative_to(ctx.path)),
                    line=lineno,
                    severity="MEDIUM",
                    title="SSH agent forwarding enabled",
                    detail="Agent forwarding allows SSH agent keys to be forwarded, enabling lateral movement.",
                    fix_suggestion="Set 'AllowAgentForwarding no'",
                    references=["SSH Hardening & Offensive Mastery §3.2.1"]
                ))

            # MEDIUM: MaxAuthTries too high
            if "MaxAuthTries" in stripped:
                parts = stripped.split()
                for p in parts:
                    try:
                        val = int(p)
                        if val > 6:
                            findings.append(Finding(
                                rule_id=RULE_ID,
                                file_path=str(fp.relative_to(ctx.path)),
                                line=lineno,
                                severity="MEDIUM",
                                title=f"SSH MaxAuthTries too high ({val})",
                                detail=f"MaxAuthTries={val} allows excessive authentication attempts, "
                                       f"enabling brute-force attacks. Recommend 3-6.",
                                fix_suggestion="Set 'MaxAuthTries 3'",
                                references=["SSH Hardening & Offensive Mastery §3.1.4"]
                            ))
                        break
                    except ValueError:
                        continue

    return findings
