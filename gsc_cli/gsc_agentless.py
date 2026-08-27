#!/usr/bin/env python3
"""
GSC Agentless Scanner — SSH-based host security assessment.
Adapted from SHOK Monitor (kiurakku/shok-monitor, MIT).

Runs a single bash script over SSH, parses output locally.
No agents installed on remote servers.

Usage: python3 gsc_agentless.py <host> [--user root] [--key ~/.ssh/id_ed25519]
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime

# ── Lynis-style SSH hardening scan (one script, one SSH round-trip) ──
HARDENING_SCRIPT = r"""LANG=C
echo "@@SSHD_ROOT@@ $(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"
echo "@@SSHD_PASS@@ $(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
echo "@@SSHD_EMPTY@@ $(sshd -T 2>/dev/null | awk '/^permitemptypasswords/{print $2}')"
echo "@@SSHD_MAXAUTH@@ $(sshd -T 2>/dev/null | awk '/^maxauthtries/{print $2}')"
echo "@@UPD_ALL@@ $( (timeout 12 apt-get -s upgrade 2>/dev/null | grep -c '^Inst') ; (timeout 12 dnf -q check-update 2>/dev/null | grep -Ec '^[a-zA-Z0-9]') ; echo 0 | sort -rn | head -1)"
echo "@@UPD_SEC@@ $( (timeout 12 apt list --upgradable 2>/dev/null | grep -ic security) ; echo 0 | sort -rn | head -1)"
echo "@@REBOOT@@ $([ -f /var/run/reboot-required ] && echo yes || echo no)"
echo "@@PUB_PORTS@@ $(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '^(0\\.0\\.0\\.0|\\*|\\[::\\]):' | wc -l)"
echo "@@WW_FILES@@ $(timeout 8 find /etc /usr/local /home /srv /opt -xdev -type f -perm -0002 2>/dev/null | wc -l)"
echo "@@SUID@@ $(timeout 8 find /usr/bin /usr/sbin /bin /sbin /usr/local -perm -4000 -type f 2>/dev/null | wc -l)"
echo "@@EMPTY_PASS@@ $(awk -F: '($2==""){c++} END{print c+0}' /etc/shadow 2>/dev/null)"
echo "@@UID0@@ $(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | grep -vc '^root$')"
echo "@@FAIL2BAN@@ $(systemctl is-active fail2ban 2>/dev/null || echo inactive)"
echo "@@FW@@ $(ufw status 2>/dev/null | head -1 | grep -qi active && echo active || (systemctl is-active firewalld 2>/dev/null | grep -q '^active' && echo active || echo inactive))"
echo "@@PUB_DB@@ $(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oE '0\\.0\\.0\\.0:(5432|3306|6379|27017|9200|5984|8123|9042)' | wc -l)"
echo "@@OSREL@@ $(. /etc/os-release 2>/dev/null; echo "$ID $VERSION_ID")"
echo "@@END@@"
"""

# ── Threat intel: auth.log brute-force analysis ──
THREAT_SCRIPT = r"""LANG=C
( timeout 15 journalctl _COMM=sshd --since "48 hours ago" --no-pager 2>/dev/null; cat /var/log/auth.log /var/log/secure 2>/dev/null ) | awk '
/Failed password|authentication failure|Invalid user/ { if (match($0, /from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) { ip=substr($0,RSTART+5,RLENGTH-5); fip[ip]++; tot++ } }
/Invalid user/ { if (match($0, /Invalid user [A-Za-z0-9._-]+/)) { u=substr($0,RSTART+13,RLENGTH-13); usr[u]++ } }
/Accepted / { if (match($0, /from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) { a=substr($0,RSTART+5,RLENGTH-5); acc[a]++ } }
END {
  print "@@FAILED@@"; for (i in fip) print fip[i], i;
  print "@@USERS@@"; for (u in usr) print usr[u], u;
  print "@@ACCEPTED@@"; for (a in acc) print acc[a], a;
  print "@@TOTAL@@"; print tot+0;
  print "@@END@@";
}'"""


def ssh_exec(host: str, script: str, user: str = "root", key: str = None, timeout: int = 45) -> str:
    """Execute script on remote host via SSH."""
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if key:
        cmd += ["-i", key]
    cmd += [f"{user}@{host}", script]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout


def parse_sections(output: str) -> dict:
    """Parse @@SECTION@@ markers from SSH output."""
    sections = {}
    current = None
    for line in output.split('\n'):
        line = line.strip()
        m = re.match(r'^@@(\w+)@@$', line)
        if m:
            current = m.group(1)
            sections[current] = []
        elif current and line:
            sections[current].append(line)
    return sections


def scan_hardening(host: str, user: str = "root", key: str = None) -> dict:
    """Run SSH hardening scan."""
    output = ssh_exec(host, HARDENING_SCRIPT, user, key, timeout=45)
    if output.startswith("ERROR"):
        return {"error": output}
    
    d = parse_sections(output)
    
    findings = []
    
    # SSH hardening checks
    sshd_root = (d.get('SSHD_ROOT', ['unknown'])[0] or '').lower()
    if sshd_root in ('yes', 'without-password'):
        findings.append({
            "id": "ssh-root-login",
            "severity": "CRITICAL",
            "title": "Root login over SSH is allowed",
            "finding": f"PermitRootLogin={sshd_root}",
            "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        })
    
    sshd_pass = (d.get('SSHD_PASS', ['unknown'])[0] or '').lower()
    if sshd_pass == 'yes':
        findings.append({
            "id": "ssh-password-auth",
            "severity": "HIGH",
            "title": "Password authentication enabled for SSH",
            "finding": "PasswordAuthentication=yes",
            "remediation": "Set 'PasswordAuthentication no' — use SSH keys only"
        })
    
    sshd_empty = (d.get('SSHD_EMPTY', ['unknown'])[0] or '').lower()
    if sshd_empty == 'yes':
        findings.append({
            "id": "ssh-empty-passwords",
            "severity": "CRITICAL",
            "title": "Empty passwords permitted over SSH",
            "finding": "PermitEmptyPasswords=yes",
            "remediation": "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
        })
    
    # Security updates
    try:
        upd_sec = int(d.get('UPD_SEC', ['0'])[0])
        upd_all = int(d.get('UPD_ALL', ['0'])[0])
    except ValueError:
        upd_sec, upd_all = 0, 0
    
    if upd_sec > 0:
        findings.append({
            "id": "sec-updates",
            "severity": "HIGH",
            "title": "Security updates pending",
            "finding": f"{upd_sec} security updates ({upd_all} total)",
            "remediation": "apt update && apt upgrade — unpatched CVEs present"
        })
    
    # Reboot required
    if (d.get('REBOOT', ['no'])[0] or '').lower() == 'yes':
        findings.append({
            "id": "reboot-required",
            "severity": "MEDIUM",
            "title": "Reboot required after kernel update",
            "finding": "/var/run/reboot-required exists",
            "remediation": "Schedule reboot during maintenance window"
        })
    
    # World-writable files
    try:
        ww = int(d.get('WW_FILES', ['0'])[0])
    except ValueError:
        ww = 0
    if ww > 0:
        findings.append({
            "id": "world-writable",
            "severity": "HIGH",
            "title": "World-writable files found",
            "finding": f"{ww} files with permissions 0o002",
            "remediation": "Review and fix: find /etc -perm -0002 -type f"
        })
    
    # SUID binaries
    try:
        suid = int(d.get('SUID', ['0'])[0])
    except ValueError:
        suid = 0
    
    # Empty passwords
    try:
        empty = int(d.get('EMPTY_PASS', ['0'])[0])
    except ValueError:
        empty = 0
    if empty > 0:
        findings.append({
            "id": "empty-passwords",
            "severity": "CRITICAL",
            "title": "Accounts with empty passwords",
            "finding": f"{empty} accounts in /etc/shadow with no password",
            "remediation": "Lock accounts: passwd -l <username>"
        })
    
    # Extra UID-0 accounts
    try:
        uid0 = int(d.get('UID0', ['0'])[0])
    except ValueError:
        uid0 = 0
    if uid0 > 0:
        findings.append({
            "id": "extra-root",
            "severity": "HIGH",
            "title": "Extra UID-0 accounts detected",
            "finding": f"{uid0} accounts with UID=0 besides root",
            "remediation": "Audit: awk -F: '($3==0){print $1}' /etc/passwd"
        })
    
    # fail2ban
    f2b = (d.get('FAIL2BAN', ['inactive'])[0] or '').lower()
    if f2b != 'active':
        findings.append({
            "id": "no-fail2ban",
            "severity": "MEDIUM",
            "title": "fail2ban not active",
            "finding": f"Status: {f2b}",
            "remediation": "Install and enable: apt install fail2ban && systemctl enable --now fail2ban"
        })
    
    # Firewall
    fw = (d.get('FW', ['inactive'])[0] or '').lower()
    if fw == 'inactive':
        findings.append({
            "id": "no-firewall",
            "severity": "HIGH",
            "title": "No active firewall detected",
            "finding": "Neither ufw nor firewalld is active",
            "remediation": "Enable firewall: ufw enable (or systemctl enable --now firewalld)"
        })
    
    # Exposed DB ports
    try:
        pub_db = int(d.get('PUB_DB', ['0'])[0])
    except ValueError:
        pub_db = 0
    if pub_db > 0:
        findings.append({
            "id": "exposed-db",
            "severity": "CRITICAL",
            "title": "Database ports exposed to internet",
            "finding": f"{pub_db} database ports bound to 0.0.0.0",
            "remediation": "Bind databases to 127.0.0.1 or use firewall rules"
        })
    
    # Host info
    host_info = {
        "os": (d.get('OSREL', ['unknown'])[0] or 'unknown').strip(),
        "ssh_root_login": sshd_root,
        "ssh_password_auth": sshd_pass,
        "fail2ban": f2b,
        "firewall": fw,
        "pending_updates": f"{upd_sec} security / {upd_all} total",
        "world_writable_files": ww,
        "suid_binaries": suid,
        "exposed_db_ports": pub_db,
    }
    
    return {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "host_info": host_info,
        "findings": findings,
        "total": len(findings),
        "critical": len([f for f in findings if f['severity'] == 'CRITICAL']),
        "high": len([f for f in findings if f['severity'] == 'HIGH']),
        "medium": len([f for f in findings if f['severity'] == 'MEDIUM']),
    }


def scan_threats(host: str, user: str = "root", key: str = None) -> dict:
    """Analyze SSH brute-force attempts from auth.log."""
    output = ssh_exec(host, THREAT_SCRIPT, user, key, timeout=45)
    if output.startswith("ERROR"):
        return {"error": output}
    
    d = parse_sections(output)
    
    attackers = []
    for line in d.get('FAILED', []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            attackers.append({"ip": parts[1], "count": int(parts[0])})
    attackers.sort(key=lambda x: x['count'], reverse=True)
    
    users = []
    for line in d.get('USERS', []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            users.append({"username": parts[1], "count": int(parts[0])})
    users.sort(key=lambda x: x['count'], reverse=True)
    
    accepted = []
    for line in d.get('ACCEPTED', []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            accepted.append({"ip": parts[1], "count": int(parts[0])})
    
    total = int((d.get('TOTAL', ['0'])[0] or '0'))
    
    return {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "total_failures": total,
        "unique_ips": len(attackers),
        "top_attackers": attackers[:10],
        "targeted_users": users[:10],
        "accepted_logins": accepted[:5],
        "alert": total > 300  # Threshold from SHOK
    }


def main():
    parser = argparse.ArgumentParser(description="GSC Agentless Scanner — SSH host security assessment")
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("--user", "-u", default="root", help="SSH user (default: root)")
    parser.add_argument("--key", "-i", help="SSH private key path")
    parser.add_argument("--mode", choices=["hardening", "threats", "all"], default="all")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    
    results = {}
    
    if args.mode in ("hardening", "all"):
        print(f"🔍 Scanning {args.host} (hardening)...", file=sys.stderr)
        results["hardening"] = scan_hardening(args.host, args.user, args.key)
    
    if args.mode in ("threats", "all"):
        print(f"🎯 Analyzing threats on {args.host}...", file=sys.stderr)
        results["threats"] = scan_threats(args.host, args.user, args.key)
    
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for mode, data in results.items():
            if "error" in data:
                print(f"\n❌ {mode}: {data['error']}")
                continue
            
            print(f"\n{'='*60}")
            print(f"📊 {mode.upper()} — {data.get('host', args.host)}")
            print(f"{'='*60}")
            
            if mode == "hardening":
                hi = data.get("host_info", {})
                print(f"  OS: {hi.get('os', '?')}")
                print(f"  SSH Root: {hi.get('ssh_root_login', '?')} | PassAuth: {hi.get('ssh_password_auth', '?')}")
                print(f"  fail2ban: {hi.get('fail2ban', '?')} | Firewall: {hi.get('firewall', '?')}")
                print(f"  Updates: {hi.get('pending_updates', '?')}")
                print(f"  World-writable: {hi.get('world_writable_files', 0)} | SUID: {hi.get('suid_binaries', 0)}")
                
                print(f"\n  Findings: {data.get('total', 0)} ({data.get('critical', 0)} CRIT, {data.get('high', 0)} HIGH, {data.get('medium', 0)} MED)")
                for f in data.get("findings", []):
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f['severity'], '⚪')
                    print(f"  {icon} [{f['severity']}] {f['title']}")
                    print(f"     → {f['remediation'][:80]}")
            
            elif mode == "threats":
                print(f"  Failed logins (48h): {data.get('total_failures', 0)}")
                print(f"  Unique attacker IPs: {data.get('unique_ips', 0)}")
                if data.get('alert'):
                    print("  ⚠️  BRUTE-FORCE ALERT: threshold exceeded!")
                
                if data.get("top_attackers"):
                    print("\n  Top attackers:")
                    for a in data["top_attackers"][:5]:
                        print(f"    {a['ip']}: {a['count']} attempts")
                
                if data.get("targeted_users"):
                    print("\n  Targeted users:")
                    for u in data["targeted_users"][:5]:
                        print(f"    {u['username']}: {u['count']} attempts")
        
        print()


if __name__ == "__main__":
    main()
