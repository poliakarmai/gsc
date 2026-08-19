#!/usr/bin/env python3
"""Cron-runner: NVD collector using date range (last 14 days)."""
import sys, os, json, re, hashlib, sqlite3, time
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
VAULT_PATH = Path.home() / "obsidian-vault" / "hermes" / "gsc-collector"
STATE_PATH = Path.home() / ".hermes" / "state" / "gsc_collector_state.json"
HEADERS = {"User-Agent": "GSC-Collector/1.0", "Accept": "application/json"}

CVE_PATTERN_MAP = [
    (re.compile(r"hard[\s-]?coded\s+(password|secret|key|token|credential)", re.I),
     "Hardcoded credential", "CRITICAL", "hardcoded-secret", "GS001",
     r"(?:password|secret|key|token)\s*=\s*[\"']"),
    (re.compile(r"SQL\s+injection", re.I),
     "SQL injection", "CRITICAL", "sql-injection", "GS005",
     r"f[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b"),
    (re.compile(r"(?:command|OS\s+command)\s+injection", re.I),
     "Command injection", "CRITICAL", "command-injection", "GS004",
     r"(?:os\.system|subprocess\.\w+\s*\(\s*[^)]*shell\s*=\s*True)"),
    (re.compile(r"(?:deserialization|deseriali[sz]e|pickle|unserialize)", re.I),
     "Insecure deserialization", "CRITICAL", "deserialization", "GS004",
     r"(?:pickle\.loads?|yaml\.load\s*\()"),
    (re.compile(r"authentication\s+bypass|auth\s+bypass", re.I),
     "Authentication bypass", "CRITICAL", "auth-bypass", "GS011",
     r"(?:verify\s*=\s*False|alg\s*:\s*[\"']none[\"'])"),
    (re.compile(r"(?:privilege|privesc)\s+escalation", re.I),
     "Privilege escalation", "CRITICAL", "privilege-escalation", "GS014",
     r"(?:sudo|NOPASSWD|chmod\+s)"),
    (re.compile(r"(?:information|data)\s+(?:disclosure|exposure|leak)", re.I),
     "Information disclosure", "MEDIUM", "info-disclosure", "GS014",
     r"(?:SECRET_KEY|password|token)\s*=\s*[\"']"),
]

def main():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    patterns_added = 0
    findings_added = 0

    # Use date range for truly recent CVEs
    since = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%S.000")
    until = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {"pubStartDate": since, "pubEndDate": until, "resultsPerPage": 50}
    
    print(f"NVD: querying {since[:10]} to {until[:10]}...")
    resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=HEADERS, params=params, timeout=30)
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)
    print(f"NVD: {total} CVEs in last 14d, fetched {len(vulns)}")

    for vuln_data in vulns:
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")
        desc_en = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_data = (metrics.get("cvssMetricV31", [{}])[0] or metrics.get("cvssMetricV30", [{}])[0] or {})
        base_score = cvss_data.get("cvssData", {}).get("baseScore", 0)
        severity = "CRITICAL" if base_score >= 9.0 else "HIGH" if base_score >= 7.0 else "MEDIUM"

        for regex, title, cat_sev, category, detector, pattern in CVE_PATTERN_MAP:
            if regex.search(desc_en):
                if not pattern:
                    continue
                pattern_hash = hashlib.md5(pattern.encode()).hexdigest()[:16]
                existing = db.execute("SELECT id FROM patterns WHERE pattern_hash=? LIMIT 1", (pattern_hash,)).fetchone()

                if not existing:
                    noise = "precise" if severity in ("CRITICAL", "HIGH") else "normal"
                    try:
                        db.execute(
                            "INSERT INTO patterns (title, search_pattern, pattern_type, category, language, active, noise_tier, pattern_hash, project, echelon) VALUES (?,?,?,?,?,1,?,?,'*',1)",
                            (f"{cve_id}: {title[:80]}", pattern, severity, category, "python", noise, pattern_hash, 1),
                        )
                        patterns_added += 1
                    except Exception as e:
                        print(f"  pattern insert fail: {e}")
                        continue
                    pid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                else:
                    pid = existing[0]

                try:
                    from gsc_core.gsc_db import compute_finding_key
                    db.execute(
                        "INSERT INTO findings (project, rule_id, category, title, file_path, detail, noise_tier, pattern_id, finding_key) VALUES (?,?,?,?,?,?,?,?,?)",
                        ("gsc-collector", detector or "COLLECTED", severity, f"{cve_id}: {title}", f"https://nvd.nist.gov/vuln/detail/{cve_id}", desc_en[:500], "normal", pid,
                         compute_finding_key(detector or "COLLECTED", f"https://nvd.nist.gov/vuln/detail/{cve_id}", desc_en[:500])),
                    )
                    findings_added += 1
                except Exception:
                    pass
                db.commit()
                break  # one pattern per CVE is enough

    print(f"NVD results: {patterns_added} patterns, {findings_added} findings")

    # Obsidian export
    VAULT_PATH.mkdir(parents=True, exist_ok=True)
    findings = db.execute(
        "SELECT * FROM findings WHERE project='gsc-collector' AND date(created_at)=date('now') ORDER BY category DESC, created_at DESC LIMIT 100"
    ).fetchall()
    if findings:
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filepath = VAULT_PATH / f"collection-{timestamp}.md"
        with open(filepath, "w") as f:
            f.write(f"---\ntitle: \"GSC Collector — {timestamp}\"\ncollected: {datetime.now().isoformat()}\ncount: {len(findings)}\ntype: gsc-collector\n---\n\n")
            f.write(f"# GSC Collector — {timestamp}\n\n**{len(findings)}** findings collected.\n\n")
            by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for row in findings:
                sev = row[2] if len(row) > 2 else "MEDIUM"
                if sev in by_sev:
                    by_sev[sev].append(row)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                items = by_sev.get(sev, [])
                if items:
                    f.write(f"## {sev} ({len(items)})\n\n")
                    for row in items[:10]:
                        f.write(f"- **{row[4][:100]}**\n")
                        f.write(f"  - Source: {row[9]}  \n")
                        f.write(f"  - URL: {row[10]}  \n\n")
        print(f"Obsidian: {filepath} ({len(findings)} findings)")
    else:
        print("Obsidian: no findings today")

    db.close()

if __name__ == "__main__":
    main()
