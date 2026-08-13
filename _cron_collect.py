#!/usr/bin/env python3
"""Cron-runner: NVD + GitHub collector for GSC."""
import sys, os, json, re, hashlib, sqlite3, time
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
VAULT_PATH = Path.home() / "obsidian-vault" / "hermes" / "gsc-collector"
STATE_PATH = Path.home() / ".hermes" / "state" / "gsc_collector_state.json"
HEADERS = {"User-Agent": "GSC-Collector/1.0", "Accept": "application/json"}

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

CVE_PATTERN_MAP = [
    (re.compile(r"hard[\s-]?coded\s+(password|secret|key|token|credential)", re.I),
     "Hardcoded credential", "hardcoded-secret", "GS001",
     r"(?:password|secret|key|token)\s*=\s*[\"']"),
    (re.compile(r"SQL\s+injection", re.I),
     "SQL injection", "sql-injection", "GS005",
     r"f[\"']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b"),
    (re.compile(r"(?:command|OS\s+command)\s+injection", re.I),
     "Command injection", "command-injection", "GS004",
     r"(?:os\.system|subprocess\.\w+\s*\(\s*[^)]*shell\s*=\s*True)"),
    (re.compile(r"(?:path|directory)\s+traversal", re.I),
     "Path traversal", "path-traversal", "",
     r"(?:\.\./|\.\.\\)"),
    (re.compile(r"(?:deserialization|deseriali[sz]e|pickle|unserialize)", re.I),
     "Insecure deserialization", "deserialization", "GS004",
     r"(?:pickle\.loads?|yaml\.load\s*\()"),
    (re.compile(r"cross[\s-]?site\s+scripting|XSS", re.I),
     "Cross-site scripting (XSS)", "xss", "",
     r"(?:innerHTML|document\.write\s*\()"),
    (re.compile(r"SSRF|server[\s-]?side\s+request\s+forgery", re.I),
     "Server-side request forgery (SSRF)", "ssrf", "",
     r"(?:requests\.\w+\s*\(\s*(?:url|f[\"']))"),
    (re.compile(r"authentication\s+bypass|auth\s+bypass", re.I),
     "Authentication bypass", "auth-bypass", "GS011",
     r"(?:verify\s*=\s*False|alg\s*:\s*[\"']none[\"'])"),
    (re.compile(r"buffer\s+overflow|buffer\s+overrun", re.I),
     "Buffer overflow", "buffer-overflow", "",
     r"(?:strcpy|strcat|sprintf|gets\s*\()"),
    (re.compile(r"use[\s-]?after[\s-]?free|UAF", re.I),
     "Use-after-free", "use-after-free", "", ""),
    (re.compile(r"(?:privilege|privesc)\s+escalation", re.I),
     "Privilege escalation", "privilege-escalation", "GS014",
     r"(?:sudo|NOPASSWD|chmod\+s)"),
    (re.compile(r"(?:information|data)\s+(?:disclosure|exposure|leak)", re.I),
     "Information disclosure", "info-disclosure", "GS014",
     r"(?:SECRET_KEY|password|token)\s*=\s*[\"']"),
]

def save_pattern_and_finding(db, title, category, severity, pattern_str, language, detector, source, source_url, snippet):
    """Insert into patterns + findings tables (schema-aware)."""
    pattern_hash = hashlib.md5(pattern_str.encode()).hexdigest()[:16]
    existing = db.execute("SELECT id FROM patterns WHERE pattern_hash=? LIMIT 1", (pattern_hash,)).fetchone()

    pattern_id = None
    if not existing:
        noise = "precise" if severity in ("CRITICAL", "HIGH") else "normal"
        try:
            db.execute(
                """INSERT INTO patterns (project, category, echelon, title, pattern_type, search_pattern, noise_tier, pattern_hash, language)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("gsc-collector", severity, 1, title[:200], "regex", pattern_str, noise, pattern_hash, language),
            )
        except Exception as e:
            print(f"  pattern insert fail: {e}")
            return 0, 0
        pattern_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    else:
        pattern_id = existing[0]

    try:
        from gsc_db import compute_finding_key
        db.execute(
            """INSERT INTO findings (project, echelon, category, title, file_path, detail, pattern_id, noise_tier, finding_key)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("gsc-collector", 1, severity, title[:200], source_url, (snippet or "")[:500], pattern_id, "normal",
             compute_finding_key(None, source_url, (snippet or "")[:500])),
        )
        return 1, 1  # 1 pattern, 1 finding
    except Exception as e:
        print(f"  finding insert fail: {e}")
        return 0, 0


def collect_nvd(db):
    patterns_added = 0
    findings_added = 0

    since = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%S.000")
    until = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {"pubStartDate": since, "pubEndDate": until, "resultsPerPage": 50}

    print(f"\nNVD: {since[:10]} – {until[:10]}...")
    resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=HEADERS, params=params, timeout=30)
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)
    print(f"NVD: {total} CVEs in period, fetched {len(vulns)}")

    matched = []
    for vuln_data in vulns:
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")
        desc_en = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_data = (metrics.get("cvssMetricV31", [{}])[0] or metrics.get("cvssMetricV30", [{}])[0] or {})
        base_score = cvss_data.get("cvssData", {}).get("baseScore", 0)
        severity = "CRITICAL" if base_score >= 9.0 else "HIGH" if base_score >= 7.0 else "MEDIUM"

        for regex, title, category, detector, pattern_str in CVE_PATTERN_MAP:
            if regex.search(desc_en):
                p, f = save_pattern_and_finding(
                    db, title=f"{cve_id}: {title}", category=category,
                    severity=severity, pattern_str=pattern_str, language="python",
                    detector=detector, source="nvd",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    snippet=desc_en[:300],
                )
                patterns_added += p
                findings_added += f
                matched.append(cve_id)
                if p > 0:
                    print(f"  {cve_id}: {title} ({severity})")
                break
        time.sleep(0.1)

    print(f"NVD: {patterns_added} new patterns, {findings_added} new findings from {len(matched)} matched CVEs")
    db.commit()
    return patterns_added, findings_added


def collect_github(db):
    patterns_added = 0
    findings_added = 0

    queries = [
        {"q": '"SECRET_KEY" "=" NOT os.getenv NOT environ language:python', "detector": "GS001", "severity": "CRITICAL", "category": "hardcoded-secret"},
        {"q": '"jwt.decode" "verify=False" language:python', "detector": "GS011", "severity": "CRITICAL", "category": "jwt"},
        {"q": '"os.system" "f" language:python stars:<10', "detector": "GS004", "severity": "HIGH", "category": "command-injection"},
        {"q": '"f\\"SELECT" "WHERE" language:python stars:<20', "detector": "GS005", "severity": "CRITICAL", "category": "sql-injection"},
        {"q": '":\\"\\"" "postgres" language:python stars:<10', "detector": "GS014", "severity": "HIGH", "category": "credential-exposure"},
    ]

    print(f"\nGitHub: {len(queries)} queries...")

    for i, qobj in enumerate(queries):
        q = qobj["q"]
        print(f"  [{i+1}/{len(queries)}] {q[:60]}...")

        gh_headers = dict(HEADERS)
        gh_headers["Accept"] = "application/vnd.github.v3+json"
        if GITHUB_TOKEN:
            gh_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        try:
            resp = requests.get(
                "https://api.github.com/search/code",
                headers=gh_headers,
                params={"q": q, "per_page": 5},
                timeout=15,
            )

            if resp.status_code == 403:
                print(f"    Rate limited! Skipping remaining GitHub queries.")
                break
            if resp.status_code != 200:
                print(f"    HTTP {resp.status_code}")
                continue

            data = resp.json()
            items = data.get("items", [])
            print(f"    {data.get('total_count',0)} results total, processing {len(items)}")

            for item in items:
                repo = item["repository"]["full_name"]
                path = item.get("path", "")
                html_url = item.get("html_url", "")

                p, f = save_pattern_and_finding(
                    db, title=f"{repo}: {path}", category=qobj["category"],
                    severity=qobj["severity"], pattern_str=q,
                    language="python", detector=qobj["detector"],
                    source="github", source_url=html_url,
                    snippet=f"Repository: {repo}\nFile: {path}",
                )
                patterns_added += p
                findings_added += f
                if p > 0:
                    print(f"    + {repo}/{path}")

            time.sleep(2)  # rate limit

        except Exception as e:
            print(f"    Error: {e}")

    print(f"GitHub: {patterns_added} new patterns, {findings_added} new findings")
    db.commit()
    return patterns_added, findings_added


def export_obsidian(db):
    VAULT_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d")

    findings = db.execute(
        "SELECT * FROM findings WHERE project='gsc-collector' AND date(created_at)=date('now') ORDER BY category DESC, created_at DESC LIMIT 100"
    ).fetchall()

    if not findings:
        print("Obsidian: no findings today")
        return

    filepath = VAULT_PATH / f"collection-{timestamp}.md"
    with open(filepath, "w") as f:
        f.write(f"---\ntitle: \"GSC Collector — {timestamp}\"\ncollected: {datetime.now().isoformat()}\ncount: {len(findings)}\ntype: gsc-collector\n---\n\n")
        f.write(f"# GSC Collector — {timestamp}\n\n**{len(findings)}** findings collected.\n\n")
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for row in findings:
            sev = row[4] if len(row) > 4 else "MEDIUM"  # row[4]=category (=severity)
            if sev in by_sev:
                by_sev[sev].append(row)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = by_sev.get(sev, [])
            if items:
                f.write(f"## {sev} ({len(items)})\n\n")
                for row in items[:10]:
                    f.write(f"- **{row[5][:100]}**\n")  # row[5]=title
                    f.write(f"  - Source: {row[2] if len(row)>2 else 'gsc-collector'}  \n")
                    f.write(f"  - URL: {row[6] if len(row)>6 else ''}  \n\n")
    print(f"Obsidian: {filepath} ({len(findings)} findings)")


def main():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")

    total_p = 0
    total_f = 0

    # NVD
    p, f = collect_nvd(db)
    total_p += p
    total_f += f

    # GitHub
    p, f = collect_github(db)
    total_p += p
    total_f += f

    db.commit()

    # Obsidian
    export_obsidian(db)

    db.close()
    print(f"\n{'='*50}")
    print(f"  TOTAL: {total_p} patterns, {total_f} findings")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
