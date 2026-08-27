#!/usr/bin/env python3
"""
GSC Lightweight Collector — collects vulnerability patterns for self-learning.

Uses requests (no Scrapy overhead) for API-based sources:
  - NVD CVE API (known exploited vulnerabilities)
  - GitHub code search (via REST API)
  - HackerOne hacktivity (via public API)

Feeds directly into GSC DB + Obsidian vault.

Usage:
    python3 gsc_collect_light.py nvd      # CVE patterns
    python3 gsc_collect_light.py github   # GitHub code search
    python3 gsc_collect_light.py all      # everything
"""
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
VAULT_PATH = Path.home() / "obsidian-vault" / "hermes" / "gsc-collector"
STATE_PATH = Path.home() / ".hermes" / "state" / "gsc_collector_state.json"

HEADERS = {
    "User-Agent": "GSC-Collector/1.0 (+https://github.com/poliakarmai/gsc)",
    "Accept": "application/json",
}

# GitHub token for authenticated API access
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
if not _GITHUB_TOKEN:
    # Fallback for cron environments without the token exported:
    # 1) gh CLI auth (already authorized), 2) ~/.hermes/.env
    try:
        import subprocess as _sp
        _GITHUB_TOKEN = _sp.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        _GITHUB_TOKEN = ""
if not _GITHUB_TOKEN:
    try:
        _env_path = os.path.expanduser("~/.hermes/.env")
        with open(_env_path) as _f:
            for _line in _f:
                if _line.startswith("GITHUB_TOKEN="):
                    _GITHUB_TOKEN = _line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
    except Exception:
        _GITHUB_TOKEN = ""

# ── Pattern extraction from CVE descriptions ───────────────────────────────

CVE_PATTERN_MAP = [
    (re.compile(r"hard[\s-]?coded\s+(password|secret|key|token|credential)", re.I),
     "Hardcoded credential", "CRITICAL", "hardcoded-secret", "GS001",
     r'(?:password|secret|key|token)\s*=\s*["\']'),
    (re.compile(r"SQL\s+injection", re.I),
     "SQL injection", "CRITICAL", "sql-injection", "GS005",
     r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b'),
    (re.compile(r"(?:command|OS\s+command)\s+injection", re.I),
     "Command injection", "CRITICAL", "command-injection", "GS004",
     r'(?:os\.system|subprocess\.\w+\s*\(\s*[^)]*shell\s*=\s*True)'),
    (re.compile(r"(?:deserialization|deseriali[sz]e|pickle|unserialize)", re.I),
     "Insecure deserialization", "CRITICAL", "deserialization", "GS004",
     r'(?:pickle\.loads?|yaml\.load\s*\()'),
    (re.compile(r"authentication\s+bypass|auth\s+bypass", re.I),
     "Authentication bypass", "CRITICAL", "auth-bypass", "GS011",
     r'(?:verify\s*=\s*False|alg\s*:\s*["\']none["\'])'),
    (re.compile(r"(?:privilege|privesc)\s+escalation", re.I),
     "Privilege escalation", "CRITICAL", "privilege-escalation", "GS014",
     r'(?:sudo|NOPASSWD|chmod\+s)'),
    (re.compile(r"(?:information|data)\s+(?:disclosure|exposure|leak)", re.I),
     "Information disclosure", "MEDIUM", "info-disclosure", "GS014",
     r'(?:SECRET_KEY|password|token)\s*=\s*["\']'),
]


class GscCollector:
    """Lightweight vulnerability pattern collector."""

    def __init__(self):
        self.db = sqlite3.connect(str(DB_PATH))
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.patterns_added = 0
        self.findings_added = 0
        self.state = self._load_state()

    # ── State management ────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
        return {"last_cve_run": None, "last_github_run": None, "processed_cves": []}

    def _save_state(self):
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(self.state, indent=2, default=str))

    # ── NVD CVE Collector ───────────────────────────────────────────────────

    def collect_nvd(self, limit: int = 50):
        """Collect recent CVEs from NVD. Fetches the most recently published."""
        print(f"\n📡 NVD CVE Collector — fetching {limit} recent CVEs...")

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        try:
            # Step 1: get total count
            resp = requests.get(url, headers=HEADERS, params={"resultsPerPage": 1}, timeout=30)
            if resp.status_code != 200:
                print(f"  ❌ NVD API returned {resp.status_code}")
                return
            total = resp.json().get("totalResults", 0)
            print(f"  Total CVEs in NVD: {total}")

            # Step 2: fetch most recent ones (API returns sorted by pub date ASC)
            start_idx = max(0, total - min(limit, 100))
            params = {
                "startIndex": start_idx,
                "resultsPerPage": min(limit, 100),
            }
            resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
            if resp.status_code != 200:
                print(f"  ❌ NVD API returned {resp.status_code}")
                return
            data = resp.json()
        except Exception as e:
            print(f"  ❌ NVD API error: {e}")
            return

        vulns = data.get("vulnerabilities", [])
        print(f"  Fetched {len(vulns)} recent CVEs (offset {start_idx})")

        for vuln_data in vulns:
            cve = vuln_data.get("cve", {})
            cve_id = cve.get("id", "")

            if cve_id in self.state["processed_cves"]:
                continue

            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            # Extract severity (check V31 first, fall back to V30)
            metrics = cve.get("metrics", {})
            cvss_data = (metrics.get("cvssMetricV31", [{}])[0]
                         or metrics.get("cvssMetricV30", [{}])[0])
            if not cvss_data:
                cvss_data = {}
            base_score = cvss_data.get("cvssData", {}).get("baseScore", 0)
            severity = (
                "CRITICAL" if base_score >= 9.0 else
                "HIGH" if base_score >= 7.0 else
                "MEDIUM"
            )

            # Save the CVE as an INFORMATIONAL reference (active=0), NOT as a
            # generic code-detection pattern. A CVE describes a bug in a SPECIFIC
            # product; it cannot be turned into a generic regex applicable to
            # arbitrary code. Generic patterns are already covered by the proper
            # GS0XX detectors (GS004 command injection, GS005 SQLi, GS001 creds…).
            # Previously this produced misleading titles like
            # "CVE-2026-56413: Command injection" that polluted scans and fell
            # through to GS000-LEGACY (benchmark 21.08.2026).
            self._save_pattern(
                title=f"{cve_id}: {desc_en[:150]}",
                category="cve-reference",
                severity=severity,
                pattern=f"nvd-reference/{cve_id}",
                language="python",
                detector="",
                source="nvd",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                snippet=desc_en[:300],
                active=False,
            )

            self.state["processed_cves"].append(cve_id)
            time.sleep(0.1)  # Rate limit

        # Keep only last 1000 CVEs
        self.state["processed_cves"] = self.state["processed_cves"][-1000:]
        self.state["last_cve_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()

        print(f"\n  ✅ {self.patterns_added} patterns added from {len(vulns)} CVEs")

    def _extract_cve_patterns(self, description: str, cve_id: str) -> list[dict]:
        """Extract security patterns from CVE description."""
        patterns = []
        for regex, title, severity, category, detector, pattern in CVE_PATTERN_MAP:
            if regex.search(description):
                patterns.append({
                    "title": title,
                    "category": category,
                    "severity": severity,
                    "detector": detector,
                    "pattern": pattern,
                    "language": "python",
                })
        return patterns

    # ── GitHub Code Search ──────────────────────────────────────────────────

    def collect_github(self, queries: list[dict] | None = None):
        """Collect vulnerability patterns from GitHub code search API."""
        if queries is None:
            queries = [
                {"q": '"SECRET_KEY" "=" NOT os.getenv NOT environ language:python', "detector": "GS001", "severity": "CRITICAL", "category": "hardcoded-secret"},
                {"q": '"jwt.decode" "verify=False" language:python', "detector": "GS011", "severity": "CRITICAL", "category": "jwt"},
                {'q': '"os.system" "f" language:python stars:<10', "detector": "GS004", "severity": "HIGH", "category": "command-injection"},
                {'q': '"f\"SELECT" "WHERE" language:python stars:<20', "detector": "GS005", "severity": "CRITICAL", "category": "sql-injection"},
                {'q': '":\\"\\" "postgres" language:python stars:<10', "detector": "GS014", "severity": "HIGH", "category": "credential-exposure"},
            ]

        print(f"\n📡 GitHub Code Search — {len(queries)} queries...")

        for i, query in enumerate(queries):
            q = query["q"]
            print(f"  [{i+1}/{len(queries)}] {q[:60]}...")

            try:
                url = "https://api.github.com/search/code"
                gh_headers = dict(HEADERS)
                gh_headers["Accept"] = "application/vnd.github.v3+json"
                if _GITHUB_TOKEN:
                    gh_headers["Authorization"] = f"Bearer {_GITHUB_TOKEN}"
                resp = requests.get(
                    url,
                    headers=gh_headers,
                    params={"q": q, "per_page": 5},
                    timeout=15,
                )

                if resp.status_code == 403:
                    print("    ⚠️ Rate limited — skipping remaining queries")
                    break
                if resp.status_code != 200:
                    print(f"    ⚠️ HTTP {resp.status_code}")
                    continue

                data = resp.json()
                items = data.get("items", [])
                print(f"    Found {data.get('total_count', 0)} results, processing {len(items)}")

                for item in items:
                    repo = item["repository"]["full_name"]
                    path = item.get("path", "")
                    html_url = item.get("html_url", "")

                    self._save_pattern(
                        title=f"{repo}: {path}",
                        category=query["category"],
                        severity=query["severity"],
                        pattern=q,
                        language="python",
                        detector=query["detector"],
                        source="github",
                        source_url=html_url,
                        snippet=f"Repository: {repo}\nFile: {path}",
                    )

                time.sleep(2)  # Rate limit (30 req/min for unauthenticated)

            except Exception as e:
                print(f"    ❌ {e}")

        self.state["last_github_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()

        print(f"\n  ✅ {self.patterns_added} total patterns added")

    # ── DB persistence ──────────────────────────────────────────────────────

    def _save_pattern(self, title: str, category: str, severity: str,
                      pattern: str, language: str, detector: str,
                      source: str, source_url: str, snippet: str = "",
                      active: bool = True):
        """Save pattern + finding to GSC DB."""
        if not pattern:
            return

        pattern_hash = hashlib.md5(pattern.encode()).hexdigest()[:16]

        # Check if pattern exists
        existing = self.db.execute(
            "SELECT id FROM patterns WHERE pattern_hash=? LIMIT 1",
            (pattern_hash,)
        ).fetchone()

        if not existing:
            try:
                noise = "precise" if severity in ("CRITICAL", "HIGH") else "normal"
                self.db.execute(
                    """INSERT INTO patterns
                       (title, search_pattern, pattern_type, category, language,
                        active, noise_tier, pattern_hash, project, echelon)
                       VALUES (?, ?, 'regex', ?, ?, ?, ?, ?, '*', 1)""",
                    (title[:200], pattern, severity, language,
                     1 if active else 0, noise, pattern_hash)
                )
                pattern_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
                self.patterns_added += 1
            except Exception as e:
                print(f"    ⚠️ Pattern insert failed: {e}")
                return
        else:
            pattern_id = existing[0]

        # Save finding
        try:
            from gsc_db import compute_finding_key
            self.db.execute(
                """INSERT INTO findings
                   (project, rule_id, category, title, file_path,
                    detail, noise_tier, pattern_id, finding_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("gsc-collector", detector or "COLLECTED", severity,
                 title[:200], source_url, snippet[:500], "normal",
                 pattern_id,
                 compute_finding_key(detector or "COLLECTED", source_url, snippet[:500]))
            )
            self.findings_added += 1
        except Exception:
            pass

        self.db.commit()

    # ── Obsidian export ─────────────────────────────────────────────────────

    def export_obsidian(self):
        """Export latest collection to Obsidian vault."""
        VAULT_PATH.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d")

        findings = self.db.execute(
            """SELECT * FROM findings WHERE project='gsc-collector'
               AND date(created_at) = date('now')
               ORDER BY category DESC, created_at DESC LIMIT 100"""
        ).fetchall()

        if not findings:
            return

        filename = f"collection-{timestamp}.md"
        filepath = VAULT_PATH / filename

        with open(filepath, "w") as f:
            f.write(f"---\ntitle: \"GSC Collector — {timestamp}\"\n")
            f.write(f"collected: {datetime.now().isoformat()}\n")
            f.write(f"count: {len(findings)}\ntype: gsc-collector\n---\n\n")
            f.write(f"# GSC Collector — {timestamp}\n\n")
            f.write(f"**{len(findings)}** findings collected.\n\n")

            by_sev = {}
            for row in findings:
                sev = row[2] if len(row) > 2 else "MEDIUM"  # category is severity
                by_sev.setdefault(sev, []).append(row)

            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                items = by_sev.get(sev, [])
                if items:
                    f.write(f"## {sev} ({len(items)})\n\n")
                    for row in items[:10]:
                        f.write(f"- **{row[4][:100]}**\n")
                        f.write(f"  - Source: {row[9]}\n")
                        f.write(f"  - URL: {row[10]}\n\n")

        print(f"  📝 Obsidian: {len(findings)} findings → {filepath}")

    def close(self):
        self.db.close()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 gsc_collect_light.py [nvd|github|all]")
        print("  nvd     — CVE patterns from NVD (known exploited vulns)")
        print("  github  — GitHub code search patterns")
        print("  all     — everything")
        sys.exit(1)

    mode = sys.argv[1]
    collector = GscCollector()

    try:
        if mode in ("nvd", "all"):
            collector.collect_nvd(limit=50)
            collector.export_obsidian()

        if mode in ("github", "all"):
            collector.collect_github()
            collector.export_obsidian()

        print(f"\n{'='*50}")
        print(f"  📊 Total: {collector.patterns_added} patterns, "
              f"{collector.findings_added} findings")
        print(f"{'='*50}")

    finally:
        collector.close()


if __name__ == "__main__":
    main()
