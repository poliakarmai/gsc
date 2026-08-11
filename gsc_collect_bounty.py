#!/usr/bin/env python3
"""
GSC Bounty Collector — extracts real vulnerability patterns from bug bounty DBs.

Sources:
  - GitHub Security Advisories (GHSA) — structured vuln data with fix commits
  - Bugcrowd VRT — vulnerability taxonomy for classification

Feeds into GSC DB as labeled training examples for Deep Reduce / revalidation.

Usage:
    python3 gsc_collect_bounty.py ghsa     # GHSA advisories → vulnerable/fixed code
    python3 gsc_collect_bounty.py vrt      # Bugcrowd VRT taxonomy
    python3 gsc_collect_bounty.py all      # everything
"""
import sys
import os
import json
import re
import hashlib
import sqlite3
import time
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
STATE_PATH = Path.home() / ".hermes" / "state" / "gsc_bounty_state.json"
VAULT_PATH = Path.home() / "obsidian-vault" / "hermes" / "gsc-bounty"

HEADERS = {
    "User-Agent": "GSC-Bounty-Collector/1.0 (+https://github.com/poliakarmai/gsc)",
    "Accept": "application/json",
}

# Language → GitHub ecosystem mapping for GHSA filtering
ECO_TO_LANG = {
    "pip": "python",
    "npm": "javascript",
    "go": "go",
    "cargo": "rust",
    "maven": "java",
    "composer": "php",
    "nuget": "csharp",
    "rubygems": "ruby",
}
TARGET_ECOS = {"pip", "npm", "go", "cargo"}

# ── GHSA Collector ───────────────────────────────────────────────────────────

class GhsaCollector:
    """Collect vulnerability examples from GitHub Security Advisories."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.state = self._load_state()
        self.added = 0
        self.skipped = 0
        self.errors = 0

    def _load_state(self) -> dict:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
        return {"processed_ghsa": [], "last_ghsa_run": None}

    def _save_state(self):
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(self.state, indent=2, default=str))

    def collect(self, days: int = 7, limit: int = 30):
        """Collect GHSA advisories from last N days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        print(f"\n📡 GHSA Collector — last {days} days, up to {limit} advisories...")

        url = "https://api.github.com/advisories"
        params = {
            "type": "reviewed",
            "per_page": min(limit, 100),
            "sort": "published",
            "direction": "desc",
        }

        fetched = 0
        page = 1

        while fetched < limit and page <= 3:
            try:
                resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
                if resp.status_code == 403:
                    print(f"  ⚠️ Rate limited after {fetched} advisories")
                    break
                if resp.status_code != 200:
                    print(f"  ❌ GHSA API returned {resp.status_code}")
                    break
                advisories = resp.json()
            except Exception as e:
                print(f"  ❌ GHSA API error: {e}")
                break

            if not advisories:
                break

            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                published = adv.get("published_at", "")

                # Stop if too old
                if published < since and fetched > 0:
                    break

                if ghsa_id in self.state["processed_ghsa"]:
                    self.skipped += 1
                    continue

                fetched += 1
                print(f"  [{fetched}] {ghsa_id}: {adv.get('summary','?')[:80]}")

                try:
                    self._process_advisory(adv)
                except Exception as e:
                    print(f"    ❌ Process error: {e}")
                    self.errors += 1

                self.state["processed_ghsa"].append(ghsa_id)
                time.sleep(0.5)  # Rate limit

            page += 1

        # Keep last 2000
        self.state["processed_ghsa"] = self.state["processed_ghsa"][-2000:]
        self.state["last_ghsa_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()

        print(f"\n  ✅ {self.added} examples added, {self.skipped} skipped, {self.errors} errors")

    def _process_advisory(self, adv: dict):
        """Process one GHSA advisory: extract vulnerable/fixed code from patches."""
        ghsa_id = adv.get("ghsa_id", "")
        cve_id = adv.get("cve_id", "")
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        severity = (adv.get("severity") or "MEDIUM").upper()
        cwes = adv.get("cwes", [])
        cwe_id = cwes[0]["cwe_id"] if cwes else ""
        references = adv.get("references", [])

        # Filter by ecosystem
        vulns = adv.get("vulnerabilities", [])
        if not vulns:
            return

        ecosystem = vulns[0].get("package", {}).get("ecosystem", "")
        language = ECO_TO_LANG.get(ecosystem, "unknown")
        if ecosystem not in TARGET_ECOS:
            return  # Skip unsupported ecosystems

        # Extract commit URLs
        commit_urls = [r for r in references if "/commit/" in r]
        if not commit_urls:
            return  # No patch to learn from

        # Try to get diff from first commit
        for commit_url in commit_urls[:2]:
            diff_text = self._fetch_commit_diff(commit_url)
            if not diff_text:
                continue

            vulnerable_code, fixed_code = self._extract_code_change(diff_text, language)
            if not vulnerable_code or not fixed_code:
                continue

            self._save_example(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                cwe_id=cwe_id,
                summary=summary,
                description=description[:1000],
                severity=severity,
                language=language,
                ecosystem=ecosystem,
                vulnerable_code=vulnerable_code[:2000],
                fixed_code=fixed_code[:2000],
                commit_url=commit_url,
                source_url=f"https://github.com/advisories/{ghsa_id}",
            )
            self.added += 1
            print(f"    ✅ {cwe_id or 'N/A'} | {language} | +{len(fixed_code)}/-{len(vulnerable_code)} chars")
            return  # One example per advisory is enough

    def _fetch_commit_diff(self, commit_url: str) -> str | None:
        """Fetch unified diff from GitHub commit."""
        # Convert html_url to diff URL: .../commit/abc123 → .../commit/abc123.diff
        diff_url = commit_url.replace("github.com", "github.com") + ".diff"

        # Also try .patch
        for ext in [".diff", ".patch"]:
            try:
                url = commit_url.rstrip("/") + ext
                # Use raw URL
                raw_url = url.replace("github.com", "raw.githubusercontent.com")
                # Actually, GitHub diff works directly: commit/abc123.diff
                resp = requests.get(url, headers={**HEADERS, "Accept": "text/plain"}, timeout=20)
                if resp.status_code == 200 and len(resp.text) > 50:
                    return resp.text
            except Exception:
                continue
        return None

    def _extract_code_change(self, diff_text: str, language: str) -> tuple[str | None, str | None]:
        """Extract vulnerable (removed) and fixed (added) code from unified diff."""
        removed_lines = []
        added_lines = []

        for line in diff_text.split("\n"):
            if line.startswith("--- ") or line.startswith("+++ "):
                continue
            if line.startswith("@@ "):
                continue
            if line.startswith("-") and not line.startswith("---"):
                code = line[1:]
                if code.strip() and not code.strip().startswith("#"):
                    removed_lines.append(code)
            elif line.startswith("+") and not line.startswith("+++"):
                code = line[1:]
                if code.strip() and not code.strip().startswith("#"):
                    added_lines.append(code)

        if not removed_lines or not added_lines:
            return None, None

        vulnerable_code = "\n".join(removed_lines[:30])
        fixed_code = "\n".join(added_lines[:30])

        # Skip if diff is just refactoring (same content, different formatting)
        norm_vuln = re.sub(r'\s+', '', vulnerable_code)
        norm_fix = re.sub(r'\s+', '', fixed_code)
        if norm_vuln == norm_fix:
            return None, None

        return vulnerable_code, fixed_code

    def _save_example(self, ghsa_id: str, cve_id: str, cwe_id: str,
                      summary: str, description: str, severity: str,
                      language: str, ecosystem: str,
                      vulnerable_code: str, fixed_code: str,
                      commit_url: str, source_url: str):
        """Save labeled example to DB."""
        example_hash = hashlib.md5(vulnerable_code.encode()).hexdigest()[:16]

        try:
            self.db.execute(
                """INSERT OR IGNORE INTO bounty_examples
                   (ghsa_id, cve_id, cwe_id, summary, description, severity,
                    language, ecosystem, vulnerable_code, fixed_code,
                    commit_url, source_url, example_hash, collected_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                (ghsa_id, cve_id, cwe_id, summary, description, severity,
                 language, ecosystem, vulnerable_code, fixed_code,
                 commit_url, source_url, example_hash)
            )
            self.db.commit()
        except sqlite3.OperationalError:
            # Table might not exist yet
            pass


# ── Bugcrowd VRT Collector ───────────────────────────────────────────────────

class VrtCollector:
    """Collect vulnerability taxonomy from Bugcrowd VRT."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.added = 0

    def collect(self):
        """Fetch Bugcrowd VRT and save categories."""
        print("\n📡 Bugcrowd VRT Collector...")
        url = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"

        try:
            resp = requests.get(url, headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                print(f"  ❌ VRT returned {resp.status_code}")
                return
            data = resp.json()
        except Exception as e:
            print(f"  ❌ VRT error: {e}")
            return

        content = data.get("content", [])
        print(f"  Loaded VRT with {len(content)} top-level categories")

        for category in content:
            self._walk_vrt_tree(category, parent_id=None)

        print(f"  ✅ {self.added} VRT categories saved")

    def _walk_vrt_tree(self, node: dict, parent_id: str | None, depth: int = 0):
        """Recursively walk VRT tree and save categories."""
        node_id = node.get("id", "")
        name = node.get("name", "")
        priority = node.get("priority", 0)

        try:
            self.db.execute(
                """INSERT OR REPLACE INTO vrt_categories
                   (vrt_id, name, parent_id, priority, depth)
                   VALUES (?, ?, ?, ?, ?)""",
                (node_id, name, parent_id, priority, depth)
            )
            self.added += 1
        except sqlite3.OperationalError:
            pass

        for child in node.get("children", []):
            self._walk_vrt_tree(child, parent_id=node_id, depth=depth + 1)

        self.db.commit()


# ── DB Schema Migration ──────────────────────────────────────────────────────

def ensure_bounty_schema(db: sqlite3.Connection):
    """Create bounty-related tables if they don't exist."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS bounty_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ghsa_id TEXT NOT NULL,
            cve_id TEXT DEFAULT '',
            cwe_id TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'MEDIUM',
            language TEXT DEFAULT 'unknown',
            ecosystem TEXT DEFAULT '',
            vulnerable_code TEXT NOT NULL,
            fixed_code TEXT NOT NULL,
            commit_url TEXT DEFAULT '',
            source_url TEXT DEFAULT '',
            example_hash TEXT UNIQUE,
            collected_at TEXT DEFAULT (datetime('now')),
            used_in_training INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_bounty_lang ON bounty_examples(language);
        CREATE INDEX IF NOT EXISTS idx_bounty_cwe ON bounty_examples(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_bounty_severity ON bounty_examples(severity);
        CREATE INDEX IF NOT EXISTS idx_bounty_ghsa ON bounty_examples(ghsa_id);

        CREATE TABLE IF NOT EXISTS vrt_categories (
            vrt_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id TEXT,
            priority INTEGER DEFAULT 0,
            depth INTEGER DEFAULT 0,
            collected_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_vrt_parent ON vrt_categories(parent_id);
    """)
    db.commit()


# ── Export ────────────────────────────────────────────────────────────────────

def export_obsidian(db: sqlite3.Connection):
    """Export latest bounty examples to Obsidian vault."""
    VAULT_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d")

    examples = db.execute(
        """SELECT ghsa_id, cwe_id, summary, severity, language, commit_url
           FROM bounty_examples ORDER BY collected_at DESC LIMIT 50"""
    ).fetchall()

    if not examples:
        return

    filepath = VAULT_PATH / f"bounty-{timestamp}.md"
    with open(filepath, "w") as f:
        f.write(f"---\ntitle: \"GSC Bounty — {timestamp}\"\n")
        f.write(f"collected: {datetime.now().isoformat()}\n")
        f.write(f"count: {len(examples)}\ntype: gsc-bounty\n---\n\n")
        f.write(f"# 🎯 GSC Bounty Collector — {timestamp}\n\n")
        f.write(f"**{len(examples)}** labeled examples collected.\n\n")

        by_lang = {}
        for row in examples:
            lang = row[4] or "other"
            by_lang.setdefault(lang, []).append(row)

        for lang in sorted(by_lang):
            items = by_lang[lang]
            f.write(f"## {lang.capitalize()} ({len(items)})\n\n")
            for row in items[:10]:
                f.write(f"- **{row[2][:100]}**\n")
                f.write(f"  - {row[0]} | {row[1]} | {row[3]}\n")
                f.write(f"  - Commit: {row[5]}\n\n")

    print(f"  📝 Obsidian: {filepath}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 gsc_collect_bounty.py [ghsa|vrt|all]")
        print("  ghsa   — GitHub Security Advisories → vulnerable/fixed code")
        print("  vrt    — Bugcrowd VRT taxonomy")
        print("  all    — everything")
        sys.exit(1)

    mode = sys.argv[1]
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")

    ensure_bounty_schema(db)

    try:
        if mode in ("ghsa", "all"):
            ghsa = GhsaCollector(db)
            ghsa.collect(days=7, limit=30)
            export_obsidian(db)

        if mode in ("vrt", "all"):
            vrt = VrtCollector(db)
            vrt.collect()

        # Summary
        total = db.execute("SELECT COUNT(*) FROM bounty_examples").fetchone()[0]
        vrt_count = db.execute("SELECT COUNT(*) FROM vrt_categories").fetchone()[0]

        print(f"\n{'='*50}")
        print(f"  📊 Bounty DB: {total} examples, {vrt_count} VRT categories")
        print(f"{'='*50}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
