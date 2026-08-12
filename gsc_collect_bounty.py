#!/usr/bin/env python3
"""
GSC Bounty Collector v2 — extracts real vulnerability patterns from bug bounty DBs.

Sources:
  - GitHub Security Advisories (GHSA) — structured vuln data with fix commits
  - Bugcrowd VRT — vulnerability taxonomy for classification

v2 improvements (12.08.2026):
  - CWE-ranked hunk extraction (not all hunks — only security-relevant ones)
  - Negative examples (clean code from same file before vulnerability)
  - Pattern-based deduplication (not just advisory ID)
  - Fix quality scoring + ±5 line context
  - Coverage dashboard

Public data note: GHSA examples are public — NO differential privacy needed.
These can be freely shared between tenants, used in prompts, and auto-generated.

Usage:
    python3 gsc_collect_bounty.py ghsa        # GHSA advisories → vulnerable/fixed code
    python3 gsc_collect_bounty.py negatives    # Collect negative (clean) examples
    python3 gsc_collect_bounty.py dashboard    # Coverage report
    python3 gsc_collect_bounty.py vrt          # Bugcrowd VRT taxonomy
    python3 gsc_collect_bounty.py all          # everything
"""
import sys, os, json, re, hashlib, sqlite3, time, requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import Counter

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
STATE_PATH = Path.home() / ".hermes" / "state" / "gsc_bounty_state.json"
VAULT_PATH = Path.home() / "obsidian-vault" / "hermes" / "gsc-bounty"

HEADERS = {
    "User-Agent": "GSC-Bounty-Collector/2.0 (+https://github.com/poliakarmai/gsc)",
    "Accept": "application/json",
}

ECO_TO_LANG = {
    "pip": "python", "npm": "javascript", "go": "go", "cargo": "rust",
    "maven": "java", "composer": "php", "nuget": "csharp", "rubygems": "ruby",
}
TARGET_ECOS = {"pip", "npm", "go", "cargo"}

# ── CWE → keyword patterns for hunk relevance scoring ─────────────────────────
# Higher score = hunk likely contains the vulnerability fix
CWE_HUNK_PATTERNS = {
    "CWE-22": [r'path', r'os\.path', r'\.\.\/', r'open\(', r'readfile', r'filepath',
               r'traversal', r'basename', r'join'],
    "CWE-59": [r'symlink', r'follow', r'link', r'os\.readlink', r'lstat', r'resolve',
               r'worktree'],
    "CWE-73": [r'pathspec', r'--path', r'file.*name', r'external.*control',
              r'git.*option', r'unsafe', r'arbitrary.*file'],
    "CWE-79": [r'innerHTML', r'inner', r'sanitize', r'escape', r'dangerously',
               r'setHTML', r'document\.write', r'DOMPurify', r'html', r'xss'],
    "CWE-88": [r'argument.*injection', r'option.*forw', r'--[a-z]', r'check_unsafe',
               r'allow_unsafe', r'unguarded'],
    "CWE-89": [r'SELECT', r'INSERT', r'UPDATE', r'DELETE', r'sql', r'query',
               r'parameterize', r'placeholder', r'execute'],
    "CWE-94": [r'eval\(', r'exec\(', r'Function\(', r'__import__'],
    "CWE-133": [r'format', r'f["\']', r'\.format\(', r'string.*interpolat'],
    "CWE-200": [r'debug', r'secret', r'disclos', r'expose', r'log', r'leak',
                r'workspace', r'UUID', r'information', r'devtools'],
    "CWE-331": [r'entropy', r'random', r'secure', r'crypt', r'Math\.random\(\)',
                r'crypto\.random', r'getRandom', r'insufficient', r'generat'],
    "CWE-384": [r'session', r'regenerate', r'fixation', r'forget', r'invalidate',
                r'remember', r'clear\(\)', r'cookie'],
    "CWE-400": [r'memory', r'consume', r'allocation', r'resource', r'ToUnicode',
                r'large', r'stream', r'uncontrolled'],
    "CWE-407": [r'algorithmic', r'complexity', r'DoS', r'backtracking', r'loop',
                r'regex.*ReDoS', r'language.*middleware'],
    "CWE-488": [r'memo', r'retain', r'cross.*user', r'SSR', r'cache',
                r'session.*data', r'request', r'exposure.*data'],
    "CWE-798": [r'SECRET_KEY', r'password', r'key', r'environ', r'getenv',
                r'credential', r'hardcod'],
    "CWE-834": [r'loop', r'iterate', r'range', r'while', r'for', r'limit',
                r'excessive', r'CID.*font', r'width'],
    "CWE-918": [r'SSRF', r'request.*url', r'fetch\(', r'internal.*IP',
                r'validate.*url', r'allow.*host'],
    "CWE-1333": [r'ReDoS', r'backtracking', r'exponential', r'regex', r'pattern',
                 r'catastroph', r'pymdown', r'caret', r'tilde'],
}
HUNK_RELEVANCE_MIN = 0.3  # Minimum relevance to save (was 0.1)

# Language extensions for negative example search
LANG_EXTS = {
    "python": [".py"], "javascript": [".js", ".ts", ".tsx", ".jsx"],
    "go": [".go"], "rust": [".rs"],
}

IGNORE_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
               "dist", "build", "vendor", ".tox", ".eggs", "test", "tests"}


# ── Schema v2 ─────────────────────────────────────────────────────────────────

def _add_column_if_missing(db, table, col_name, col_def):
    """Add column if it doesn't exist (SQLite doesn't support IF NOT EXISTS for ALTER)."""
    existing = [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if col_name not in existing:
        try:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
        except sqlite3.OperationalError:
            pass


def ensure_bounty_schema(db: sqlite3.Connection):
    """Create bounty-related tables (v2 schema) with migration support."""
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
            fix_context TEXT DEFAULT '',
            fix_quality TEXT DEFAULT 'unknown',
            language_version TEXT DEFAULT '',
            commit_url TEXT DEFAULT '',
            source_url TEXT DEFAULT '',
            example_hash TEXT UNIQUE,
            pattern_hash TEXT DEFAULT '',
            hunk_relevance REAL DEFAULT 0.0,
            collected_at TEXT DEFAULT (datetime('now')),
            used_in_training INTEGER DEFAULT 0
        );""")
    
    # v1→v2 migration: add missing columns if they don't exist
    _add_column_if_missing(db, "bounty_examples", "fix_context", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "bounty_examples", "fix_quality", "TEXT DEFAULT 'unknown'")
    _add_column_if_missing(db, "bounty_examples", "language_version", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "bounty_examples", "pattern_hash", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "bounty_examples", "hunk_relevance", "REAL DEFAULT 0.0")
    
    db.executescript("""
        CREATE INDEX IF NOT EXISTS idx_bounty_lang ON bounty_examples(language);
        CREATE INDEX IF NOT EXISTS idx_bounty_cwe ON bounty_examples(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_bounty_severity ON bounty_examples(severity);
        CREATE INDEX IF NOT EXISTS idx_bounty_ghsa ON bounty_examples(ghsa_id);
        CREATE INDEX IF NOT EXISTS idx_bounty_pattern ON bounty_examples(pattern_hash);

        CREATE TABLE IF NOT EXISTS negative_examples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT DEFAULT '',
            language TEXT DEFAULT 'unknown',
            clean_code TEXT NOT NULL,
            source_file TEXT DEFAULT '',
            source_project TEXT DEFAULT '',
            example_hash TEXT UNIQUE,
            collected_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_neg_cwe ON negative_examples(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_neg_lang ON negative_examples(language);

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


# ── Hunk Ranking Engine ───────────────────────────────────────────────────────

def rank_hunks_by_cwe(diff_text: str, cwe_id: str) -> list[dict]:
    """Split unified diff into hunks, score each by CWE relevance."""
    if cwe_id not in CWE_HUNK_PATTERNS:
        patterns = [r'\w+']  # Generic fallback
    else:
        patterns = CWE_HUNK_PATTERNS[cwe_id]

    # Parse unified diff into hunks
    hunks = []
    current = {"removed": [], "added": [], "header": ""}

    for line in diff_text.split("\n"):
        if line.startswith("@@ "):
            if current["removed"] or current["added"]:
                hunks.append(current)
            current = {"removed": [], "added": [], "header": line}
        elif line.startswith("--- ") or line.startswith("+++ "):
            continue
        elif line.startswith("-") and not line.startswith("---"):
            code = line[1:].strip()
            if code and not code.startswith("#"):
                current["removed"].append(line[1:])
        elif line.startswith("+"):
            code = line[1:].strip()
            if code and not code.startswith("#"):
                current["added"].append(line[1:])
    if current["removed"] or current["added"]:
        hunks.append(current)

    if not hunks:
        return []

    # Score each hunk
    for h in hunks:
        text = " ".join(h["removed"] + h["added"]).lower()
        score = 0
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                score += 1
        # Bonus: hunk with significant code change (not just whitespace/comments)
        code_chars = sum(len(l.strip()) for l in h["removed"] + h["added"]
                        if l.strip() and not l.strip().startswith("#"))
        if code_chars > 50:
            score += 1
        h["relevance"] = score / max(len(patterns), 1)

    hunks.sort(key=lambda h: -h["relevance"])
    return hunks


def _score_fix_quality(vulnerable_code: str, fixed_code: str, cwe_id: str) -> str:
    """Heuristic fix quality: is this a real fix or a workaround?"""
    vuln_len = len(vulnerable_code)
    fix_len = len(fixed_code)

    # Workaround indicators: minimal change, comment-only, hardcoded bypass
    if fix_len < 20:
        return "workaround"
    if fixed_code.strip().startswith("//") or fixed_code.strip().startswith("#"):
        return "workaround"
    if 'FIXME' in fixed_code or 'HACK' in fixed_code or 'TODO' in fixed_code:
        return "workaround"

    # Real fix indicators: structural change, new validation, env var
    if any(kw in fixed_code.lower() for kw in ['validate', 'sanitize', 'environ', 'escape',
                                                'check_unsafe', 'allow_unsafe',
                                                'os.getenv', 'process.env']):
        return "fix"
    if fix_len > vuln_len * 0.5:
        return "fix"

    return "patch"


# ── GHSA Collector v2 ─────────────────────────────────────────────────────────

class GhsaCollector:
    """Collect vulnerability examples from GitHub Security Advisories."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.state = self._load_state()
        self.added = 0
        self.skipped = 0
        self.errors = 0
        self.dup_patterns = 0

    def _load_state(self) -> dict:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
        return {"processed_ghsa": [], "last_ghsa_run": None, "pattern_hashes": []}

    def _save_state(self):
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(self.state, indent=2, default=str))

    def _ghsa_exists_in_db(self, ghsa_id: str) -> bool:
        """Check if GHSA already in bounty_examples (idempotency)."""
        try:
            row = self.db.execute(
                "SELECT 1 FROM bounty_examples WHERE ghsa_id = ? LIMIT 1", (ghsa_id,)
            ).fetchone()
            return row is not None
        except sqlite3.OperationalError:
            return False

    def _get_near_ready_cwes(self) -> list:
        """Find CWE+lang combos closest to ready (4-5 examples) for prioritization."""
        try:
            rows = self.db.execute("""
                SELECT cwe_id, COUNT(*) as cnt FROM bounty_examples
                WHERE cwe_id != '' AND language IN ('python','javascript','go','rust')
                GROUP BY cwe_id HAVING cnt >= 3 AND cnt < 5 ORDER BY cnt DESC
            """).fetchall()
            return [r[0] for r in rows]
        except sqlite3.OperationalError:
            return []

    def collect(self, days: int = 7, limit: int = 30, prioritize_cwes: list = None):
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        if prioritize_cwes:
            print(f"\n📡 GHSA Collector v2 — last {days}d, up to {limit}, prioritizing {prioritize_cwes}...")
        else:
            print(f"\n📡 GHSA Collector v2 — last {days}d, up to {limit} advisories...")
        
        # 🆕 Prioritize by near-ready CWE combos
        if prioritize_cwes is None:
            prioritize_cwes = self._get_near_ready_cwes()

        url = "https://api.github.com/advisories"
        # 🆕 Итерируем по экосистемам — свежие advisories доминирует nuget (.NET),
        # который глушит pip/npm/go. Фильтруем напрямую через API ecosystem=.
        ecosystems = ["pip", "npm", "go", "rust"]
        fetched = 0

        for eco in ecosystems:
            if fetched >= limit:
                break
            params = {"type": "reviewed", "ecosystem": eco,
                      "per_page": 100, "sort": "published", "direction": "desc"}
            page = 1

            while fetched < limit and page <= 5:
                try:
                    resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
                    if resp.status_code in (403, 429):
                        print(f"  ⚠️ Rate limited after {fetched} (ecosystem={eco})")
                        break
                    if resp.status_code != 200:
                        break
                    advisories = resp.json()
                except Exception as e:
                    print(f"  ❌ GHSA API error: {e}")
                    break
                if not advisories:
                    break

                # 🆕 Sort advisories: prioritize CWE-close-to-ready first
                if prioritize_cwes:
                    def _priority(adv):
                        cwes = adv.get("cwes", [])
                        cwe = cwes[0]["cwe_id"] if cwes else ""
                        if cwe in prioritize_cwes:
                            return prioritize_cwes.index(cwe)
                        return 999
                    advisories = sorted(advisories, key=_priority)

                for adv in advisories:
                    ghsa_id = adv.get("ghsa_id", "")
                    published = adv.get("published_at", "")
                    if published < since and fetched > 0:
                        break
                    
                    # 🆕 Idempotency: skip if already in DB
                    if ghsa_id in self.state["processed_ghsa"]:
                        self.skipped += 1
                        continue
                    if self._ghsa_exists_in_db(ghsa_id):
                        self.skipped += 1
                        continue

                    fetched += 1
                    print(f"  [{fetched}] {ghsa_id}: {adv.get('summary','?')[:80]}")

                    try:
                        self._process_advisory(adv)
                    except Exception as e:
                        print(f"    ❌ {e}")
                        self.errors += 1

                    self.state["processed_ghsa"].append(ghsa_id)
                    time.sleep(0.5)

                if fetched >= limit:
                    break
                page += 1

        self.state["processed_ghsa"] = self.state["processed_ghsa"][-2000:]
        self.state["last_ghsa_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()
        print(f"\n  ✅ {self.added} added, {self.dup_patterns} deduped, {self.skipped} skip, {self.errors} err")

    def _process_advisory(self, adv: dict):
        ghsa_id = adv.get("ghsa_id", "")
        cve_id = adv.get("cve_id", "")
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        severity = (adv.get("severity") or "MEDIUM").upper()
        cwes = adv.get("cwes", [])
        cwe_id = cwes[0]["cwe_id"] if cwes else ""
        references = adv.get("references", [])

        vulns = adv.get("vulnerabilities", [])
        if not vulns:
            return
        ecosystem = vulns[0].get("package", {}).get("ecosystem", "")
        language = ECO_TO_LANG.get(ecosystem, "unknown")
        if ecosystem not in TARGET_ECOS:
            return

        package_name = vulns[0].get("package", {}).get("name", "")
        version_range = vulns[0].get("vulnerable_version_range", "")

        commit_urls = [r for r in references if "/commit/" in r]
        if not commit_urls:
            return

        for commit_url in commit_urls[:2]:
            diff_text = self._fetch_commit_diff(commit_url)
            if not diff_text:
                continue

            # v2: Rank hunks by CWE relevance
            ranked = rank_hunks_by_cwe(diff_text, cwe_id)
            if not ranked:
                continue

            top_hunk = ranked[0]
            if top_hunk["relevance"] < HUNK_RELEVANCE_MIN:
                print(f"    ⏭️  Low relevance ({top_hunk['relevance']:.2f} < {HUNK_RELEVANCE_MIN})")
                continue  # Nothing security-relevant enough

            vulnerable_code = "\n".join(top_hunk["removed"][:40])
            fixed_code = "\n".join(top_hunk["added"][:40])

            if not vulnerable_code or not fixed_code:
                continue

            # Refactoring check
            if re.sub(r'\s+', '', vulnerable_code) == re.sub(r'\s+', '', fixed_code):
                continue

            # v2: Extract ±5 lines of context around the hunk
            fix_context = _extract_hunk_context(diff_text, top_hunk["header"], language)

            # v2: Fix quality score
            fix_quality = _score_fix_quality(vulnerable_code, fixed_code, cwe_id)

            # v2: Pattern-based dedup (normalize code, not raw)
            pattern_hash = _compute_pattern_hash(vulnerable_code, language)
            if pattern_hash in self.state.get("pattern_hashes", []):
                self.dup_patterns += 1
                print(f"    ⏭️  Duplicate pattern (skipped)")
                return
            self.state.setdefault("pattern_hashes", []).append(pattern_hash)

            self._save_example(
                ghsa_id=ghsa_id, cve_id=cve_id, cwe_id=cwe_id,
                summary=summary, description=description[:1000],
                severity=severity, language=language, ecosystem=ecosystem,
                vulnerable_code=vulnerable_code[:2000],
                fixed_code=fixed_code[:2000],
                fix_context=fix_context[:2000],
                fix_quality=fix_quality,
                language_version=version_range,
                commit_url=commit_url,
                source_url=f"https://github.com/advisories/{ghsa_id}",
                hunk_relevance=round(top_hunk["relevance"], 3),
                pattern_hash=pattern_hash,
            )
            self.added += 1
            print(f"    ✅ {cwe_id} | {language} | qual={fix_quality} | rel={top_hunk['relevance']:.2f}")
            return

    def _fetch_commit_diff(self, commit_url: str) -> str | None:
        for ext in [".diff", ".patch"]:
            try:
                url = commit_url.rstrip("/") + ext
                resp = requests.get(url, headers={**HEADERS, "Accept": "text/plain"}, timeout=20)
                if resp.status_code == 200 and len(resp.text) > 50:
                    return resp.text
            except Exception:
                continue
        return None

    def _save_example(self, ghsa_id, cve_id, cwe_id, summary, description, severity,
                      language, ecosystem, vulnerable_code, fixed_code, fix_context,
                      fix_quality, language_version, commit_url, source_url,
                      hunk_relevance, pattern_hash):
        example_hash = hashlib.md5(vulnerable_code.encode()).hexdigest()[:16]
        try:
            self.db.execute("""
                INSERT OR IGNORE INTO bounty_examples
                (ghsa_id, cve_id, cwe_id, summary, description, severity,
                 language, ecosystem, vulnerable_code, fixed_code, fix_context,
                 fix_quality, language_version, commit_url, source_url,
                 example_hash, pattern_hash, hunk_relevance, collected_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
            """, (ghsa_id, cve_id, cwe_id, summary, description, severity,
                  language, ecosystem, vulnerable_code, fixed_code, fix_context,
                  fix_quality, language_version, commit_url, source_url,
                  example_hash, pattern_hash, hunk_relevance))
            self.db.commit()
        except sqlite3.OperationalError:
            pass


def _compute_pattern_hash(vulnerable_code: str, language: str) -> str:
    """Normalize vulnerable code for dedup: remove identifiers, keep structure."""
    normalized = re.sub(r'"[^"]*"', '"..."', vulnerable_code)
    normalized = re.sub(r"'[^']*'", "'...'", normalized)
    normalized = re.sub(r'\d+', 'N', normalized)
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return hashlib.md5((language + "|" + normalized).encode()).hexdigest()[:16]


def _extract_hunk_context(diff_text: str, hunk_header: str, language: str) -> str:
    """Extract ±5 lines of surrounding context from the hunk."""
    lines = diff_text.split("\n")
    context_lines = []
    in_target_hunk = False
    context_before = []
    context_after = []
    buf = []

    for line in lines:
        if line.startswith("@@ "):
            if in_target_hunk:
                break
            if line == hunk_header:
                in_target_hunk = True
                context_before = list(buf[-5:])  # Last 5 context lines before hunk
            buf = []
        elif in_target_hunk:
            if line.startswith(" ") or line.startswith("-") or line.startswith("+"):
                buf.append(line)
            if len(buf) >= 10:
                context_after = [l for l in buf if l.startswith(" ")][:5]
                break
        else:
            if line.startswith(" "):
                buf.append(line)

    return "\n".join(context_before + context_after)


# ── Negative Examples Collector ───────────────────────────────────────────────

class NegativeCollector:
    """Collect clean code examples — code NOT vulnerable to a given CWE."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.added = 0

    def collect(self):
        """For each CWE+language combo in bounty_examples, collect negative examples."""
        print("\n📡 Negative Examples Collector...")

        combos = self.db.execute("""
            SELECT DISTINCT cwe_id, language FROM bounty_examples
            WHERE cwe_id != '' AND language != 'unknown'
        """).fetchall()

        if not combos:
            print("  No bounty examples yet — run 'ghsa' first")
            return

        for cwe_id, language in combos:
            positives = self.db.execute(
                "SELECT ghsa_id FROM bounty_examples WHERE cwe_id=? AND language=?",
                (cwe_id, language)
            ).fetchall()
            if len(positives) < 2:
                continue

            print(f"  {cwe_id} | {language}: searching for negative examples...")

            # Strategy: find GHSA advisories of DIFFERENT CWE for the same language
            # These are real vulns but not of *this* type → safe to use as negatives
            negatives = self.db.execute("""
                SELECT ghsa_id, summary, language FROM bounty_examples
                WHERE language = ? AND cwe_id != ? AND cwe_id != ''
                LIMIT 3
            """, (language, cwe_id)).fetchall()

            for n in negatives:
                self._save_negative(cwe_id, language,
                                    f"Safe: {n[1][:200]} ({n[0]})",
                                    n[0], "cross-cwe")

            # Also try to find sibling files from bounty repos
            ghsa_ids = [p[0] for p in positives[:3]]
            for ghsa in ghsa_ids:
                examples = self.db.execute(
                    "SELECT commit_url, language FROM bounty_examples WHERE ghsa_id=?",
                    (ghsa,)
                ).fetchall()
                if not examples:
                    continue
                commit_url = examples[0][0]
                if not commit_url:
                    continue
                # Try to get the file tree from the commit's parent
                clean_snippet = self._fetch_clean_sibling(commit_url, language)
                if clean_snippet:
                    self._save_negative(cwe_id, language, clean_snippet[:300],
                                        f"sibling-of-{ghsa}", "sibling-file")
                    self.added += 1

        print(f"  ✅ {self.added} negative examples collected")

    def _fetch_clean_sibling(self, commit_url: str, language: str) -> str | None:
        """Try to get a clean sibling file from the same repo (parent commit)."""
        try:
            # Get the parent commit via GitHub API
            owner_repo = "/".join(commit_url.split("/")[-4:-2]) if "/" in commit_url else ""
            sha = commit_url.rstrip("/").split("/")[-1].split(".")[0] if "/" in commit_url else ""

            if not owner_repo or not sha:
                return None

            # Fetch commit to get parent SHA
            api_url = f"https://api.github.com/repos/{owner_repo}/commits/{sha}"
            resp = requests.get(api_url, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                return None
            data = resp.json()
            parents = data.get("parents", [])
            if not parents:
                return None

            parent_sha = parents[0]["sha"]

            # Get parent commit file list
            tree_url = f"https://api.github.com/repos/{owner_repo}/git/commits/{parent_sha}"
            resp = requests.get(tree_url, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                return None
            tree_data = resp.json()
            tree_sha = tree_data.get("tree", {}).get("sha", "")

            # Find a source file in the tree
            tree_api = f"https://api.github.com/repos/{owner_repo}/git/trees/{tree_sha}?recursive=1"
            resp = requests.get(tree_api, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                return None
            tree_items = resp.json().get("tree", [])

            exts = LANG_EXTS.get(language, [".py"])
            for item in tree_items:
                if any(item["path"].endswith(ext) for ext in exts):
                    if "test" in item["path"].lower() or "spec" in item["path"].lower():
                        continue
                    blob_url = item["url"]
                    resp = requests.get(blob_url, headers=HEADERS, timeout=15)
                    if resp.status_code == 200:
                        content = resp.json().get("content", "")
                        import base64
                        try:
                            decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                            return decoded[:1000]
                        except Exception:
                            pass
                    break
        except Exception:
            pass
        return None

    def _save_negative(self, cwe_id, language, clean_code, source, source_type):
        example_hash = hashlib.md5(clean_code.encode()).hexdigest()[:16]
        try:
            self.db.execute("""
                INSERT OR IGNORE INTO negative_examples
                (cwe_id, language, clean_code, source_file, source_project, example_hash, collected_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (cwe_id, language, clean_code[:2000], source, source_type, example_hash))
            self.db.commit()
        except sqlite3.OperationalError:
            pass


# ── Dashboard ─────────────────────────────────────────────────────────────────

def show_dashboard(db: sqlite3.Connection):
    """Coverage dashboard: CWE × language matrix + readiness for auto-generation."""
    print("\n📊 Bounty Coverage Dashboard\n")
    print(f"{'CWE':<12} {'Lang':<12} {'Examples':>9} {'Fix':>6} {'W/A':>6} {'Neg':>5} {'Ready':>6}")
    print("-" * 65)

    rows = db.execute("""
        SELECT cwe_id, language,
               COUNT(*) as total,
               SUM(CASE WHEN fix_quality='fix' THEN 1 ELSE 0 END) as fixes,
               SUM(CASE WHEN fix_quality='workaround' THEN 1 ELSE 0 END) as workarounds
        FROM bounty_examples
        WHERE cwe_id != ''
        GROUP BY cwe_id, language
        ORDER BY total DESC
    """).fetchall()

    if not rows:
        print("  (no data yet)")
        return

    ready_combos = []
    for cwe_id, lang, total, fixes, workarounds in rows:
        neg_count = db.execute(
            "SELECT COUNT(*) FROM negative_examples WHERE cwe_id=? AND language=?",
            (cwe_id, lang)
        ).fetchone()[0]

        # Ready for auto-generation: ≥5 examples, ≥3 fixes, ≥1 negative
        ready = total >= 5 and (fixes or 0) >= 3 and neg_count >= 1
        marker = "✅ YES" if ready else f"⚠️  {5-total} more"

        print(f"{cwe_id:<12} {lang:<12} {total:>9} {fixes or 0:>6} {workarounds or 0:>6} {neg_count:>5} {marker:>6}")
        if ready:
            ready_combos.append((cwe_id, lang))

    if ready_combos:
        print(f"\n🎯 {len(ready_combos)} combos ready for auto-generation:")
        for cwe, lang in ready_combos:
            print(f"   {cwe} | {lang}")
    else:
        print(f"\n📈 Working toward 5+ examples per CWE+lang...")
        print(f"   Run 'ghsa' daily to build the dataset.")

    # Summary
    total = db.execute("SELECT COUNT(*) FROM bounty_examples").fetchone()[0]
    total_neg = db.execute("SELECT COUNT(*) FROM negative_examples").fetchone()[0]
    unique_cwe = db.execute("SELECT COUNT(DISTINCT cwe_id) FROM bounty_examples WHERE cwe_id != ''").fetchone()[0]
    print(f"\n{'='*65}")
    print(f"  Total: {total} positive | {total_neg} negative | {unique_cwe} unique CWEs")
    print(f"  Public data (GHSA) — no DP needed ✓")


# ── Bugcrowd VRT Collector ────────────────────────────────────────────────────

class VrtCollector:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.added = 0

    def collect(self):
        print("\n📡 Bugcrowd VRT Collector...")
        url = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=30)
            if resp.status_code != 200:
                print(f"  ❌ HTTP {resp.status_code}")
                return
            data = resp.json()
        except Exception as e:
            print(f"  ❌ {e}")
            return
        content = data.get("content", [])
        print(f"  Loaded {len(content)} top-level categories")
        for cat in content:
            self._walk_vrt_tree(cat, None)
        print(f"  ✅ {self.added} categories")

    def _walk_vrt_tree(self, node, parent_id, depth=0):
        nid, name = node.get("id", ""), node.get("name", "")
        priority = node.get("priority", 0)
        try:
            self.db.execute("INSERT OR REPLACE INTO vrt_categories VALUES (?,?,?,?,?,datetime('now'))",
                            (nid, name, parent_id, priority, depth))
            self.added += 1
        except sqlite3.OperationalError:
            pass
        for child in node.get("children", []):
            self._walk_vrt_tree(child, nid, depth + 1)
        self.db.commit()


# ── Export ────────────────────────────────────────────────────────────────────

def export_obsidian(db: sqlite3.Connection):
    VAULT_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d")
    examples = db.execute("""SELECT ghsa_id, cwe_id, summary, severity, language, fix_quality
        FROM bounty_examples ORDER BY collected_at DESC LIMIT 50""").fetchall()
    if not examples:
        return
    filepath = VAULT_PATH / f"bounty-{timestamp}.md"
    with open(filepath, "w") as f:
        f.write(f"---\ntitle: \"GSC Bounty — {timestamp}\"\ncount: {len(examples)}\ntype: gsc-bounty\n---\n\n")
        f.write(f"# 🎯 GSC Bounty Collector — {timestamp}\n\n**{len(examples)}** labelled examples.\n\n")
        by_lang = {}
        for r in examples:
            by_lang.setdefault(r[4] or "other", []).append(r)
        for lang in sorted(by_lang):
            f.write(f"## {lang.capitalize()} ({len(by_lang[lang])})\n\n")
            for r in by_lang[lang][:10]:
                f.write(f"- **{r[2][:100]}**\n  {r[0]} | {r[1]} | {r[3]} | q={r[5]}\n\n")
    print(f"  📝 Obsidian: {filepath}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC Bounty Collector v2")
    p.add_argument("mode", nargs="?", default="dashboard",
                   choices=["ghsa", "negatives", "dashboard", "vrt", "all"])
    p.add_argument("--days", type=int, default=7, help="Days of GHSA to collect (default: 7)")
    p.add_argument("--limit", type=int, default=30, help="Max GHSA advisories (default: 30)")
    args = p.parse_args()

    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    ensure_bounty_schema(db)

    try:
        if args.mode in ("ghsa", "all"):
            g = GhsaCollector(db)
            g.collect(days=args.days, limit=args.limit)
            export_obsidian(db)

        if args.mode in ("negatives", "all"):
            n = NegativeCollector(db)
            n.collect()

        if args.mode in ("dashboard", "all", "ghsa"):
            show_dashboard(db)

        if args.mode in ("vrt", "all"):
            v = VrtCollector(db)
            v.collect()

        if args.mode != "dashboard":
            show_dashboard(db)
    finally:
        db.close()


if __name__ == "__main__":
    main()
