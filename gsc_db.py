# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC Database — SQLite wrapper with schema migrations.

Handles: findings, chains, feedback, metrics, schema versioning.
Auto-migrates on first access. Creates timestamped backups.
"""

import json, os, re, shutil, sqlite3, hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(os.environ.get(
    "GSC_DB_PATH", str(Path.home() / ".hermes/state/gsc_audit.db")))
TARGET_VERSION = 31

# Canonical base schema (v1). These tables are the foundation every migration
# and query assumes. They MUST exist before any ALTER TABLE runs — fresh
# installs otherwise crash at v19/v29 ALTERs (audit C-03).
SCHEMA_BASE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    started_at TEXT DEFAULT (datetime('now')),
    finished_at TEXT,
    total_findings INTEGER,
    new_findings INTEGER,
    confirmed_findings INTEGER,
    model TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_runs_project ON audit_runs(project);

CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    echelon INTEGER NOT NULL CHECK(echelon BETWEEN 1 AND 3),
    title TEXT NOT NULL,
    pattern_type TEXT NOT NULL CHECK(pattern_type IN ('grep','regex','semantic','config','structural')),
    search_pattern TEXT NOT NULL,
    description TEXT,
    false_positive_count INTEGER DEFAULT 0,
    true_positive_count INTEGER DEFAULT 1,
    last_seen_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    active INTEGER DEFAULT 1,
    deactivated_at TEXT,
    effectiveness REAL,
    language TEXT,
    noise_tier TEXT DEFAULT 'normal',
    pattern_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_patterns_project ON patterns(project, echelon);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES audit_runs(id),
    project TEXT NOT NULL,
    echelon INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    detail TEXT,
    pattern_id INTEGER REFERENCES patterns(id),
    status TEXT DEFAULT 'open' CHECK(status IN ('open','confirmed','false_positive','fixed','by_design')),
    fixed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    reviewed_at TEXT,
    pattern_title TEXT,
    noise_tier TEXT DEFAULT 'normal',
    revalidation_verdict TEXT,
    revalidation_reasoning TEXT,
    revalidation_checked_at TEXT,
    revalidation_git_fixed TEXT,
    pattern_fingerprint TEXT,
    resolved_at TEXT,
    mutation_parent TEXT,
    resolved_by TEXT,
    current_state TEXT DEFAULT 'new',
    state_updated_at TEXT,
    revalidation_reason TEXT,
    revalidated_at TEXT,
    confidence_score REAL,
    rule_id TEXT,
    finding_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project, status);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(pattern_fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_resolved ON findings(resolved_at);
CREATE INDEX IF NOT EXISTS idx_findings_key ON findings(finding_key);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT DEFAULT '',
    source TEXT DEFAULT 'cli',
    actor TEXT DEFAULT '',
    pr_number INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_feedback_key ON feedback(finding_key);
CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON feedback(verdict);

CREATE TABLE IF NOT EXISTS file_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT,
    status TEXT DEFAULT 'pending',
    candidates_count INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    last_scan_run TEXT,
    last_scan_at TEXT,
    locked_by_run_id TEXT,
    analysis_history TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(project, file_path)
);
CREATE INDEX IF NOT EXISTS idx_file_state_project ON file_state(project, status);
CREATE INDEX IF NOT EXISTS idx_file_state_locked ON file_state(locked_by_run_id);
"""

SCHEMA_V018 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chains (
    chain_key        TEXT PRIMARY KEY,
    target           TEXT,
    profile          TEXT,
    finding_keys     TEXT NOT NULL,
    composed_severity TEXT NOT NULL,
    confidence       REAL NOT NULL,
    narrative        TEXT,
    steps            TEXT,
    preconditions    TEXT,
    status           TEXT NOT NULL DEFAULT 'open',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT,
    feedback_at      TEXT,
    feedback_reason  TEXT
);

CREATE INDEX IF NOT EXISTS idx_chains_status ON chains(status);
CREATE INDEX IF NOT EXISTS idx_chains_target ON chains(target);
"""

SCHEMA_V019 = """
CREATE TABLE IF NOT EXISTS mutation_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL,
    parent_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    similarity REAL NOT NULL,
    detected_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(finding_key, parent_key)
);

CREATE INDEX IF NOT EXISTS idx_mutation_finding
    ON mutation_alerts(finding_key);

CREATE TABLE IF NOT EXISTS finding_sightings (
    finding_key TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_mode TEXT NOT NULL,
    seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sightings_key
    ON finding_sightings(finding_key);
CREATE INDEX IF NOT EXISTS idx_sightings_target
    ON finding_sightings(target, seen_at);
"""

ALTERS_V019 = [
    "ALTER TABLE findings ADD COLUMN pattern_fingerprint TEXT",
    "ALTER TABLE findings ADD COLUMN resolved_at TEXT",
    "ALTER TABLE findings ADD COLUMN resolved_by TEXT",
]

INDEXES_V019 = [
    "CREATE INDEX IF NOT EXISTS idx_findings_resolved "
    "ON findings(resolved_at)",
    "CREATE INDEX IF NOT EXISTS idx_findings_fp "
    "ON findings(pattern_fingerprint)",
]

SCHEMA_V021 = """
CREATE TABLE IF NOT EXISTS published_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    comment_id INTEGER NOT NULL,
    head_sha TEXT,
    finding_keys TEXT,
    rollout_phase TEXT,
    truncated INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(repo, pr_number)
);

CREATE TABLE IF NOT EXISTS publication_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT,
    pr_number INTEGER,
    event TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pub_events_created
    ON publication_events(created_at);

CREATE TABLE IF NOT EXISTS comment_reactions (
    comment_id INTEGER PRIMARY KEY,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    thumbs_up INTEGER NOT NULL DEFAULT 0,
    thumbs_down INTEGER NOT NULL DEFAULT 0,
    confused INTEGER NOT NULL DEFAULT 0,
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

ALTERS_V022 = [
    "ALTER TABLE feedback ADD COLUMN source TEXT DEFAULT 'cli'",
    "ALTER TABLE feedback ADD COLUMN actor TEXT DEFAULT ''",
    "ALTER TABLE feedback ADD COLUMN pr_number INTEGER",
]

INDEXES_V022 = [
    "CREATE INDEX IF NOT EXISTS idx_feedback_key "
    "ON feedback(finding_key)",
    "CREATE INDEX IF NOT EXISTS idx_feedback_verdict "
    "ON feedback(verdict)",
]


SCHEMA_V024 = """
CREATE TABLE IF NOT EXISTS secret_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    repo_count INTEGER DEFAULT 1,
    total_sightings INTEGER DEFAULT 1,
    rotated INTEGER DEFAULT 0,
    rotation_detected_at TEXT,
    status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS secret_sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    prev_fingerprint TEXT,
    next_fingerprint TEXT,
    seen_at TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES secret_fingerprints(fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_sightings_repo ON secret_sightings(repo_path);
CREATE INDEX IF NOT EXISTS idx_sightings_fp ON secret_sightings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_sightings_loc
    ON secret_sightings(repo_path, file_path, line_number);

"""

# Schema v24 alters
ALTERS_V024 = """
ALTER TABLE findings ADD COLUMN autofixed INTEGER DEFAULT 0;
"""

SCHEMA_V028 = """
CREATE TABLE IF NOT EXISTS epss_cache (
    cve_id TEXT PRIMARY KEY,
    epss REAL NOT NULL,
    percentile REAL NOT NULL,
    epss_date TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_epss_fetched ON epss_cache(fetched_at);
"""

SCHEMA_V027 = """
CREATE TABLE IF NOT EXISTS federated_global_weights (
    rule_id TEXT PRIMARY KEY,
    global_tp_rate REAL NOT NULL,
    global_verdicts INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS federated_deactivated (
    rule_id TEXT PRIMARY KEY,
    reason TEXT,
    deactivated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS federated_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA_V026 = """
CREATE TABLE IF NOT EXISTS sca_cache (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    vulns_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (ecosystem, package, version)
);
"""

SCHEMA_V025 = """
CREATE TABLE IF NOT EXISTS nuclei_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    tags TEXT,
    requests TEXT NOT NULL,
    matchers TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_templates(severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_tags ON nuclei_templates(tags);

CREATE TABLE IF NOT EXISTS dast_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_at TEXT,
    evidence TEXT,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sightings_loc
    ON secret_sightings(repo_path, file_path, line_number);
"""

# Schema v24 alters
ALTERS_V024 = """
ALTER TABLE findings ADD COLUMN autofixed INTEGER DEFAULT 0;
"""

SCHEMA_V028 = """
CREATE TABLE IF NOT EXISTS epss_cache (
    cve_id TEXT PRIMARY KEY,
    epss REAL NOT NULL,
    percentile REAL NOT NULL,
    epss_date TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_epss_fetched ON epss_cache(fetched_at);
"""

SCHEMA_V027 = """
CREATE TABLE IF NOT EXISTS federated_global_weights (
    rule_id TEXT PRIMARY KEY,
    global_tp_rate REAL NOT NULL,
    global_verdicts INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS federated_deactivated (
    rule_id TEXT PRIMARY KEY,
    reason TEXT,
    deactivated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS federated_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA_V026 = """
CREATE TABLE IF NOT EXISTS sca_cache (
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    vulns_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (ecosystem, package, version)
);
"""

SCHEMA_V025 = """
CREATE TABLE IF NOT EXISTS nuclei_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    tags TEXT,
    requests TEXT NOT NULL,
    matchers TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_templates(severity);
CREATE INDEX IF NOT EXISTS idx_nuclei_tags ON nuclei_templates(tags);

CREATE TABLE IF NOT EXISTS dast_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_at TEXT,
    evidence TEXT,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_dast_target ON dast_findings(target_url, scanned_at);
"""

SCHEMA_V023 = """
CREATE TABLE IF NOT EXISTS overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    finding_key TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    UNIQUE(repo, pr_number, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_overrides_pr
    ON overrides(repo, pr_number);
"""


def compute_finding_key(rule: str, file_path: str, snippet: str) -> str:
    """Stable finding key = sha256(rule|file|snippet)[:12] (invariant #1).

    MUST match get_finding exactly. ``rule`` = pattern_title or rule_id or "?",
    ``snippet`` = (detail or title)[:100]. Every INSERT path that feeds this
    lookup must compute the same key or lookups silently miss (audit A-05).
    """
    rule = rule or "?"
    file_path = file_path or "?"
    snippet = (snippet or "")[:100]
    return hashlib.sha256(f"{rule}|{file_path}|{snippet}".encode()).hexdigest()[:12]


class GSCDatabase:
    """Unified SQLite access for GSC findings + chains + migrations."""

    def __init__(self, path: Path = DB_PATH):
        self.path = path
        # Ensure parent dir exists — CI runners may not have ~/.hermes/state/
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass  # fall through to connect() which will raise a clear error
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    # ── Migration ──────────────────────────────────────────────

    def _migrate(self):
        self._ensure_base_schema()
        version = self._schema_version()
        if version >= TARGET_VERSION:
            return
        self._backup()
        if version < 18:
            self.conn.executescript(SCHEMA_V018)
        if version < 19:
            self._apply_v019()
        if version < 21:
            self._apply_v021()
        if version < 22:
            self._apply_v022()
        if version < 23:
            self._apply_v023()
        if version < 24:
            self._apply_v024()
        if version < 25:
            self._apply_v025()
        if version < 26:
            self._apply_v026()
        if version < 27:
            self._apply_v027()
        if version < 28:
            self._apply_v028()
        if version < 29:
            self._apply_v029()
        if version < 30:
            self._apply_v030()
        if version < 31:
            self._apply_v031()
        self.conn.execute("DELETE FROM schema_version")
        self.conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)",
            (TARGET_VERSION,)
        )
        self.conn.commit()

    def _ensure_base_schema(self):
        """Create base tables if absent (fresh install). Idempotent.

        Fixes audit C-03: the migration chain assumed findings/audit_runs/
        patterns/feedback/file_state already existed, so a clean checkout
        crashed at the first ALTER TABLE. This creates them up-front.
        """
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
        if row:
            return
        self.conn.executescript(SCHEMA_BASE)
        self.conn.commit()

    def _add_column_if_missing(self, table: str, column: str, definition: str):
        """Idempotent ALTER TABLE ADD COLUMN (audit C-04)."""
        cols = {r["name"] for r in self.conn.execute(
            f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            self.conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _apply_v019(self):
        self.conn.execute("PRAGMA journal_mode=WAL")
        for alter in ALTERS_V019:
            # "ALTER TABLE findings ADD COLUMN <col> <type>" — parse and route
            # through _add_column_if_missing so fresh + partial DBs are safe.
            m = re.match(r"ALTER TABLE (\w+) ADD COLUMN (\w+) (.+)", alter, re.I)
            if m:
                self._add_column_if_missing(m.group(1), m.group(2), m.group(3))
            else:
                try:
                    self.conn.execute(alter)
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e).lower():
                        raise
        self.conn.executescript(SCHEMA_V019)
        for idx in INDEXES_V019:
            try:
                self.conn.execute(idx)
            except sqlite3.OperationalError:
                pass

    def _apply_v021(self):
        self.conn.executescript(SCHEMA_V021)

    def _apply_v023(self):
        self.conn.executescript(SCHEMA_V023)

    def _apply_v022(self):
        for alter in ALTERS_V022:
            m = re.match(r"ALTER TABLE (\w+) ADD COLUMN (\w+) (.+)", alter, re.I)
            if m:
                self._add_column_if_missing(m.group(1), m.group(2), m.group(3))
            else:
                try:
                    self.conn.execute(alter)
                except sqlite3.OperationalError:
                    pass
        for idx in INDEXES_V022:
            try:
                self.conn.execute(idx)
            except sqlite3.OperationalError:
                pass


    def _schema_version(self) -> int:
        try:
            row = self.conn.execute(
                "SELECT MAX(version) AS v FROM schema_version"
            ).fetchone()
            return row["v"] or 0
        except sqlite3.OperationalError:
            return 0

    def _apply_v024(self):
        """Schema v24: cross-repo secret fingerprints + sightings."""
        self.conn.executescript(SCHEMA_V024)
        # autofixed column — apply idempotently (was previously never applied)
        self._add_column_if_missing("findings", "autofixed", "INTEGER DEFAULT 0")

    def _apply_v028(self):
        """Schema v28: epss_cache for EPSS exploitability lookups."""
        self.conn.executescript(SCHEMA_V028)

    def _apply_v029(self):
        """Schema v29: finding state machine + verification tracking + detector_status."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS finding_states (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_key     TEXT NOT NULL,
                from_state      TEXT NOT NULL DEFAULT 'new',
                to_state        TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                actor           TEXT NOT NULL DEFAULT '',
                comment         TEXT DEFAULT '',
                attempt         INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (finding_key) REFERENCES findings(finding_key)
            );
            CREATE INDEX IF NOT EXISTS idx_finding_states_key
                ON finding_states(finding_key, created_at);
            CREATE INDEX IF NOT EXISTS idx_finding_states_state
                ON finding_states(to_state, created_at);

            CREATE TABLE IF NOT EXISTS verify_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_key     TEXT NOT NULL,
                result          TEXT NOT NULL,
                attempt         INTEGER DEFAULT 1,
                max_attempts    INTEGER DEFAULT 2,
                ready_for_pr    INTEGER DEFAULT 0,
                error_message   TEXT DEFAULT '',
                rescan_count    INTEGER DEFAULT 0,
                test_passed     INTEGER DEFAULT 0,
                dast_count      INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (finding_key) REFERENCES findings(finding_key)
            );
            CREATE INDEX IF NOT EXISTS idx_verify_results_key
                ON verify_results(finding_key, created_at);

            CREATE TABLE IF NOT EXISTS detector_status (
                rule_id         TEXT PRIMARY KEY,
                status          TEXT NOT NULL DEFAULT 'full',
                confidence      REAL DEFAULT 0.85,
                tp_rate         REAL DEFAULT 0.0,
                verdicts        INTEGER DEFAULT 0,
                tp_count        INTEGER DEFAULT 0,
                fp_count        INTEGER DEFAULT 0,
                created_at      TEXT DEFAULT (datetime('now')),
                updated_at      TEXT DEFAULT (datetime('now'))
            );
        """)
        # Idempotent column adds (audit C-04) — previously raw ALTER TABLE,
        # which crashed on re-run / fresh DB with "duplicate column name".
        self._add_column_if_missing("findings", "current_state", "TEXT DEFAULT 'new'")
        self._add_column_if_missing("findings", "state_updated_at", "TEXT")
        self._add_column_if_missing("findings", "rule_id", "TEXT")

    def _apply_v030(self):
        """Schema v30: pattern_status for per-pattern precision tracking (GS005 decomposition)."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS pattern_status (
                pattern_id        TEXT PRIMARY KEY,
                rule_id           TEXT NOT NULL,
                enabled           INTEGER NOT NULL DEFAULT 1,
                measured_precision REAL,
                true_positives    INTEGER DEFAULT 0,
                false_positives   INTEGER DEFAULT 0,
                sample_size       INTEGER DEFAULT 0,
                disabled_reason   TEXT,
                disabled_at       TEXT,
                updated_at        TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_pattern_status_rule
                ON pattern_status(rule_id, enabled);
        """)

    def _apply_v031(self):
        """Schema v31: finding_key column + index + backfill (audit A-05)."""
        self._add_column_if_missing("findings", "finding_key", "TEXT")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_key ON findings(finding_key)")
        # Backfill legacy rows (finding_key NULL) in chunks — idempotent.
        try:
            rows = self.conn.execute(
                "SELECT id, pattern_title, rule_id, file_path, detail, title "
                "FROM findings WHERE finding_key IS NULL").fetchall()
            for i, r in enumerate(rows):
                fk = compute_finding_key(
                    r["pattern_title"] or r["rule_id"],
                    r["file_path"],
                    (r["detail"] or r["title"] or ""),
                )
                self.conn.execute(
                    "UPDATE findings SET finding_key=? WHERE id=?", (fk, r["id"]))
                if i % 10000 == 0:
                    self.conn.commit()
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

    def _apply_v027(self):
        """Schema v27: federated learning tables."""
        self.conn.executescript(SCHEMA_V027)

    def _apply_v026(self):
        """Schema v26: sca_cache for OSV.dev responses."""
        self.conn.executescript(SCHEMA_V026)

    def _apply_v025(self):
        """Schema v25: nuclei_templates + dast_findings for SAST+DAST hybrid."""
        self.conn.executescript(SCHEMA_V025)

    def _backup(self):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = f"{self.path}.bak-v018-{stamp}"
        shutil.copy2(self.path, dst)
        print(f"[DB] Backup: {dst}")

    # ── Chains ─────────────────────────────────────────────────

    def save_chain(self, chain, target: str, profile: str):
        """Upsert chain. chain is an AttackChain or dict with same keys."""
        self.conn.execute("""
            INSERT INTO chains (chain_key, target, profile, finding_keys,
                composed_severity, confidence, narrative, steps,
                preconditions, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(chain_key) DO UPDATE SET
                confidence = excluded.confidence,
                narrative  = excluded.narrative,
                steps      = excluded.steps,
                updated_at = excluded.updated_at
        """, (
            chain.chain_key if hasattr(chain, 'chain_key') else chain["chain_key"],
            target, profile,
            json.dumps(chain.finding_keys if hasattr(chain, 'finding_keys') else chain.get("finding_keys", [])),
            (chain.composed_severity if hasattr(chain, 'composed_severity') else chain.get("composed_severity", "HIGH")),
            (chain.confidence if hasattr(chain, 'confidence') else chain.get("confidence", 0.7)),
            (chain.narrative if hasattr(chain, 'narrative') else chain.get("narrative", "")),
            json.dumps(chain.steps if hasattr(chain, 'steps') else chain.get("steps", [])),
            json.dumps(chain.preconditions if hasattr(chain, 'preconditions') else chain.get("preconditions", [])),
        ))
        self.conn.commit()

    def get_chain(self, chain_key: str):
        return self.conn.execute(
            "SELECT * FROM chains WHERE chain_key = ?", (chain_key,)
        ).fetchone()

    def query_chains(self, target: str = None, status: str = None,
                     limit: int = 100) -> list:
        sql = "SELECT * FROM chains WHERE 1=1"
        params = []
        if target:
            sql += " AND target = ?"
            params.append(target)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def feedback_chain(self, chain_key: str, verdict: str, reason: str = ""):
        self.conn.execute("""
            UPDATE chains SET status = ?, feedback_at = datetime('now'),
                feedback_reason = ? WHERE chain_key = ?
        """, (verdict, reason, chain_key))
        self.conn.commit()

    def chain_stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) c FROM chains").fetchone()["c"]
        tp = self.conn.execute(
            "SELECT COUNT(*) c FROM chains WHERE status='tp'").fetchone()["c"]
        fp = self.conn.execute(
            "SELECT COUNT(*) c FROM chains WHERE status='fp'").fetchone()["c"]
        return {
            "total": total, "tp": tp, "fp": fp,
            "verdicts": tp + fp,
            "tp_rate": round(tp / (tp + fp), 2) if (tp + fp) else None,
        }

    # ── Findings ───────────────────────────────────────────────

    def get_finding(self, key: str):
        """Look up finding by finding_key (sha256[:12]).

        O(1) via the ``finding_key`` index; falls back to a scan of legacy
        rows that predate the column (finding_key NULL).
        """
        try:
            row = self.conn.execute(
                "SELECT * FROM findings WHERE finding_key=?", (key,)
            ).fetchone()
            if row:
                return dict(row)
        except sqlite3.OperationalError:
            return None
        # Fallback: legacy rows without a stored finding_key (NULL) — rare.
        try:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE finding_key IS NULL"
            ).fetchall()
            for r in rows:
                d = dict(r)
                rule = d.get("pattern_title") or d.get("rule_id")
                fp = d.get("file_path")
                snippet = (d.get("detail") or d.get("title") or "")
                if compute_finding_key(rule, fp, snippet) == key:
                    return d
        except sqlite3.OperationalError:
            pass
        return None

    def count_findings(self) -> int:
        try:
            return self.conn.execute(
                "SELECT COUNT(*) c FROM findings").fetchone()["c"]
        except sqlite3.OperationalError:
            return 0

    def count_revalidated(self) -> int:
        try:
            return self.conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE revalidation_verdict IS NOT NULL"
            ).fetchone()["c"]
        except sqlite3.OperationalError:
            return 0

    # ── Generic query / execute (used by mutation tracker) ──

    def query(self, sql: str, params=()):
        """Return cursor for read queries."""
        return self.conn.execute(sql, params)

    def execute(self, sql: str, params=()):
        """Execute write SQL."""
        self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()

    # ── v0.19: Mutation tracking ──────────────────────────────

    def record_sighting(self, finding_key: str, target: str, scan_mode: str):
        self.conn.execute(
            "INSERT INTO finding_sightings(finding_key, target, scan_mode) "
            "VALUES (?, ?, ?)", (finding_key, target, scan_mode))

    def save_alert(self, alert):
        """alert is MutationAlert dataclass or dict."""
        fk = alert.finding_key if hasattr(alert, 'finding_key') else alert["finding_key"]
        pk = alert.parent_key if hasattr(alert, 'parent_key') else alert["parent_key"]
        kd = alert.kind if hasattr(alert, 'kind') else alert["kind"]
        sm = alert.similarity if hasattr(alert, 'similarity') else alert["similarity"]
        self.conn.execute("""
            INSERT OR IGNORE INTO mutation_alerts
                (finding_key, parent_key, kind, similarity)
            VALUES (?, ?, ?, ?)
        """, (fk, pk, kd, sm))
        self.conn.commit()

    def mutation_stats(self) -> dict:
        def _count(table, where=""):
            try:
                sql = f"SELECT COUNT(*) c FROM {table}"
                if where:
                    sql += f" WHERE {where}"
                return self.conn.execute(sql).fetchone()["c"]
            except sqlite3.OperationalError:
                return 0
        return {
            "alerts_total": _count("mutation_alerts"),
            "mutations": _count("mutation_alerts", "kind='mutation'"),
            "recurrences": _count("mutation_alerts", "kind='recurrence'"),
            "resolved_90d": _count("findings",
                "resolved_at > datetime('now', '-90 days')"),
            "auto_resolved_7d": _count("findings",
                "resolved_by='auto' AND resolved_at > datetime('now', '-7 days')"),
        }

    def backfill_progress(self) -> dict:
        total = self.count_findings()
        done = 0
        try:
            done = self.conn.execute(
                "SELECT COUNT(*) c FROM findings "
                "WHERE pattern_fingerprint IS NOT NULL").fetchone()["c"]
        except sqlite3.OperationalError:
            pass
        return {
            "total": total, "done": done,
            "pct": round(done / total * 100, 1) if total else 100.0,
        }

    # ── v0.23 Phase 2: Publication registry ────────────────────

    def upsert_published_comment(self, repo: str, pr_number: int,
                                  comment_id: int, head_sha: str = "",
                                  finding_keys: list = None,
                                  rollout_phase: str = "",
                                  truncated: int = 0):
        keys_json = json.dumps(finding_keys or [])
        self.conn.execute("""
            INSERT INTO published_comments
                (repo, pr_number, comment_id, head_sha, finding_keys,
                 rollout_phase, truncated, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(repo, pr_number) DO UPDATE SET
                comment_id = excluded.comment_id,
                head_sha = excluded.head_sha,
                finding_keys = excluded.finding_keys,
                rollout_phase = excluded.rollout_phase,
                truncated = excluded.truncated,
                updated_at = excluded.updated_at
        """, (repo, pr_number, comment_id, head_sha, keys_json,
              rollout_phase, truncated))
        self.conn.commit()

    def record_publication_event(self, repo: str, pr_number: int,
                                  event: str, detail: str = ""):
        self.conn.execute("""
            INSERT INTO publication_events (repo, pr_number, event, detail)
            VALUES (?, ?, ?, ?)
        """, (repo, pr_number, event, detail))
        self.conn.commit()

    def phase2_stats(self, days: int = 14) -> dict:
        window = f"-{days} days"
        pub = self.query("""
            SELECT COUNT(*) AS comments, SUM(truncated) AS truncated
            FROM published_comments
            WHERE updated_at > datetime('now', ?)
        """, (window,)).fetchone()
        events = self.query("""
            SELECT event, COUNT(*) AS n FROM publication_events
            WHERE created_at > datetime('now', ?)
            GROUP BY event
        """, (window,)).fetchall()
        react = self.query("""
            SELECT COALESCE(SUM(thumbs_up),0) AS up,
                   COALESCE(SUM(thumbs_down),0) AS down,
                   COALESCE(SUM(confused),0) AS confused
            FROM comment_reactions
            WHERE collected_at > datetime('now', ?)
        """, (window,)).fetchone()
        neg = react["down"] + react["confused"]
        total_r = neg + react["up"]
        return {
            "comments_published": pub["comments"] or 0,
            "truncated": pub["truncated"] or 0,
            "events": {r["event"]: r["n"] for r in events},
            "reactions": {"up": react["up"], "down": react["down"],
                          "confused": react["confused"]},
            "negative_rate": round(neg / total_r, 3) if total_r else None,
        }


    # ── v0.24 Phase 3: Feedback with source tracking ──────────

    def record_feedback(self, finding_key: str, verdict: str, reason: str = "",
                        source: str = "cli", actor: str = "",
                        pr_number: int = None):
        """Upsert: latest verdict per (finding_key, actor) wins."""
        with self.conn:  # transaction: delete+insert are atomic
            self.conn.execute(
                "DELETE FROM feedback WHERE finding_key = ? AND actor = ?",
                (finding_key, actor))
            self.conn.execute("""
                INSERT INTO feedback
                    (finding_key, verdict, reason, source, actor, pr_number,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (finding_key, verdict, reason[:500], source, actor,
                  pr_number))

    def detector_tp_rates(self) -> list[dict]:
        """TP-rate per detector. fixed counts as positive signal."""
        try:
            rows = self.query("""
                SELECT f.pattern_title AS rule_id, fb.verdict, COUNT(*) AS n
                FROM feedback fb
                JOIN findings f ON f.id = fb.finding_key
                GROUP BY f.pattern_title, fb.verdict
            """).fetchall()
        except sqlite3.OperationalError:
            return []
        agg: dict = {}
        for r in rows:
            rid = str(r["rule_id"] or "").split()[0] if r["rule_id"] else "?"
            det = rid.split("-")[0] if "-" in rid else rid
            a = agg.setdefault(det, {"tp": 0, "fp": 0, "fixed": 0})
            v = r["verdict"]
            if v in a:
                a[v] += r["n"]
        out = []
        for det, a in sorted(agg.items()):
            verdicts = a["tp"] + a["fp"] + a["fixed"]
            positive = a["tp"] + a["fixed"]
            rate = positive / verdicts if verdicts else None
            out.append({
                "detector": det,
                "verdicts": verdicts,
                **a,
                "tp_rate": round(rate, 3) if rate is not None else None,
                "blocking_ready": bool(
                    verdicts >= 10 and rate is not None and rate >= 0.70),
            })
        return out


    # ── v0.25 Phase 4: Overrides ────────────────────────────

    def upsert_override(self, repo, pr_number, finding_key, actor, reason,
                        ttl_days: int = 30):
        with self.conn:
            self.conn.execute("""
                INSERT INTO overrides
                    (repo, pr_number, finding_key, actor, reason, expires_at)
                VALUES (?, ?, ?, ?, ?, datetime('now', ?))
                ON CONFLICT(repo, pr_number, finding_key) DO UPDATE SET
                    actor = excluded.actor,
                    reason = excluded.reason,
                    created_at = datetime('now'),
                    expires_at = excluded.expires_at
            """, (repo, pr_number, finding_key, actor, reason[:300],
                  f"+{ttl_days} days"))

    def active_overrides(self, repo, pr_number) -> set:
        try:
            rows = self.query("""
                SELECT finding_key FROM overrides
                WHERE repo = ? AND pr_number = ?
                  AND expires_at > datetime('now')
            """, (repo, pr_number)).fetchall()
            return {r["finding_key"] for r in rows}
        except sqlite3.OperationalError:
            return set()


    # ── v0.26 Phase 5: Blocking stats ──────────────────────

    def phase5_stats(self, days: int = 14) -> dict:
        window = f"-{days} days"
        fb = self.query("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN verdict = 'fp' THEN 1 ELSE 0 END) AS fp
            FROM feedback
            WHERE created_at > datetime('now', ?)
        """, (window,)).fetchone()
        from . import phase5_stats as _ps
        events = {}
        try:
            rows = self.query("""
                SELECT event, COUNT(*) AS n FROM publication_events
                WHERE created_at > datetime('now', ?)
                GROUP BY event
            """, (window,)).fetchall()
            events = {r["event"]: r["n"] for r in rows}
        except Exception:
            pass
        return {
            "blocks": events.get("blocking", 0),
            "chain_blocks": events.get("chain_block", 0),
            "overrides": events.get("override", 0),
            "fp_on_recent": fb["fp"] or 0,
            "verdicts_recent": fb["total"] or 0,
        }

    def count_events(self, event_type: str) -> int:
        try:
            row = self.query(
                "SELECT COUNT(*) AS n FROM publication_events WHERE event = ?",
                (event_type,)).fetchone()
            return row["n"] if row else 0
        except Exception:
            return 0

    def count_feedback(self) -> int:
        try:
            return self.query(
                "SELECT COUNT(*) AS n FROM feedback").fetchone()["n"] or 0
        except Exception:
            return 0

    # ── Close ──────────────────────────────────────────────────

    # ── v29 State Machine ──────────────────────────────────

    def log_state_transition(self, finding_key: str, from_state: str,
                              to_state: str, event_type: str,
                              actor: str = "", comment: str = "",
                              attempt: int = 0):
        """Record immutable state transition. finding_key = pattern_fingerprint or id."""
        self.conn.execute("""
            INSERT INTO finding_states (finding_key, from_state, to_state,
                event_type, actor, comment, attempt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (finding_key, from_state, to_state, event_type, actor, comment, attempt))

        # Update current state on the finding row (match by pattern_fingerprint)
        self.conn.execute("""
            UPDATE findings SET current_state = ?, state_updated_at = datetime('now')
            WHERE pattern_fingerprint = ?
        """, (to_state, finding_key))
        self.conn.commit()

    def get_current_state(self, finding_key: str) -> str:
        row = self.query(
            "SELECT current_state FROM findings WHERE pattern_fingerprint = ?",
            (finding_key,)).fetchone()
        return row["current_state"] if row else "new"

    def get_state_history(self, finding_key: str) -> list[dict]:
        rows = self.query("""
            SELECT * FROM finding_states WHERE finding_key = ?
            ORDER BY created_at
        """, (finding_key,)).fetchall()
        return [dict(r) for r in rows]

    def save_verify_result(self, finding_key: str, result: str,
                           attempt: int = 1, ready_for_pr: bool = False,
                           error_message: str = "", rescan_count: int = 0,
                           test_passed: bool = False, dast_count: int = 0):
        self.conn.execute("""
            INSERT INTO verify_results (finding_key, result, attempt,
                ready_for_pr, error_message, rescan_count, test_passed, dast_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding_key, result, attempt, int(ready_for_pr),
              error_message, rescan_count, int(test_passed), dast_count))
        self.conn.commit()

    def get_verify_history(self, finding_key: str) -> list[dict]:
        rows = self.query("""
            SELECT * FROM verify_results WHERE finding_key = ?
            ORDER BY created_at DESC
        """, (finding_key,)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
