#!/usr/bin/env python3
"""
GSC Database — SQLite wrapper with schema migrations.

Handles: findings, chains, feedback, metrics, schema versioning.
Auto-migrates on first access. Creates timestamped backups.
"""

import json, shutil, sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"
TARGET_VERSION = 19

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


class GSCDatabase:
    """Unified SQLite access for GSC findings + chains + migrations."""

    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    # ── Migration ──────────────────────────────────────────────

    def _migrate(self):
        version = self._schema_version()
        if version >= TARGET_VERSION:
            return
        self._backup()
        if version < 18:
            self.conn.executescript(SCHEMA_V018)
        if version < 19:
            self._apply_v019()
        self.conn.execute("DELETE FROM schema_version")
        self.conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)",
            (TARGET_VERSION,)
        )
        self.conn.commit()

    def _apply_v019(self):
        self.conn.execute("PRAGMA journal_mode=WAL")
        for alter in ALTERS_V019:
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

    def _schema_version(self) -> int:
        try:
            row = self.conn.execute(
                "SELECT MAX(version) AS v FROM schema_version"
            ).fetchone()
            return row["v"] or 0
        except sqlite3.OperationalError:
            return 0

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
        """Look up finding by finding_key (sha256[:12])."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE 1=0"
        ).fetchall()  # Check if table exists
        try:
            # finding_key is computed, not stored — scan all
            rows = self.conn.execute(
                "SELECT * FROM findings"
            ).fetchall()
            import hashlib
            for r in rows:
                d = dict(r)
                rule = d.get("pattern_title", d.get("rule_id", "?"))
                fp = d.get("file_path", "?")
                snippet = (d.get("detail") or d.get("title") or "")[:100]
                fk = hashlib.sha256(f"{rule}|{fp}|{snippet}".encode()).hexdigest()[:12]
                if fk == key:
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

    # ── Close ──────────────────────────────────────────────────

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
