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
TARGET_VERSION = 18

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
        self.conn.executescript(SCHEMA_V018)
        self.conn.execute("DELETE FROM schema_version")
        self.conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)",
            (TARGET_VERSION,)
        )
        self.conn.commit()

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

    # ── Close ──────────────────────────────────────────────────

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
