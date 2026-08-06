# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
"""
GSC Database — SQLite wrapper with schema migrations.

Handles: findings, chains, feedback, metrics, schema versioning.
Auto-migrates on first access. Creates timestamped backups.
"""

import json, os, shutil, sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(os.environ.get(
    "GSC_DB_PATH", str(Path.home() / ".hermes/state/gsc_audit.db")))
TARGET_VERSION = 25

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

    def _apply_v021(self):
        self.conn.executescript(SCHEMA_V021)

    def _apply_v023(self):
        self.conn.executescript(SCHEMA_V023)

    def _apply_v022(self):
        # Safe: check if feedback table exists before ALTER
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'"
        ).fetchone()
        if not row:
            return  # feedback table doesn't exist yet — skip
        for alter in ALTERS_V022:
            try:
                self.conn.execute(alter)
            except sqlite3.OperationalError:
                pass  # column already exists
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

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
