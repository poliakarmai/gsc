#!/usr/bin/env python3
"""Federated Aggregation Server — central service for cross-tenant learning."""
import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

DB = Path.home() / ".hermes" / "state" / "federated_server.db"

def get_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS federated_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_hash TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            tp_count INTEGER NOT NULL,
            fp_count INTEGER NOT NULL,
            submitted_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_fedsub_rule ON federated_submissions(rule_id);
        CREATE TABLE IF NOT EXISTS federated_global_weights (
            rule_id TEXT PRIMARY KEY,
            global_tp_rate REAL NOT NULL,
            global_verdicts INTEGER NOT NULL,
            tenant_count INTEGER NOT NULL,
            computed_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)
    return conn

class FederatedServer:
    def __init__(self, db):
        self.db = db

    def submit(self, tenant_hash: str, metrics: dict) -> int:
        n = 0
        for rule_id, counts in metrics.items():
            tp = max(0, int(counts.get("tp", 0)))
            fp = max(0, int(counts.get("fp", 0)))
            if tp + fp == 0: continue
            self.db.execute("""INSERT INTO federated_submissions (tenant_hash, rule_id, tp_count, fp_count)
                VALUES (?, ?, ?, ?)""", (tenant_hash, rule_id, tp, fp))
            n += 1
        self.db.commit()
        return n

    def compute_weights(self, min_total_verdicts: int = 10):
        rows = self.db.execute("""SELECT rule_id, SUM(tp_count) AS total_tp, SUM(fp_count) AS total_fp,
            COUNT(DISTINCT tenant_hash) AS tenant_count FROM federated_submissions
            GROUP BY rule_id HAVING (SUM(tp_count) + SUM(fp_count)) >= ?""",
            (min_total_verdicts,)).fetchall()
        for r in rows:
            total = r["total_tp"] + r["total_fp"]
            tp_rate = r["total_tp"] / total if total else 0.0
            self.db.execute("""INSERT OR REPLACE INTO federated_global_weights
                (rule_id, global_tp_rate, global_verdicts, tenant_count, computed_at)
                VALUES (?, ?, ?, ?, datetime('now'))""",
                (r["rule_id"], tp_rate, total, r["tenant_count"]))
        self.db.commit()

    def get_weights(self) -> dict:
        rows = self.db.execute("SELECT * FROM federated_global_weights").fetchall()
        return {r["rule_id"]: {"tp_rate": r["global_tp_rate"], "verdicts": r["global_verdicts"],
                "tenants": r["tenant_count"]} for r in rows}
