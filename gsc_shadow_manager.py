#!/usr/bin/env python3
"""
GSC Shadow Detector Manager — lifecycle for auto-generated shadow detectors.

Shadow → (≥10 verdicts, TP≥70%) → Full
Shadow → (≥10 verdicts, TP<30%) → Deactivated

Thresholds are CONSISTENT with self-learning (auto-deactivate <30% TP at ≥10 verdicts).
Single logic, not two different implementations.
"""
from __future__ import annotations

import sqlite3
from typing import Optional


class ShadowDetectorManager:
    SHADOW_TO_FULL_VERDICTS = 10
    SHADOW_TO_FULL_TP = 0.70
    DEACTIVATE_TP = 0.30

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self._ensure_table()

    def _ensure_table(self):
        """Ensure detector_status table exists (for DBs already at schema 29)."""
        try:
            self.db.executescript("""
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
            self.db.commit()
        except sqlite3.OperationalError:
            pass

    # ── Read ──────────────────────────────────────────────────────

    def get_status(self, rule_id: str) -> str:
        """Detectors without a record (GS001–GS031) default to 'full'."""
        row = self._fetchone(
            "SELECT status FROM detector_status WHERE rule_id=?", (rule_id,))
        return row["status"] if row else "full"

    def get_confidence(self, rule_id: str, default: float = 0.85) -> float:
        row = self._fetchone(
            "SELECT confidence FROM detector_status WHERE rule_id=?", (rule_id,))
        return row["confidence"] if row else default

    def is_shadow(self, rule_id: str) -> bool:
        return self.get_status(rule_id) == "shadow"

    # ── Registration ──────────────────────────────────────────────

    def register_shadow(self, rule_id: str, tp_rate: float) -> None:
        """Register a new shadow detector (from gsc_auto_detector).

        Confidence intentionally < 0.80 — below the HIGH≥0.85 blocking threshold.
        This is double protection: even if Blocking Engine doesn't check status,
        shadow findings won't block.
        """
        self.db.execute(
            "INSERT OR REPLACE INTO detector_status "
            "(rule_id, status, confidence, tp_rate, verdicts, tp_count, fp_count) "
            "VALUES (?, 'shadow', 0.75, ?, 0, 0, 0)",
            (rule_id, tp_rate))
        self.db.commit()

    # ── Verdict collection ────────────────────────────────────────

    def record_verdict(self, rule_id: str, verdict: str) -> None:
        """Called from feedback pipeline when a verdict is recorded.

        Only processes shadow detectors. Full-detector verdicts are handled
        by the existing self-learning pipeline — no duplication.
        """
        row = self._fetchone(
            "SELECT * FROM detector_status WHERE rule_id=?", (rule_id,))
        if not row or row["status"] != "shadow":
            return  # Full detectors handled by self-learning

        verdict = verdict.lower()
        tp = row["tp_count"] + (1 if verdict in ("tp", "fixed") else 0)
        fp = row["fp_count"] + (1 if verdict == "fp" else 0)
        total = tp + fp
        tp_rate = tp / total if total > 0 else 0.0

        self.db.execute(
            "UPDATE detector_status SET tp_count=?, fp_count=?, verdicts=?, "
            "tp_rate=?, updated_at=datetime('now') WHERE rule_id=?",
            (tp, fp, total, tp_rate, rule_id))
        self.db.commit()

        self._check_transitions(rule_id, total, tp_rate)

    # ── Transitions ───────────────────────────────────────────────

    def _check_transitions(self, rule_id: str, total: int, tp_rate: float):
        if total < self.SHADOW_TO_FULL_VERDICTS:
            return
        if tp_rate >= self.SHADOW_TO_FULL_TP:
            self._promote(rule_id, tp_rate)
        elif tp_rate < self.DEACTIVATE_TP:
            self._deactivate(rule_id)

    def _promote(self, rule_id: str, tp_rate: float):
        """Promote shadow → full. Confidence rises smoothly with tp_rate."""
        confidence = min(0.80 + (tp_rate - 0.70) * 0.5, 0.95)
        self.db.execute(
            "UPDATE detector_status SET status='full', confidence=?, "
            "updated_at=datetime('now') WHERE rule_id=?",
            (confidence, rule_id))
        self.db.commit()

    def _deactivate(self, rule_id: str):
        self.db.execute(
            "UPDATE detector_status SET status='deactivated', "
            "updated_at=datetime('now') WHERE rule_id=?", (rule_id,))
        self.db.commit()

    # ── Helpers ───────────────────────────────────────────────────

    def _fetchone(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        try:
            self.db.row_factory = sqlite3.Row
            return self.db.execute(query, params).fetchone()
        except sqlite3.OperationalError:
            return None
