# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""tests/test_fp_log.py — schema v33 fp_log: migration + record_fp + fp_stats.

FP-специфичный контракт (SARD/Juliet-подход): каждая точка деактивации
(triage FP, auto-deactivate, federated) обязана писать структурированное
событие в fp_log, чтобы self-learning и noise-аналитика имели источник правды.
"""
import os


def _open_db():
    from gsc_db import GSCDatabase
    return GSCDatabase()


def test_fp_log_table_created_on_migration():
    from gsc_db import GSCDatabase, TARGET_VERSION
    db = _open_db()
    try:
        assert db._schema_version() == TARGET_VERSION
        tables = {r["name"] for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "fp_log" in tables, "fp_log table missing after v33 migration"
    finally:
        db.close()


def test_record_fp_and_fp_stats_ordering():
    db = _open_db()
    try:
        db.record_fp(
            finding_id=1, finding_key="abc123", pattern_id=5,
            rule_id="GS000-LEGACY", reason="quality_issue",
            comment="assert is code-quality, not security",
            action_taken="soft_disabled_pattern", source="test",
        )
        db.record_fp(
            finding_id=2, pattern_id=5, rule_id="GS000-LEGACY",
            reason="false_positive", action_taken="marked_fp", source="test",
        )
        db.record_fp(
            rule_id="GS021", reason="auto_deactivated",
            action_taken="federated_deactivated", source="federated",
        )

        stats = db.fp_stats()
        by_rule = {s["rule_id"]: s for s in stats}
        assert by_rule["GS000-LEGACY"]["fp_count"] == 2
        assert by_rule["GS021"]["fp_count"] == 1
        # noisiest rule first
        assert stats[0]["rule_id"] == "GS000-LEGACY"
        # reasons/actions are aggregated, comma-separated
        assert "quality_issue" in by_rule["GS000-LEGACY"]["reasons"]
        assert "soft_disabled_pattern" in by_rule["GS000-LEGACY"]["actions"]
    finally:
        db.close()


def test_fp_stats_days_window():
    db = _open_db()
    try:
        db.record_fp(rule_id="GS037", reason="false_positive",
                     action_taken="marked_fp", source="test")
        assert len(db.fp_stats(days=7)) >= 1
    finally:
        db.close()
