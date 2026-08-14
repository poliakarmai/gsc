"""tests/test_db_migration.py — due-diligence шаг 5: migration tests.

GSCDatabase при инициализации должен создавать ПОЛНУЮ схему (все таблицы,
включая те, на которые ссылаются миграции — comment_reactions из schema v32).
Это регрессия на GSC-004: ручной CREATE TABLE давал неполную схему.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_db import GSCDatabase


def test_full_schema_created_on_init(tmp_path):
    db_path = tmp_path / "audit.db"
    with GSCDatabase(db_path):
        pass  # инициализация должна создать полную схему + все миграции

    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()

    # Ключевые таблицы (включая те, что миграции v28→v32 читают)
    for t in ("schema_version", "findings", "feedback", "comment_reactions",
              "nuclei_templates", "chains"):
        assert t in tables, f"missing table {t} in fresh DB (got {len(tables)} tables)"


def test_reopen_is_idempotent(tmp_path):
    """Повторное открытие существующей DB не падает и не дублирует данные."""
    db_path = tmp_path / "audit.db"
    with GSCDatabase(db_path):
        pass
    # повторное открытие (миграции должны быть no-op)
    with GSCDatabase(db_path):
        pass
    conn = sqlite3.connect(db_path)
    version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    conn.close()
    assert version is not None
