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


def test_comment_reactions_composite_key(tmp_path):
    """Schema v32 regression: PR-body публикации хранят comment_id=0, поэтому
    single-column PRIMARY KEY(comment_id) затирал их (последний INSERT писал
    поверх). Composite PK (repo, pr_number, comment_id) должен сохранять
    несколько строк с одинаковым comment_id, но разными repo/pr_number."""
    db_path = tmp_path / "audit.db"
    db = GSCDatabase(db_path)
    # три PR-body записи: comment_id=0 у всех, но разные (repo, pr_number)
    for repo, pr in (("a/b", 1), ("a/b", 2), ("c/d", 1)):
        db.conn.execute("""
            INSERT INTO comment_reactions
                (comment_id, repo, pr_number, thumbs_up, thumbs_down,
                 confused, collected_at)
            VALUES (0, ?, ?, 1, 0, 0, datetime('now'))
            ON CONFLICT(repo, pr_number, comment_id) DO UPDATE SET
                thumbs_up = excluded.thumbs_up
        """, (repo, pr))
    db.conn.commit()
    n = db.conn.execute("SELECT COUNT(*) FROM comment_reactions").fetchone()[0]
    assert n == 3, f"expected 3 rows (composite key), got {n} — reaction-loss bug"


def test_comment_reactions_composite_key_upsert(tmp_path):
    """Повторный INSERT с тем же (repo, pr_number, comment_id) делает UPDATE,
    а не дублирует строку."""
    db_path = tmp_path / "audit.db"
    db = GSCDatabase(db_path)
    args = (0, "a/b", 1)
    for _ in range(2):
        db.conn.execute("""
            INSERT INTO comment_reactions
                (comment_id, repo, pr_number, thumbs_up, thumbs_down,
                 confused, collected_at)
            VALUES (?, ?, ?, 1, 0, 0, datetime('now'))
            ON CONFLICT(repo, pr_number, comment_id) DO UPDATE SET
                thumbs_up = excluded.thumbs_up
        """, args)
    db.conn.commit()
    n = db.conn.execute("SELECT COUNT(*) FROM comment_reactions").fetchone()[0]
    assert n == 1, f"expected 1 row (upsert), got {n}"
