"""tests/test_backup_restore.py — GSC roadmap 4.11: backup/restore drill.

Проверяет, что online backup (scripts/gsc_backup.py) создаёт целостный снапшот
и restore возвращает БД к состоянию на момент снапшота.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.gsc_backup import backup, restore, verify  # noqa: E402


def _seed(path: Path, rows: int) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, tenant_id INTEGER)")
    conn.execute("DELETE FROM findings")
    conn.executemany(
        "INSERT INTO findings (tenant_id) VALUES (?)", [(i, ) for i in range(rows)]
    )
    conn.commit()
    conn.close()


def test_backup_restore_drill(tmp_path):
    live = tmp_path / "cloud.db"
    snap = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"

    # 1. seed 10 rows + backup
    _seed(live, 10)
    backup(str(live), str(snap))

    # snapshot должен совпадать с live
    td, rd, tb, rb = verify(str(live), str(snap))
    assert (td, rd) == (tb, rb), f"backup mismatch: {td}/{rd} vs {tb}/{rb}"

    # 2. изменить live (ещё 5 rows)
    _seed(live, 15)

    # 3. restore snapshot в отдельный файл
    restore(str(restored), str(snap))
    _, _, tr, rr = verify(str(restored), str(snap))
    assert (tr, rr) == (tb, rb), "restored != snapshot"

    # restored должен содержать именно 10 rows (состояние на момент backup)
    conn = sqlite3.connect(str(restored))
    n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()
    assert n == 10, f"restored has {n} rows, expected 10 (backup-time state)"
