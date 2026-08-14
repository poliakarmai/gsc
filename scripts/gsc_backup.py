#!/usr/bin/env python3
"""GSC roadmap 4.11: backup/restore drill для SQLite cloud DB.

Использует нативный online backup (``sqlite3.Connection.backup``) — безопасен при
WAL и активных reader'ах, не блокирует writer'ов, не требует остановки сервиса.

Команды:
    backup   — снять снапшот БД в файл (по умолчанию ~/.gsc/backups/<ts>.db)
    restore  — восстановить БД из снапшота (drill: в отдельный файл, не на живую)
    verify   — сравнить число таблиц и строк между БД и снапшотом

Запуск:
    python3 scripts/gsc_backup.py backup
    python3 scripts/gsc_backup.py restore --db /tmp/restored.db --from <snapshot>
    python3 scripts/gsc_backup.py verify  --db <db> --from <snapshot>
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = os.environ.get(
    "GSC_DB", str(Path.home() / ".gsc" / "gsc_cloud.db")
)
DEFAULT_BACKUP_DIR = Path.home() / ".gsc" / "backups"


def backup(db_path: str, out_path: str) -> str:
    """Online backup db_path → out_path. Возвращает путь снапшота."""
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(out_path)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close()
        dst.close()
    return out_path


def restore(db_path: str, from_path: str) -> str:
    """Restore db_path из снапшота from_path (online backup в обратную сторону)."""
    src = sqlite3.connect(from_path)
    dst = sqlite3.connect(db_path)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close()
        dst.close()
    return db_path


def _counts(path: str) -> tuple[int, int]:
    """(число таблиц, суммарное число строк) для сверки целостности."""
    conn = sqlite3.connect(path)
    try:
        tables = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        total = 0
        for t in tables:
            total += conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        return len(tables), total
    finally:
        conn.close()


def verify(db_path: str, from_path: str) -> tuple[int, int, int, int]:
    """Сравнить БД и снапшот; вернуть (tables_db, rows_db, tables_bak, rows_bak)."""
    td, rd = _counts(db_path)
    tb, rb = _counts(from_path)
    return td, rd, tb, rb


def main() -> int:
    ap = argparse.ArgumentParser(description="GSC SQLite backup/restore drill")
    ap.add_argument("cmd", choices=["backup", "restore", "verify"])
    ap.add_argument("--db", default=DEFAULT_DB, help="live DB path")
    ap.add_argument("--out", default=None, help="snapshot path (backup)")
    ap.add_argument("--from", dest="from_path", default=None, help="snapshot path (restore/verify)")
    args = ap.parse_args()

    if args.cmd == "backup":
        out = args.out or str(
            DEFAULT_BACKUP_DIR / f"gsc_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.db"
        )
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        backup(args.db, out)
        td, rd = _counts(args.db)
        print(f"✅ backup: {args.db} → {out} ({td} tables, {rd} rows)")
        return 0

    if args.cmd == "restore":
        if not args.from_path:
            print("restore требует --from <snapshot>", file=sys.stderr)
            return 2
        restore(args.db, args.from_path)
        td, rd = _counts(args.db)
        print(f"✅ restore: {args.from_path} → {args.db} ({td} tables, {rd} rows)")
        return 0

    # verify
    if not args.from_path:
        print("verify требует --from <snapshot>", file=sys.stderr)
        return 2
    td, rd, tb, rb = verify(args.db, args.from_path)
    ok = (td == tb) and (rd == rb)
    print(f"verify: db({td} tables, {rd} rows) vs snapshot({tb} tables, {rb} rows) → "
          f"{'MATCH' if ok else 'MISMATCH'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
