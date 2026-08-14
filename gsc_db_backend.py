"""Database backends for GSC (S1).

SqliteBackend — внутренний контур (single-machine), дефолт для dev.
PgBackend     — cloud, ОБЯЗАТЕЛЬНО с tenant_id; выставляет app.tenant_id
                для PostgreSQL Row-Level Security (двойная защита).

Единый API (server.py переходит на него — трек 1.2):
    query(sql, params)      -> list[Row]     (SELECT, много строк)
    fetchone(sql, params)   -> Row | None    (SELECT, одна строка)
    execute(sql, params)    -> int rowcount  (INSERT/UPDATE/DELETE/DDL; коммитит)
    insert_id(sql, params)  -> int | None    (INSERT ... RETURNING id)
    executescript(sql)      -> None          (много-выражений DDL)
    commit() / close()

Row = sqlite3.Row (SqliteBackend) или dict (PgBackend, psycopg dict_row) —
в обоих случаях доступ по ключу row["col"].
"""
from __future__ import annotations

import sqlite3
from typing import Any, List, Optional


def q_to_pg(sql: str) -> str:
    """Конвертирует '?' плейсхолдеры в '%s', не трогая литералы в кавычках.

    Ограничение: PostgreSQL JSONB-оператор `?` (exists) неотличим от плейсхолдера
    и будет заменён на %s — для JSONB-`?` используй `@>`/`op()`. `$$...$$`
    (bootstrap_roles.sql) идёт через psql напрямую, минуя эту функцию.
    """
    out: List[str] = []
    in_single = in_double = False
    for ch in sql:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        out.append("%s" if ch == "?" and not in_single and not in_double
                   else ch)
    return "".join(out)


class SqliteBackend:
    """Drop-in backend поверх sqlite3 для внутреннего контура."""

    def __init__(self, path: str, read_only: bool = False):
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if read_only:
            self.conn = sqlite3.connect(f"file:{path}?immutable=1", uri=True,
                                        check_same_thread=False)
        else:
            self.conn = sqlite3.connect(path, check_same_thread=False)
            # parity с историческим server.py (concurrent readers + WAL)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.row_factory = sqlite3.Row

    def query(self, sql: str, params: tuple = ()) -> List[Any]:
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()):
        return self.conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple = ()) -> int:
        try:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.rowcount
        except Exception:
            self.conn.rollback()
            raise

    def insert_id(self, sql: str, params: tuple = (), id_col: str = "id"):
        """INSERT ... RETURNING id — portable (SQLite 3.35+ поддерживает RETURNING)."""
        try:
            row = self.conn.execute(sql, params).fetchone()
            self.conn.commit()
            if row is None:
                return None
            return row[id_col] if id_col in row.keys() else row[0]
        except Exception:
            self.conn.rollback()
            raise

    def executescript(self, sql: str):
        try:
            self.conn.executescript(sql)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


class PgBackend:
    """Cloud backend: psycopg3 + RLS-контекст app.tenant_id."""

    def __init__(self, dsn: str, tenant_id: int):
        if tenant_id is None:
            raise ValueError("PgBackend requires tenant_id")
        import psycopg
        from psycopg.rows import dict_row
        self.tenant_id = tenant_id
        self.conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        # RLS-контекст: даже при ошибке в SQL чужой тенант не читается.
        # SET не поддерживает параметры $1 — интерполяция безопасна (int).
        self.conn.execute(f"SET app.tenant_id = {int(tenant_id)}")

    def query(self, sql: str, params: tuple = ()) -> List[Any]:
        return self.conn.execute(q_to_pg(sql), params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()):
        return self.conn.execute(q_to_pg(sql), params).fetchone()

    def execute(self, sql: str, params: tuple = ()) -> int:
        try:
            cur = self.conn.execute(q_to_pg(sql), params)
            self.conn.commit()
            return cur.rowcount
        except Exception:
            self.conn.rollback()
            raise

    def insert_id(self, sql: str, params: tuple = (), id_col: str = "id"):
        try:
            row = self.conn.execute(q_to_pg(sql), params).fetchone()
            self.conn.commit()
            if row is None:
                return None
            return row.get(id_col) if isinstance(row, dict) else row[0]
        except Exception:
            self.conn.rollback()
            raise

    def executescript(self, sql: str):
        # PostgreSQL: нет executescript — выполняем выражения по одному.
        try:
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    self.conn.execute(q_to_pg(stmt))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()
