"""Database backends for GSC (S1).

SqliteBackend — существующий внутренний контур (tenant_id = 0).
PgBackend     — cloud, ОБЯЗАТЕЛЬНО с tenant_id; выставляет app.tenant_id
                для PostgreSQL Row-Level Security (двойная защита).
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
    """Обёртка над текущим gsc_db.py поведением."""

    def __init__(self, path: str):
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

    def query(self, sql: str, params: tuple = ()) -> List[Any]:
        return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()):
        return self.conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple = ()):
        with self.conn:
            self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()


class PgBackend:
    def __init__(self, dsn: str, tenant_id: int):
        if tenant_id is None:
            raise ValueError("PgBackend requires tenant_id")
        import psycopg
        from psycopg.rows import dict_row
        self.tenant_id = tenant_id
        self.conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        # RLS-контекст: даже при ошибке в SQL чужой тенант не читается
        # SET не поддерживает параметры $1 — интерполяция безопасна (int)
        self.conn.execute(f"SET app.tenant_id = {int(tenant_id)}")

    def query(self, sql: str, params: tuple = ()) -> List[Any]:
        return self.conn.execute(q_to_pg(sql), params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()):
        return self.conn.execute(q_to_pg(sql), params).fetchone()

    def execute(self, sql: str, params: tuple = ()):
        self.conn.execute(q_to_pg(sql), params)

    def commit(self):
        self.conn.commit()