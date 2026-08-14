"""tests/test_backend_unified.py — GSC roadmap 4.1: единый storage backend.

server.py (SQLite local-only) и cloud/ (PostgreSQL production) — это один cloud
contour на уровне storage: оба идут через общий интерфейс ``gsc_db_backend``
(query/fetchone/execute/executescript/insert_id/close). Тест фиксирует паритет
интерфейса, чтобы рефакторинг любого контура не рассинхронизировал их.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gsc_db_backend import PgBackend, SqliteBackend  # noqa: E402

INTERFACE = ["query", "fetchone", "execute", "executescript", "insert_id", "close"]


def test_backends_share_interface():
    """Оба backend'а обязаны экспортировать один и тот же контракт."""
    for cls in (SqliteBackend, PgBackend):
        missing = [m for m in INTERFACE if not hasattr(cls, m)]
        assert not missing, f"{cls.__name__} missing: {missing}"


def test_sqlite_backend_roundtrip(tmp_path):
    """SQLite roundtrip через общий контракт (insert_id → query)."""
    db = SqliteBackend(str(tmp_path / "u.db"))
    db.executescript("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
    rid = db.insert_id("INSERT INTO t (v) VALUES (?) RETURNING id", ("hello",))
    row = db.fetchone("SELECT v FROM t WHERE id=?", (rid,))
    assert row["v"] == "hello"
    db.close()


def test_pg_backend_has_tenant_scoping(tmp_path, monkeypatch):
    """PgBackend принимает tenant_id (RLS) — без реального соединения, только контракт."""
    import inspect
    sig = inspect.signature(PgBackend.__init__)
    assert "tenant_id" in sig.parameters, "PgBackend должен принимать tenant_id для RLS"
