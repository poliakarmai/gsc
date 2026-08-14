"""Tests for gsc_db_backend.py (S1) — контракт backend-абстракции.

Фиксирует поведение SqliteBackend / PgBackend / q_to_pg, чтобы подключение
server.py к backend-фабрике (трек 1.2) шло поверх проверенного фундамента.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_db_backend import q_to_pg, SqliteBackend, PgBackend


# ── q_to_pg ────────────────────────────────────────────────

def test_q_to_pg_basic():
    assert q_to_pg("SELECT * FROM t WHERE id = ?") == "SELECT * FROM t WHERE id = %s"
    assert q_to_pg("INSERT INTO t (a, b) VALUES (?, ?)") == \
        "INSERT INTO t (a, b) VALUES (%s, %s)"


def test_q_to_pg_ignores_placeholder_in_single_quotes():
    # '?' — литерал внутри строки, не плейсхолдер
    assert q_to_pg("SELECT * FROM t WHERE op = '?' AND id = ?") == \
        "SELECT * FROM t WHERE op = '?' AND id = %s"


def test_q_to_pg_ignores_placeholder_in_double_quotes():
    # "?" — идентификатор в кавычках (колонка/алиас), не плейсхолдер
    assert q_to_pg('SELECT "?" FROM t WHERE id = ?') == 'SELECT "?" FROM t WHERE id = %s'


def test_q_to_pg_no_placeholders_unchanged():
    # PostgreSQL-specific вызов без ? — возвращается как есть
    sql = "SELECT currval(pg_get_serial_sequence('repos','id'))"
    assert q_to_pg(sql) == sql


def test_q_to_pg_jsonb_exists_operator_is_not_handled():
    """Известное ограничение (документирующий тест).

    PostgreSQL JSONB-оператор `?` (exists) неотличим от плейсхолдера для q_to_pg
    и будет заменён на %s — это БАГ. Cloud-код его сейчас не использует
    (grep 'payload ?' → 0); bootstrap_roles.sql с `$$...$$` идёт через psql
    напрямую, минуя q_to_pg. Если появится JSONB-`?` — использовать `op()`/`@>`
    или научить q_to_pg отличать оператор от плейсхолдера. Тест фиксирует
    текущее поведение, чтобы будущий рефакторинг обновил его осознанно.
    """
    sql = "SELECT * FROM t WHERE payload ? 'key'"
    assert q_to_pg(sql) == "SELECT * FROM t WHERE payload %s 'key'"


# ── SqliteBackend ──────────────────────────────────────────

def test_sqlite_backend_roundtrip(tmp_path):
    db = SqliteBackend(str(tmp_path / "test.db"))
    db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute("INSERT INTO t (name) VALUES (?)", ("alice",))
    row = db.fetchone("SELECT name FROM t WHERE id = ?", (1,))
    assert row["name"] == "alice"
    rows = db.query("SELECT * FROM t")
    assert len(rows) == 1


def test_sqlite_backend_creates_parent_dir(tmp_path):
    # deep path — parent dirs создаются автоматически
    p = tmp_path / "nested" / "dir" / "x.db"
    SqliteBackend(str(p))
    assert p.exists()


# ── PgBackend ──────────────────────────────────────────────

def test_pg_backend_requires_tenant_id():
    # ValueError кидается ДО import psycopg — тест не требует установленного psycopg
    try:
        PgBackend("postgres://user@localhost/db", None)
        assert False, "ожидался ValueError"
    except ValueError as e:
        assert "tenant_id" in str(e)
