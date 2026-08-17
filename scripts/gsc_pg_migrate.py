#!/usr/bin/env python3
"""GSC S1.3 — миграция SQLite cloud DB → PostgreSQL (идемпотентно).

Порядок: tenants → api_keys → scan_jobs → findings → sessions.
Каждая таблица переносится через INSERT ... ON CONFLICT DO NOTHING — повторный
запуск не дублирует строки.

Использование:
    GSC_DB=/path/to/gsc_cloud.db GSC_DATABASE_URL=postgres://user:pass@host/db \
        python3 scripts/gsc_pg_migrate.py [--skip-schema]

    --skip-schema  не применять cloud/schema_runtime.sql (уже применён вручную)
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gsc_cloud.gsc_db_backend import SqliteBackend, PgBackend

_SCHEMA_RUNTIME = Path(__file__).resolve().parents[1] / "cloud" / "schema_runtime.sql"


def _sqlite_path() -> str:
    return os.environ.get("GSC_DB", str(Path.home() / ".gsc" / "gsc_cloud.db"))


def _apply_schema(dst: PgBackend) -> None:
    dst.executescript(_SCHEMA_RUNTIME.read_text())
    print(f"✅ schema_runtime.sql применена ({_SCHEMA_RUNTIME.name})", flush=True)


def _copy(dst: PgBackend, table: str, cols: str, sql: str, rows) -> int:
    n = 0
    for r in rows:
        dst.execute(sql, tuple(r[c] for c in cols.split(",")))
        n += 1
    return n


def migrate(src: SqliteBackend, dst: PgBackend) -> dict:
    stats: dict = {}

    stats["tenants"] = _copy(
        dst, "tenants", "id,name,github_user,plan,scans_used,created_at",
        "INSERT INTO tenants (id, name, github_user, plan, scans_used, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        src.query("SELECT id, name, github_user, plan, scans_used, created_at FROM tenants"),
    )

    stats["api_keys"] = _copy(
        dst, "api_keys", "id,tenant_id,key_hash,key_prefix,created_at,revoked_at",
        "INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, created_at, revoked_at) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        src.query("SELECT id, tenant_id, key_hash, key_prefix, created_at, revoked_at FROM api_keys"),
    )

    stats["scan_jobs"] = _copy(
        dst, "scan_jobs", "id,tenant_id,target,profile,status,findings_count,created_at,completed_at",
        "INSERT INTO scan_jobs (id, tenant_id, target, profile, status, findings_count, "
        "created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        src.query("SELECT id, tenant_id, target, profile, status, findings_count, "
                  "created_at, completed_at FROM scan_jobs"),
    )

    stats["findings"] = _copy(
        dst, "findings", "finding_key,rule_id,title,severity,confidence,file,line,snippet,tenant_id,created_at",
        "INSERT INTO findings (finding_key, rule_id, title, severity, confidence, file, line, "
        "snippet, tenant_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (tenant_id, finding_key) DO NOTHING",
        src.query("SELECT finding_key, rule_id, title, severity, confidence, file, line, "
                  "snippet, tenant_id, created_at FROM findings"),
    )

    stats["sessions"] = _copy(
        dst, "sessions", "token,tenant_id,github_user,expires_at,created_at",
        "INSERT INTO sessions (token, tenant_id, github_user, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (token) DO NOTHING",
        src.query("SELECT token, tenant_id, github_user, expires_at, created_at FROM sessions"),
    )

    return stats


def _fix_sequences(dst: PgBackend) -> None:
    """Сброс BIGSERIAL sequence после вставки явных id (иначе следующий INSERT
    без id падает с duplicate key — sequence не знает про мигрированные строки)."""
    for table in ("tenants", "api_keys"):
        dst.execute(
            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
            f"(SELECT COALESCE(MAX(id), 1) FROM {table}))"
        )
    dst.commit()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--skip-schema", action="store_true",
                   help="не применять cloud/schema_runtime.sql")
    args = p.parse_args()

    dsn = os.environ.get("GSC_DATABASE_URL")
    if not dsn:
        print("❌ GSC_DATABASE_URL не задан (например postgres://user:pass@host/db)")
        return 2

    src_path = _sqlite_path()
    if not Path(src_path).exists():
        print(f"❌ SQLite источник не найден: {src_path}")
        return 2

    src = SqliteBackend(src_path)
    dst = PgBackend(dsn, tenant_id=0)

    if not args.skip_schema:
        _apply_schema(dst)

    stats = migrate(src, dst)
    dst.commit()
    _fix_sequences(dst)

    print("\n=== Миграция завершена ===", flush=True)
    total = 0
    for table, n in stats.items():
        print(f"  {table:<12} {n} строк обработано", flush=True)
        total += n
    print(f"  {'ИТОГО':<12} {total} строк", flush=True)

    # verify
    for table in ("tenants", "api_keys", "scan_jobs", "findings", "sessions"):
        cnt = dst.fetchone(f"SELECT COUNT(*) as c FROM {table}")["c"]
        print(f"  pg.{table:<10} = {cnt} строк", flush=True)

    src.close()
    dst.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
