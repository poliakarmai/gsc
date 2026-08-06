# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""Control plane storage (PostgreSQL only).

Тенант-данные читаются через PgBackend(tenant_id) — RLS + явный фильтр.
Служебные таблицы (tenants, api_keys, usage) — через control_plane().
"""
from __future__ import annotations

import os
from typing import Optional

from gsc_db_backend import PgBackend


def control_plane(tenant_id: Optional[int] = None) -> PgBackend:
    """Соединение для служебных таблиц. tenant_id — только для записи
    в тенант-данные; служебные запросы идут с tenant_id=0-маркером."""
    return PgBackend(os.environ["GSC_DATABASE_URL"], tenant_id or 0)


def _tenant_db(tenant_id: int) -> PgBackend:
    return PgBackend(os.environ["GSC_DATABASE_URL"], tenant_id)


# ----------------------------------------------------------------------
# repos / scans
# ----------------------------------------------------------------------
def get_or_create_repo(db: PgBackend, tenant_id: int,
                       clone_url: str) -> int:
    name = clone_url.rstrip("/").split("/")[-1]
    row = db.fetchone("SELECT id FROM repos WHERE tenant_id = ? AND name = ?",
                      (tenant_id, name))
    if row:
        return row["id"]
    db.execute("INSERT INTO repos (tenant_id, name, clone_url) "
               "VALUES (?, ?, ?)", (tenant_id, name, clone_url))
    return db.fetchone("SELECT currval(pg_get_serial_sequence('repos','id')) "
                       "AS id")["id"]


def create_scan(db: PgBackend, tenant_id: int, repo_id: int,
                profile: str) -> int:
    db.execute("""
        INSERT INTO scans (tenant_id, repo_id, profile, status)
        VALUES (?, ?, ?, 'queued')
    """, (tenant_id, repo_id, profile))
    return db.fetchone("SELECT currval(pg_get_serial_sequence('scans','id')) "
                       "AS id")["id"]


def get_scan(db: PgBackend, scan_id: int):
    return db.fetchone("SELECT * FROM scans WHERE id = ? "
                       "AND tenant_id = ?", (scan_id, db.tenant_id))


def set_scan_status(db: PgBackend, scan_id: int, status: str):
    db.execute("UPDATE scans SET status = ? WHERE id = ? AND tenant_id = ?",
               (status, scan_id, db.tenant_id))


# ----------------------------------------------------------------------
# findings / verdicts
# ----------------------------------------------------------------------
def list_findings(db: PgBackend, scan_id: int, limit: int = 200):
    return db.query("""
        SELECT finding_key, rule_id, severity, confidence, file, line,
               snippet, poc, metadata
        FROM findings
        WHERE scan_id = ? AND tenant_id = ?
        ORDER BY id LIMIT ?
    """, (scan_id, db.tenant_id, limit))


def finding_exists(db: PgBackend, tenant_id: int, finding_key: str) -> bool:
    row = db.fetchone("SELECT 1 AS x FROM findings WHERE tenant_id = ? "
                      "AND finding_key = ? LIMIT 1",
                      (tenant_id, finding_key))
    return row is not None


# ----------------------------------------------------------------------
# quota / metering (PG-only функции: now(), date_trunc)
# ----------------------------------------------------------------------
def check_quota(db: PgBackend, tenant_id: int) -> bool:
    tenant = db.fetchone("SELECT scan_limit_month FROM tenants WHERE id = ?",
                         (tenant_id,))
    if not tenant:
        return False
    used = db.fetchone("""
        SELECT scans FROM usage
        WHERE tenant_id = ?
          AND period = date_trunc('month', now())::date
    """, (tenant_id,))
    return (used["scans"] if used else 0) < tenant["scan_limit_month"]


def meter(db: PgBackend, tenant_id: int, report: dict) -> None:
    usage = report.get("usage", {})
    db.execute("""
        INSERT INTO usage (tenant_id, period, scans, llm_calls)
        VALUES (?, date_trunc('month', now())::date, 1, ?)
        ON CONFLICT (tenant_id, period) DO UPDATE SET
            scans = usage.scans + 1,
            llm_calls = usage.llm_calls + excluded.llm_calls
    """, (tenant_id, usage.get("llm_calls", 0)))