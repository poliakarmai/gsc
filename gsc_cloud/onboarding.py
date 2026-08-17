# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Маппинг GitHub installation → tenant. PLG: первая установка
создаёт free-тенант автоматически."""
from __future__ import annotations

from gsc_cloud.store import control_plane


def ensure_tenant_for_install(installation_id: int,
                              org_login: str) -> int:
    db = control_plane()
    row = db.fetchone(
        "SELECT tenant_id FROM github_installs WHERE installation_id = ?",
        (installation_id,))
    if row:
        return row["tenant_id"]
    db.execute("INSERT INTO tenants (name, plan) VALUES (?, 'free')",
               (org_login,))
    tenant_id = db.fetchone(
        "SELECT currval(pg_get_serial_sequence('tenants','id')) AS id")["id"]
    db.execute("""
        INSERT INTO github_installs (tenant_id, installation_id, org_login)
        VALUES (?, ?, ?)
    """, (tenant_id, installation_id, org_login))
    db.commit()
    return tenant_id


def register_repo(tenant_id: int, installation_id: int,
                  repo_payload: dict) -> int:
    db = control_plane(tenant_id)
    gh_id = repo_payload["id"]
    row = db.fetchone("SELECT id FROM repos WHERE tenant_id = ? "
                      "AND gh_repo_id = ?", (tenant_id, gh_id))
    if row:
        return row["id"]
    install = control_plane().fetchone(
        "SELECT id FROM github_installs WHERE installation_id = ?",
        (installation_id,))
    db.execute("""
        INSERT INTO repos (tenant_id, name, clone_url, gh_repo_id, install_id)
        VALUES (?, ?, ?, ?, ?)
    """, (tenant_id, repo_payload["full_name"],
          repo_payload["clone_url"], gh_id, install["id"]))
    db.commit()
    return db.fetchone(
        "SELECT currval(pg_get_serial_sequence('repos','id')) AS id")["id"]