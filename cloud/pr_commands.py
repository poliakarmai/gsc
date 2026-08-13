# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""/gsc-команды через issue_comment webhook (S2)."""
from __future__ import annotations

import requests

from cloud.github_auth import gh_headers
from cloud.store import control_plane
from scripts.gsc_pr_commands import (ALLOWED_ASSOCIATIONS, parse_commands)


def handle_issue_comment(payload: dict) -> dict:
    if not payload.get("issue", {}).get("pull_request"):
        return {"ok": True, "not_a_pr": True}
    comment = payload.get("comment", {})
    body = comment.get("body", "") or ""
    if not body.lstrip().startswith("/gsc "):
        return {"ok": True}

    commands = parse_commands(body)
    if not commands:
        return {"ok": True, "no_commands": True}
    if comment.get("author_association") not in ALLOWED_ASSOCIATIONS:
        return {"ok": True, "ignored_author": True}

    installation_id = payload["installation"]["id"]
    row = control_plane().fetchone(
        "SELECT tenant_id FROM github_installs WHERE installation_id = ?",
        (installation_id,))
    if not row:
        return {"ok": True, "no_tenant": True}
    tenant_id = row["tenant_id"]

    db = control_plane(tenant_id)
    pr_number = payload["issue"]["number"]
    repo_id = db.fetchone(
        "SELECT id FROM repos WHERE tenant_id = ? AND gh_repo_id = ?",
        (tenant_id, payload["repository"]["id"]))["id"]
    actor = (comment.get("user") or {}).get("login", "")[:60]

    applied = []
    for cmd in commands:
        if cmd["verdict"] == "override":
            if not cmd["reason"]:
                continue          # override без причины запрещён (v0.25)
            db.execute("""
                INSERT INTO overrides
                    (tenant_id, repo_id, pr_number, finding_key, actor,
                     reason, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, now() + interval '30 days')
                ON CONFLICT (tenant_id, repo_id, pr_number, finding_key)
                DO UPDATE SET reason = excluded.reason,
                              actor = excluded.actor,
                              expires_at = excluded.expires_at
            """, (tenant_id, repo_id, pr_number, cmd["finding_key"],
                  actor, cmd["reason"]))
        else:
            db.execute("""
                INSERT INTO verdicts
                    (tenant_id, finding_key, actor, verdict, reason, source)
                VALUES (?, ?, ?, ?, ?, 'pr-reply')
            """, (tenant_id, cmd["finding_key"], actor, cmd["verdict"],
                  cmd["reason"]))
        applied.append(cmd["finding_key"])
    db.commit()

    # Подтверждение: реакция +1 на комментарий
    if applied:
        try:
            requests.post(
                f"https://api.github.com/repos/"
                f"{payload['repository']['full_name']}/issues/comments/"
                f"{comment['id']}/reactions",
                headers=gh_headers(installation_id),
                json={"content": "+1"}, timeout=10)
        except requests.RequestException:
            pass                  # реакция не критична
    return {"ok": True, "applied": applied}