# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Обработка pull_request вебхуков: debounce + очередь."""
from __future__ import annotations

from gsc_cloud import onboarding
from gsc_cloud.scan_queue import ScanQueue
from gsc_cloud.store import control_plane

queue = ScanQueue()
SCAN_ACTIONS = {"opened", "synchronize", "reopened"}


def handle_pull_request(payload: dict) -> dict:
    action = payload.get("action")
    if action not in SCAN_ACTIONS:
        return {"ok": True, "ignored_action": action}

    pr = payload["pull_request"]
    repo_payload = payload["repository"]
    installation_id = payload["installation"]["id"]
    org = repo_payload["owner"]["login"]

    tenant_id = onboarding.ensure_tenant_for_install(installation_id, org)
    repo_id = onboarding.register_repo(tenant_id, installation_id,
                                       repo_payload)

    base_repo = repo_payload["full_name"]
    head_info = (pr.get("head") or {}).get("repo", {})
    head_repo = head_info.get("full_name", "")
    head_clone_url = head_info.get("clone_url", "")
    is_fork = head_repo != base_repo
    # Fork PR: clone the *fork* head repo (its commit is not reachable in the
    # base repo), otherwise checkout head_sha fails (audit latent fork bug).
    clone_url = head_clone_url if (is_fork and head_clone_url) else repo_payload["clone_url"]

    db = control_plane(tenant_id)
    # Debounce: более ранние QUEUED-сканы этого PR помечаем superseded
    db.execute("""
        UPDATE scans SET status = 'superseded'
        WHERE tenant_id = ? AND repo_id = ?
          AND (metadata->>'pr_number')::int = ?
          AND status = 'queued'
    """, (tenant_id, repo_id, pr["number"]))

    db.execute("""
        INSERT INTO scans (tenant_id, repo_id, profile, mode, status,
                           metadata)
        VALUES (?, ?, 'pr-gate', 'diff', 'queued',
                jsonb_build_object('pr_number', ?::int, 'head_sha', ?::text,
                                   'base_ref', ?::text, 'is_fork', ?::text::boolean))
    """, (tenant_id, repo_id, pr["number"], pr["head"]["sha"],
          pr["base"]["ref"], "true" if is_fork else "false"))
    scan_id = db.fetchone(
        "SELECT currval(pg_get_serial_sequence('scans','id')) AS id")["id"]
    db.commit()

    from gsc_cloud.target_policy import validate_target
    try:
        validate_target(repo_payload["clone_url"])
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    queue.enqueue({
        "scan_id": scan_id, "tenant_id": tenant_id,
        "installation_id": installation_id,
        "repo": {"clone_url": clone_url,
                 "base_clone_url": repo_payload["clone_url"],
                 "full_name": base_repo, "gh_repo_id": repo_payload["id"]},
        "pr": {"number": pr["number"],
               "head_sha": pr["head"]["sha"],
               "base_ref": pr["base"]["ref"],
               "base_sha": pr["base"].get("sha", ""),
               "is_fork": is_fork},
        "profile": "pr-gate",
    })
    return {"ok": True, "scan_id": scan_id}