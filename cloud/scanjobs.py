"""Обработка pull_request вебхуков: debounce + очередь."""
from __future__ import annotations

from cloud import onboarding
from cloud.scan_queue import ScanQueue
from cloud.store import control_plane

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
    head_repo = (pr.get("head") or {}).get("repo", {}).get("full_name", "")
    is_fork = head_repo != base_repo

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

    queue.enqueue({
        "scan_id": scan_id, "tenant_id": tenant_id,
        "installation_id": installation_id,
        "repo": {"clone_url": repo_payload["clone_url"],
                 "full_name": base_repo, "gh_repo_id": repo_payload["id"]},
        "pr": {"number": pr["number"],
               "head_sha": pr["head"]["sha"],
               "base_ref": pr["base"]["ref"],
               "is_fork": is_fork},
        "profile": "pr-gate",
    })
    return {"ok": True, "scan_id": scan_id}