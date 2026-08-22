# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Публикация результата в PR: комментарий + check run.

Переиспользует gsc_github_adapter v0.15 (реальный API): GitHubAPIClient +
upsert_comment + create_check_run + conclusion_from_result. Ранее ссылался на
несуществующий `GithubPRAdapter` (v0.23) → ImportError (tail fix).

Redaction: тело комментария/чек-рана прогоняется через gsc_external.redact, плюс
audit_all как fail-safe — GS001/GS017 пишут сырой matched-секрет в detail.
"""
from __future__ import annotations

from gsc_external import redact
from gsc_github_adapter import (
    GitHubAPIClient,
    GitHubPRContext,
    audit_all,
    conclusion_from_result,
    create_check_run,
    upsert_comment,
)


def _build_comment_body(report: dict) -> str:
    """Build a markdown PR comment from the scan report findings."""
    findings = report.get("findings", [])
    if not findings:
        return "✅ **GSC Security Scan** — новых находок нет."
    lines = [f"🔒 **GSC Security Scan** — {len(findings)} находок:\n"]
    for f in findings:
        sev = f.get("severity") or f.get("category") or "UNKNOWN"
        rid = f.get("rule_id") or f.get("pattern_title") or "?"
        loc = (f"{f.get('file') or f.get('file_path') or ''}:"
               f"{f.get('line') or f.get('line_number') or 0}")
        snippet = (f.get("snippet") or f.get("detail") or "").strip().replace("\n", " ")[:120]
        mark = "🚫" if f.get("blocking") else "⚠️"
        lines.append(f"- {mark} **{sev}** `{rid}` — `{loc}` {snippet}")
    return "\n".join(lines)


def publish_pr_result(job: dict, report: dict, headers: dict) -> None:
    """Post a PR comment + check run for a completed scan (S2 GitHub mode).

    Args:
        job: enqueued job dict (repo.full_name, pr.number, pr.head_sha, pr.base_ref,
             pr.is_fork).
        report: gsc external-scan JSON (findings + usage + optional policy.rollout_phase).
        headers: gh_headers(installation_id) → {"Authorization": "Bearer <token>"}.
    """
    token = headers["Authorization"].removeprefix("Bearer ")
    full_name = job["repo"]["full_name"]
    owner, _, repo = full_name.partition("/")

    ctx = GitHubPRContext(
        owner=owner,
        repo=repo,
        pr_number=job["pr"]["number"],
        base_ref=job["pr"].get("base_ref", "main"),
        head_sha=job["pr"]["head_sha"],
    )
    client = GitHubAPIClient(token)

    body = redact(_build_comment_body(report))
    leaks = audit_all(body, check_summary=body)
    if leaks["total"]:
        print(f"⚠️ Redaction leak in PR output: {leaks['total']} issue(s)", flush=True)

    upsert_comment(client, ctx, body)

    findings = report.get("findings", [])
    blocking = sum(1 for f in findings if f.get("blocking"))
    warnings = sum(1 for f in findings if not f.get("blocking"))
    phase = ((report.get("policy") or {}).get("rollout_phase")) or "warn-only"
    safe_mode = bool(job["pr"].get("is_fork"))
    conclusion = conclusion_from_result(
        blocking=blocking, warnings=warnings, safe_mode=safe_mode, phase=phase)
    create_check_run(client, ctx, conclusion, body)
