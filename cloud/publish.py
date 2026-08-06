"""Публикация результата в PR: комментарий + check run.

Переиспользует gsc_github_adapter v0.23: priority truncation,
redaction audit, phase-aware check conclusion, upsert по маркеру.
"""
from __future__ import annotations

from gsc_github_adapter import GithubPRAdapter


def publish_pr_result(job: dict, report: dict, headers: dict) -> None:
    adapter = GithubPRAdapter(
        repo=job["repo"]["full_name"],
        pr_number=job["pr"]["number"],
        head_sha=job["pr"]["head_sha"],
        token=headers["Authorization"].removeprefix("Bearer "),
    )
    # Адаптер сам: redaction audit → upsert комментария → check run
    adapter.publish(report)