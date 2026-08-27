# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GitLab MR adapter glue (Phase 15 — RF Enterprise)."""

from unittest import mock

from gsc_cli.gsc_gitlab_adapter import build_mr_note_body, run_gitlab_mr_adapter
from gsc_cli.gsc_gitlab_mr_context import GitLabMRContext


def _ctx() -> GitLabMRContext:
    return GitLabMRContext(
        host="gitlab.example.com",
        project_path="group/proj",
        mr_iid=12,
        api_base="https://gitlab.example.com/api/v4",
        valid=True,
    )


def test_build_mr_note_body_contains_marker_header_summary():
    body = build_mr_note_body(_ctx(), "summary here", "found XSS")
    assert "<!-- gsc:scan:group/proj:12 -->" in body
    assert "MR !12" in body
    assert "summary here" in body
    assert "### Findings" in body
    assert "found XSS" in body


def test_build_mr_note_body_no_findings_section_when_empty():
    body = build_mr_note_body(_ctx(), "summary")
    assert "### Findings" not in body


def test_run_gitlab_mr_adapter_bad_url_returns_2():
    assert run_gitlab_mr_adapter("not-a-url") == 2


def test_run_gitlab_mr_adapter_missing_token_returns_3(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    url = "https://gitlab.com/group/proj/-/merge_requests/12"
    assert run_gitlab_mr_adapter(url) == 3


def test_run_gitlab_mr_adapter_dry_run_returns_0(monkeypatch, capsys):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    url = "https://gitlab.com/group/proj/-/merge_requests/12"
    assert run_gitlab_mr_adapter(url, dry_run=True) == 0
    assert "[dry-run]" in capsys.readouterr().out


def test_run_gitlab_mr_adapter_success_upserts(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    url = "https://gitlab.com/group/proj/-/merge_requests/12"
    with mock.patch("gsc_cli.gsc_gitlab_adapter.upsert_note", return_value=99) as m:
        assert run_gitlab_mr_adapter(url) == 0
        m.assert_called_once()
