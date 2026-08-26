#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
tests/test_rf_git_adapter.py — tests for the Russian self-hosted git adapters
(GitLab / GitFlic / GitVerse). Phase 14.

These tests exercise ``gsc_cli.gsc_rf_git_adapter`` with mocked HTTP traffic
(``unittest.mock.patch`` on ``requests.Session.request``) and patched
environment variables (``unittest.mock.patch.dict(os.environ, ...)``).

Test layout:

  * Construction & validation
  * Issue create / note create / MR create / list projects
  * Env-driven factories (gitlab / gitflic / gitverse)
  * Network & HTTP error paths
  * Doctor diagnostics
"""

import os
import sys
import json

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ".")

import pytest
from unittest.mock import patch, MagicMock

from gsc_cli.gsc_rf_git_adapter import (
    RFGitAdapter,
    PLATFORM_GITLAB,
    PLATFORM_GITFLIC,
    PLATFORM_GITVERSE,
    DEFAULT_GITLAB_URL,
    DEFAULT_GITFLIC_URL,
    DEFAULT_GITVERSE_URL,
    gitlab_adapter,
    gitflic_adapter,
    gitverse_adapter,
    create_gitlab_issue_v2,
    create_gitflic_issue,
    create_gitverse_issue,
)


# --- Helpers ---

def _mock_response(status_code=201, json_payload=None, text=None):
    """Build a MagicMock that quacks like a requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_payload is not None:
        resp.json.return_value = json_payload
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = text if text is not None else json.dumps(json_payload or {})
    return resp


def _build_adapter(platform=PLATFORM_GITLAB):
    """Build a pre-configured adapter pointing at a fake host."""
    return RFGitAdapter(
        api_url="https://git.example.com",
        token="dummy-token-123",
        platform=platform,
    )


# --- Construction & validation ---

def test_construct_requires_api_url():
    with pytest.raises(ValueError):
        RFGitAdapter(api_url="", token="x", platform=PLATFORM_GITLAB)


def test_construct_requires_token():
    with pytest.raises(ValueError):
        RFGitAdapter(api_url="https://git.example.com", token="",
                     platform=PLATFORM_GITLAB)


def test_url_strips_trailing_slash():
    a = RFGitAdapter(api_url="https://git.example.com/", token="t",
                     platform=PLATFORM_GITLAB)
    assert a.api_url == "https://git.example.com"


def test_encode_project_id_numeric():
    assert RFGitAdapter._encode_project_id("42") == "42"


def test_encode_project_id_path():
    # GitLab group/subgroup/project path → URL-encoded
    encoded = RFGitAdapter._encode_project_id("group/subgroup/project")
    assert "/" not in encoded
    assert encoded == "group%2Fsubgroup%2Fproject"


# --- create_issue ---

def test_create_issue_success():
    adapter = _build_adapter()
    issue_payload = {
        "id": 100, "iid": 5, "project_id": 1, "title": "X",
        "web_url": "https://git.example.com/g/p/-/issues/5",
    }
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(201, issue_payload)) as m:
        data = adapter.create_issue("1", "Test Title", "Test Description",
                                    labels=["security"])
    assert data is not None
    assert data["iid"] == 5
    assert m.called
    # CRITICAL: requests.post(url, ...) passes url POSITIONALLY.
    # In the mock, args[0] is the URL, args[1] is method="" default in our
    # request() signature, so check that the URL path was hit.
    url = m.call_args.args[1] if m.call_args.args else m.call_args.kwargs.get("url")
    assert url is not None
    assert url.endswith("/api/v4/projects/1/issues")
    # Method (session.request(method, url, ...) → args[0] is the HTTP verb)
    method = (m.call_args.args[0] if m.call_args.args
              else m.call_args.kwargs.get("method"))
    assert method == "POST"
    # JSON body
    json_body = m.call_args.kwargs.get("json")
    assert json_body["title"] == "Test Title"
    assert json_body["description"] == "Test Description"
    assert json_body["labels"] == ["security"]


def test_create_issue_missing_title():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request") as m:
        data = adapter.create_issue("1", "", "desc")
    assert data is None
    assert not m.called


def test_create_issue_http_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(422, text="bad request")):
        data = adapter.create_issue("1", "T", "D")
    assert data is None


def test_create_issue_network_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      side_effect=__import__("requests").RequestException("boom")):
        data = adapter.create_issue("1", "T", "D")
    assert data is None


def test_create_issue_path_project_id():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(201, {"iid": 1,
                                                        "web_url": "x"})) as m:
        adapter.create_issue("group/sub/proj", "T", "D")
    url = m.call_args.args[1]
    assert "projects/group%2Fsub%2Fproj/issues" in url


# --- create_note ---

def test_create_note_success():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(201,
                                                 {"id": 99, "body": "hi"})
                      ) as m:
        data = adapter.create_note("1", 7, "Hello world")
    assert data is not None
    assert data["id"] == 99
    url = m.call_args.args[1]
    assert url.endswith("/api/v4/projects/1/issues/7/notes")
    assert m.call_args.kwargs["json"]["body"] == "Hello world"


def test_create_note_empty_body():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request") as m:
        data = adapter.create_note("1", 7, "")
    assert data is None
    assert not m.called


def test_create_note_oversize_body():
    adapter = _build_adapter()
    big = "x" * 1_100_000
    with patch.object(adapter.session, "request") as m:
        data = adapter.create_note("1", 7, big)
    assert data is None
    assert not m.called


def test_create_note_http_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(404, text="not found")):
        data = adapter.create_note("1", 7, "body")
    assert data is None


# --- create_merge_request ---

def test_create_merge_request_success():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(201,
                                                 {"iid": 3,
                                                  "web_url": "u"})
                      ) as m:
        data = adapter.create_merge_request(
            "1", source_branch="feat", target_branch="main",
            title="MR Title", description="desc",
            squash=True, remove_source_branch=True,
        )
    assert data is not None
    url = m.call_args.args[1]
    assert url.endswith("/api/v4/projects/1/merge_requests")
    body = m.call_args.kwargs["json"]
    assert body["source_branch"] == "feat"
    assert body["target_branch"] == "main"
    assert body["title"] == "MR Title"
    assert body["squash"] is True
    assert body["remove_source_branch"] is True


def test_create_merge_request_missing_required():
    adapter = _build_adapter()
    # No source_branch
    with patch.object(adapter.session, "request") as m:
        assert adapter.create_merge_request("1", source_branch="",
                                            target_branch="main",
                                            title="x") is None
    # No target_branch
    with patch.object(adapter.session, "request") as m:
        assert adapter.create_merge_request("1", source_branch="a",
                                            target_branch="", title="x") is None
    # No title
    with patch.object(adapter.session, "request") as m:
        assert adapter.create_merge_request("1", source_branch="a",
                                            target_branch="b",
                                            title="") is None


def test_create_merge_request_http_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(400, text="bad")):
        data = adapter.create_merge_request(
            "1", source_branch="a", target_branch="b", title="t")
    assert data is None


# --- list_projects ---

def test_list_projects_success():
    adapter = _build_adapter()
    projects = [{"id": 1, "path_with_namespace": "g/p"},
                {"id": 2, "path_with_namespace": "g/q"}]
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(200, projects)) as m:
        data = adapter.list_projects(membership=True, per_page=50)
    assert isinstance(data, list)
    assert len(data) == 2
    url = m.call_args.args[1]
    assert url.endswith("/api/v4/projects")
    assert m.call_args.kwargs["params"]["membership"] is True
    assert m.call_args.kwargs["params"]["per_page"] == 50


def test_list_projects_empty():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(200, [])):
        assert adapter.list_projects() == []


def test_list_projects_http_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(401, text="unauth")):
        assert adapter.list_projects() == []


def test_list_projects_network_error():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      side_effect=__import__("requests").RequestException("net")):
        assert adapter.list_projects() == []


def test_list_projects_invalid_json():
    adapter = _build_adapter()
    bad = MagicMock()
    bad.status_code = 200
    bad.json.side_effect = ValueError("not json")
    bad.text = "<html>oops</html>"
    with patch.object(adapter.session, "request", return_value=bad):
        assert adapter.list_projects() == []


def test_list_projects_clamps_per_page():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(200, [])) as m:
        # per_page > 100 must be dropped (GitLab max is 100)
        adapter.list_projects(per_page=500)
    params = m.call_args.kwargs.get("params") or {}
    # If clamped away, key may be absent; ensure no value > 100 slips through.
    assert "per_page" not in params or params["per_page"] <= 100


# --- Factory functions: env vars read inside the function ---

def test_gitlab_adapter_missing_token():
    with patch.dict(os.environ, {}, clear=True):
        assert gitlab_adapter() is None


def test_gitlab_adapter_with_token():
    with patch.dict(os.environ, {
        "GITLAB_API_BASE_URL": "https://gl.example.com",
        "GITLAB_TOKEN": "glpat-xyz",
    }, clear=False):
        a = gitlab_adapter()
    assert a is not None
    assert a.platform == PLATFORM_GITLAB
    assert a.api_url == "https://gl.example.com"
    assert a.token == "glpat-xyz"


def test_gitlab_adapter_uses_default_url():
    # No URL in env → default
    env = {"GITLAB_TOKEN": "glpat-xyz"}
    with patch.dict(os.environ, env, clear=True):
        a = gitlab_adapter()
    assert a is not None
    assert a.api_url == DEFAULT_GITLAB_URL


def test_gitflic_adapter_missing_token():
    with patch.dict(os.environ, {}, clear=True):
        assert gitflic_adapter() is None


def test_gitflic_adapter_with_token():
    with patch.dict(os.environ, {
        "GITFLIC_API_BASE_URL": "https://gf.example.com",
        "GITFLIC_TOKEN": "gf-xyz",
    }, clear=True):
        a = gitflic_adapter()
    assert a is not None
    assert a.platform == PLATFORM_GITFLIC
    assert a.token == "gf-xyz"


def test_gitflic_adapter_default_url():
    with patch.dict(os.environ, {"GITFLIC_TOKEN": "t"}, clear=True):
        a = gitflic_adapter()
    assert a.api_url == DEFAULT_GITFLIC_URL


def test_gitverse_adapter_missing_token():
    with patch.dict(os.environ, {}, clear=True):
        assert gitverse_adapter() is None


def test_gitverse_adapter_with_token():
    with patch.dict(os.environ, {
        "GITVERSE_API_BASE_URL": "https://gv.example.com",
        "GITVERSE_TOKEN": "gv-xyz",
    }, clear=True):
        a = gitverse_adapter()
    assert a is not None
    assert a.platform == PLATFORM_GITVERSE
    assert a.token == "gv-xyz"


def test_gitverse_adapter_default_url():
    with patch.dict(os.environ, {"GITVERSE_TOKEN": "t"}, clear=True):
        a = gitverse_adapter()
    assert a.api_url == DEFAULT_GITVERSE_URL


# Test that env is read inside the function (anti-cosyak #3).
# We toggle env between two patch.dict blocks and assert different results.
def test_factory_reads_env_at_call_time_not_import_time():
    # No token → None
    with patch.dict(os.environ, {}, clear=True):
        assert gitlab_adapter() is None
    # Now set token → adapter built
    with patch.dict(os.environ, {"GITLAB_TOKEN": "glpat-late"}, clear=True):
        a = gitlab_adapter()
    assert a is not None
    assert a.token == "glpat-late"


# --- Convenience wrappers ---

def test_create_gitlab_issue_v2_success():
    with patch.dict(os.environ, {
        "GITLAB_API_BASE_URL": "https://gl.example.com",
        "GITLAB_TOKEN": "glpat-x",
    }, clear=True):
        with patch("gsc_cli.gsc_rf_git_adapter.RFGitAdapter.create_issue",
                   return_value={"web_url": "https://gl.example.com/x"}):
            url = create_gitlab_issue_v2("1", "T", "D")
    assert url == "https://gl.example.com/x"


def test_create_gitlab_issue_v2_no_token():
    with patch.dict(os.environ, {}, clear=True):
        assert create_gitlab_issue_v2("1", "T", "D") is None


def test_create_gitlab_issue_v2_underlying_failure():
    with patch.dict(os.environ, {"GITLAB_TOKEN": "x"}, clear=True):
        with patch("gsc_cli.gsc_rf_git_adapter.RFGitAdapter.create_issue",
                   return_value=None):
            assert create_gitlab_issue_v2("1", "T", "D") is None


def test_create_gitflic_issue_success():
    with patch.dict(os.environ, {
        "GITFLIC_TOKEN": "gf",
    }, clear=True):
        with patch("gsc_cli.gsc_rf_git_adapter.RFGitAdapter.create_issue",
                   return_value={"web_url": "u1"}):
            assert create_gitflic_issue("1", "T", "D") == "u1"


def test_create_gitverse_issue_success():
    with patch.dict(os.environ, {
        "GITVERSE_TOKEN": "gv",
    }, clear=True):
        with patch("gsc_cli.gsc_rf_git_adapter.RFGitAdapter.create_issue",
                   return_value={"web_url": "u2"}):
            assert create_gitverse_issue("1", "T", "D") == "u2"


# --- Doctor ---

def test_doctor_reachable_with_token():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(200,
                                                 {"version": "16.8.0"})):
        st = adapter.doctor()
    assert st["reachable"] is True
    assert st["token_present"] is True
    assert st["version"] == "16.8.0"
    assert st["auth_ok"] is True
    assert st["errors"] == []


def test_doctor_unreachable():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      side_effect=__import__("requests").RequestException("dns")):
        st = adapter.doctor()
    assert st["reachable"] is False
    assert st["auth_ok"] is False
    assert any("Network error" in e for e in st["errors"])


def test_doctor_auth_failed():
    adapter = _build_adapter()
    with patch.object(adapter.session, "request",
                      return_value=_mock_response(401, text="unauth")):
        st = adapter.doctor()
    assert st["reachable"] is True
    assert st["auth_ok"] is False
    assert any("401" in e for e in st["errors"])
