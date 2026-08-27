# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GitLab API client (Phase 15 — RF Enterprise)."""

from unittest import mock

import requests

from gsc_cli.gsc_gitlab_api_client import (
    GitLabAPIClient,
    _encode_project_path,
    find_existing_note,
    upsert_note,
)


def test_encode_project_path():
    assert _encode_project_path("group/project") == "group%2Fproject"
    assert _encode_project_path("group/sub/project") == "group%2Fsub%2Fproject"
    assert _encode_project_path("single") == "single"


def test_client_headers_and_base_url():
    c = GitLabAPIClient("secret-token", "https://gitlab.com/api/v4/")
    assert c.base_url == "https://gitlab.com/api/v4"  # trailing slash stripped
    assert c.headers["Private-Token"] == "secret-token"
    assert c.headers["Content-Type"] == "application/json"


def _resp(payload):
    r = mock.Mock()
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


def test_get_uses_private_token_and_url(monkeypatch):
    r = _resp([{"id": 7, "body": "x"}])
    get_mock = mock.Mock(return_value=r)
    monkeypatch.setattr(requests, "get", get_mock)

    c = GitLabAPIClient("tok", "https://gitlab.com/api/v4")
    out = c.get("/projects/a/notes")

    assert out == [{"id": 7, "body": "x"}]
    url = get_mock.call_args.args[0]  # url is positional
    assert url == "https://gitlab.com/api/v4/projects/a/notes"
    assert get_mock.call_args.kwargs["headers"]["Private-Token"] == "tok"


def test_post_uses_private_token(monkeypatch):
    r = _resp({"id": 99})
    post_mock = mock.Mock(return_value=r)
    monkeypatch.setattr(requests, "post", post_mock)

    c = GitLabAPIClient("tok", "https://gitlab.com/api/v4")
    out = c.post("/projects/a/notes", json_data={"body": "b"})

    assert out == {"id": 99}
    assert post_mock.call_args.args[0] == "https://gitlab.com/api/v4/projects/a/notes"
    assert post_mock.call_args.kwargs["headers"]["Private-Token"] == "tok"


def test_find_existing_note_found():
    c = mock.Mock()
    c.get.return_value = [
        {"id": 7, "body": "hello GSC marker here"},
        {"id": 8, "body": "unrelated"},
    ]
    assert find_existing_note(c, "group/proj", 12, "marker") == 7


def test_find_existing_note_not_found():
    c = mock.Mock()
    c.get.return_value = [{"id": 8, "body": "unrelated"}]
    assert find_existing_note(c, "group/proj", 12, "marker") is None


def test_find_existing_note_encodes_project_path():
    c = mock.Mock()
    c.get.return_value = []
    find_existing_note(c, "group/proj", 12, "marker")
    path = c.get.call_args.args[0]
    assert "/projects/group%2Fproj/merge_requests/12/notes" in path


def test_find_existing_note_request_error_returns_none():
    c = mock.Mock()
    c.get.side_effect = requests.RequestException("boom")
    assert find_existing_note(c, "group/proj", 12, "marker") is None


def test_upsert_note_update_existing():
    c = mock.Mock()
    c.get.return_value = [{"id": 7, "body": "marker"}]
    assert upsert_note(c, "group/proj", 12, "new body", "marker") == 7
    c.put.assert_called_once()
    assert "/notes/7" in c.put.call_args.args[0]
    assert c.put.call_args.kwargs["json_data"] == {"body": "new body"}


def test_upsert_note_create():
    c = mock.Mock()
    c.get.return_value = []  # no existing note
    c.post.return_value = {"id": 99}
    assert upsert_note(c, "group/proj", 12, "body", "marker") == 99
    c.post.assert_called_once()
    assert c.post.call_args.kwargs["json_data"] == {"body": "body"}
