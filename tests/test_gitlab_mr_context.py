# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GitLab MR context parser (Phase 15 — RF Enterprise self-hosted).

Covers:
  * parse_gitlab_mr_url:
      - gitlab.com canonical URL
      - self-hosted nested project paths (group/sub/project)
      - trailing slash, query strings, fragment
      - extra path segments after iid (``/diffs``, ``/commits``)
      - http:// scheme (corporate proxies) → api_base still https://
      - invalid inputs: None, empty, non-string, non-MR URL, bad iid,
        empty project path, ``.``/``..`` segments, missing host
  * parse_gitlab_webhook:
      - canonical merge_request event payload
      - project_id string variant
      - iid as string (lenient int coercion)
      - missing required keys → None
      - non-dict payload → None
      - non-dict intermediate nodes (e.g. ``project`` is None)
      - ``http_url`` fallback when ``web_url`` is missing
      - ``git_http_url`` last-resort fallback
      - ``ssh_url`` does NOT contribute a host (no usable HTTP netloc)
      - malformed project_path (``..`` segment) → None
  * GitLabMRContext.to_dict() roundtrip and field defaults.
"""

import pytest

from gsc_cli.gsc_gitlab_mr_context import (
    GitLabMRContext,
    parse_gitlab_mr_url,
    parse_gitlab_webhook,
)


# ── GitLabMRContext dataclass ────────────────────────────────────────────


def test_dataclass_defaults_all_fields_empty_and_invalid():
    ctx = GitLabMRContext()
    assert ctx.host == ""
    assert ctx.project_path == ""
    assert ctx.project_id == ""
    assert ctx.mr_iid == 0
    assert ctx.api_base == ""
    assert ctx.source_branch == ""
    assert ctx.target_branch == ""
    assert ctx.valid is False


def test_dataclass_to_dict_matches_fields():
    ctx = GitLabMRContext(
        host="gitlab.example.org",
        project_path="team/app",
        project_id="42",
        mr_iid=9,
        api_base="https://gitlab.example.org/api/v4",
        source_branch="feat",
        target_branch="main",
        valid=True,
    )
    assert ctx.to_dict() == {
        "host": "gitlab.example.org",
        "project_path": "team/app",
        "project_id": "42",
        "mr_iid": 9,
        "api_base": "https://gitlab.example.org/api/v4",
        "source_branch": "feat",
        "target_branch": "main",
        "valid": True,
    }


# ── parse_gitlab_mr_url — happy path ────────────────────────────────────


def test_parse_gitlab_mr_url_gitlab_com_canonical():
    ctx = parse_gitlab_mr_url("https://gitlab.com/group/project/-/merge_requests/123")
    assert ctx is not None
    assert ctx.valid is True
    assert ctx.host == "gitlab.com"
    assert ctx.project_path == "group/project"
    assert ctx.mr_iid == 123
    assert ctx.api_base == "https://gitlab.com/api/v4"
    assert ctx.project_id == ""
    assert ctx.source_branch == ""
    assert ctx.target_branch == ""


def test_parse_gitlab_mr_url_self_hosted_nested_path():
    ctx = parse_gitlab_mr_url(
        "https://gitlab.company.ru/group/sub/project/-/merge_requests/5"
    )
    assert ctx is not None
    assert ctx.host == "gitlab.company.ru"
    assert ctx.project_path == "group/sub/project"
    assert ctx.mr_iid == 5
    assert ctx.api_base == "https://gitlab.company.ru/api/v4"


def test_parse_gitlab_mr_url_with_port():
    # Corporate GitLab behind a non-default port.
    ctx = parse_gitlab_mr_url(
        "https://gitlab.internal:8443/team/svc/-/merge_requests/42"
    )
    assert ctx is not None
    assert ctx.host == "gitlab.internal:8443"
    assert ctx.project_path == "team/svc"
    assert ctx.api_base == "https://gitlab.internal:8443/api/v4"


def test_parse_gitlab_mr_url_trailing_slash():
    ctx = parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/1/")
    assert ctx is not None
    assert ctx.mr_iid == 1
    assert ctx.project_path == "g/p"


def test_parse_gitlab_mr_url_with_query_string():
    ctx = parse_gitlab_mr_url(
        "https://gitlab.com/g/p/-/merge_requests/9?diff_id=1"
    )
    assert ctx is not None
    assert ctx.mr_iid == 9
    assert ctx.project_path == "g/p"


def test_parse_gitlab_mr_url_with_fragment():
    ctx = parse_gitlab_mr_url(
        "https://gitlab.com/g/p/-/merge_requests/9#note_1"
    )
    assert ctx is not None
    assert ctx.mr_iid == 9


def test_parse_gitlab_mr_url_with_query_and_fragment():
    ctx = parse_gitlab_mr_url(
        "https://gitlab.com/g/p/-/merge_requests/9?diff_id=1#note_1"
    )
    assert ctx is not None
    assert ctx.mr_iid == 9


def test_parse_gitlab_mr_url_drops_extra_path_segments():
    # /diffs, /commits, /pipelines are common after the iid.
    ctx = parse_gitlab_mr_url(
        "https://gitlab.com/g/p/-/merge_requests/9/diffs"
    )
    assert ctx is not None
    assert ctx.mr_iid == 9
    assert ctx.project_path == "g/p"


def test_parse_gitlab_mr_url_http_scheme_api_base_still_https():
    # http://gitlab.local behind a TLS-terminating proxy — GitLab's API
    # base is always https by convention.
    ctx = parse_gitlab_mr_url("http://gitlab.local/g/p/-/merge_requests/3")
    assert ctx is not None
    assert ctx.host == "gitlab.local"
    assert ctx.api_base == "https://gitlab.local/api/v4"


def test_parse_gitlab_mr_url_to_dict_roundtrip():
    ctx = parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/4")
    assert ctx is not None
    d = ctx.to_dict()
    assert d["valid"] is True
    assert d["host"] == "gitlab.com"
    assert d["project_path"] == "g/p"
    assert d["mr_iid"] == 4
    assert d["api_base"] == "https://gitlab.com/api/v4"


# ── parse_gitlab_mr_url — error & edge cases ───────────────────────────


def test_parse_gitlab_mr_url_none_input():
    assert parse_gitlab_mr_url(None) is None  # type: ignore[arg-type]


def test_parse_gitlab_mr_url_empty_string():
    assert parse_gitlab_mr_url("") is None


def test_parse_gitlab_mr_url_whitespace_only():
    assert parse_gitlab_mr_url("   \n\t  ") is None


def test_parse_gitlab_mr_url_non_string_input():
    assert parse_gitlab_mr_url(12345) is None  # type: ignore[arg-type]
    assert parse_gitlab_mr_url(b"https://gitlab.com/g/p/-/merge_requests/1") is None  # type: ignore[arg-type]


def test_parse_gitlab_mr_url_not_a_gitlab_url():
    assert parse_gitlab_mr_url("https://github.com/g/p/pull/1") is None
    assert parse_gitlab_mr_url("https://example.com/whatever") is None


def test_parse_gitlab_mr_url_no_merge_requests_marker():
    # Right host, wrong path.
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/issues/1") is None
    assert parse_gitlab_mr_url("https://gitlab.com/g/p") is None


def test_parse_gitlab_mr_url_empty_project_path():
    # ``/-/merge_requests/1`` with no project segment.
    assert parse_gitlab_mr_url("https://gitlab.com/-/merge_requests/1") is None


def test_parse_gitlab_mr_url_zero_iid():
    # Iid must be positive.
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/0") is None


def test_parse_gitlab_mr_url_non_integer_iid():
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/abc") is None
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/1.5") is None
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/-1") is None


def test_parse_gitlab_mr_url_dot_segment_in_path():
    # Defensive: project_path with ``.`` or ``..`` segments is rejected.
    assert parse_gitlab_mr_url("https://gitlab.com/./p/-/merge_requests/1") is None
    assert parse_gitlab_mr_url("https://gitlab.com/../p/-/merge_requests/1") is None
    assert parse_gitlab_mr_url("https://gitlab.com/g/../p/-/merge_requests/1") is None


def test_parse_gitlab_mr_url_no_host():
    # No scheme → urlparse yields empty netloc.
    assert parse_gitlab_mr_url("gitlab.com/g/p/-/merge_requests/1") is None


def test_parse_gitlab_mr_url_only_marker_no_iid():
    # ``/-/merge_requests/`` with nothing after → iid is empty.
    assert parse_gitlab_mr_url("https://gitlab.com/g/p/-/merge_requests/") is None


# ── parse_gitlab_webhook — happy path ───────────────────────────────────


def test_parse_gitlab_webhook_canonical_merge_request_event():
    payload = {
        "object_kind": "merge_request",
        "project": {
            "id": 12345,
            "name": "app",
            "path_with_namespace": "team/app",
            "web_url": "https://gitlab.company.ru/team/app",
            "http_url": "https://gitlab.company.ru/team/app.git",
        },
        "object_attributes": {
            "iid": 7,
            "source_branch": "feature/x",
            "target_branch": "main",
            "title": "Add widget",
        },
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.valid is True
    assert ctx.host == "gitlab.company.ru"
    assert ctx.project_path == "team/app"
    assert ctx.project_id == "12345"
    assert ctx.mr_iid == 7
    assert ctx.api_base == "https://gitlab.company.ru/api/v4"
    assert ctx.source_branch == "feature/x"
    assert ctx.target_branch == "main"


def test_parse_gitlab_webhook_nested_project_path():
    payload = {
        "project": {
            "id": 9,
            "path_with_namespace": "group/sub/proj",
            "web_url": "https://gl.example/group/sub/proj",
        },
        "object_attributes": {"iid": 1, "source_branch": "a", "target_branch": "b"},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.project_path == "group/sub/proj"
    assert ctx.host == "gl.example"


def test_parse_gitlab_webhook_project_id_string_variant():
    payload = {
        "project": {
            "id": "42",
            "path_with_namespace": "t/p",
            "web_url": "https://gl/t/p",
        },
        "object_attributes": {"iid": 3},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.project_id == "42"


def test_parse_gitlab_webhook_iid_as_string_coerced():
    # Some webhook variants serialise iid as a string; be lenient.
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
            "web_url": "https://gl/t/p",
        },
        "object_attributes": {"iid": "12"},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.mr_iid == 12


def test_parse_gitlab_webhook_uses_http_url_fallback():
    # web_url missing — fall back to http_url.
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
            "http_url": "https://gl.internal/t/p.git",
        },
        "object_attributes": {"iid": 2},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.host == "gl.internal"


def test_parse_gitlab_webhook_uses_git_http_url_last_resort():
    # web_url and http_url both missing — fall back to git_http_url.
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
            "git_http_url": "https://gl/t/p.git",
        },
        "object_attributes": {"iid": 2},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.host == "gl"


def test_parse_gitlab_webhook_ssh_url_does_not_contribute_host():
    # ssh_url is ``git@...:t/p.git`` — no usable HTTP netloc; host stays empty
    # and the parser returns None because a context without a host is unusable.
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
            "ssh_url": "git@gl.example:t/p.git",
        },
        "object_attributes": {"iid": 2},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_no_url_fields_at_all():
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
        },
        "object_attributes": {"iid": 2},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_to_dict_roundtrip():
    payload = {
        "project": {
            "id": 12345,
            "path_with_namespace": "team/app",
            "web_url": "https://gitlab.company.ru/team/app",
        },
        "object_attributes": {
            "iid": 7,
            "source_branch": "feat",
            "target_branch": "main",
        },
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    d = ctx.to_dict()
    assert d["host"] == "gitlab.company.ru"
    assert d["project_path"] == "team/app"
    assert d["project_id"] == "12345"
    assert d["mr_iid"] == 7
    assert d["api_base"] == "https://gitlab.company.ru/api/v4"
    assert d["source_branch"] == "feat"
    assert d["target_branch"] == "main"
    assert d["valid"] is True


# ── parse_gitlab_webhook — error & edge cases ───────────────────────────


def test_parse_gitlab_webhook_none_input():
    assert parse_gitlab_webhook(None) is None  # type: ignore[arg-type]


def test_parse_gitlab_webhook_non_dict_inputs():
    assert parse_gitlab_webhook([]) is None  # type: ignore[arg-type]
    assert parse_gitlab_webhook("merge_request") is None  # type: ignore[arg-type]
    assert parse_gitlab_webhook(42) is None  # type: ignore[arg-type]
    assert parse_gitlab_webhook(b"{}") is None  # type: ignore[arg-type]


def test_parse_gitlab_webhook_missing_project():
    payload = {"object_attributes": {"iid": 1}}
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_missing_object_attributes():
    payload = {"project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"}}
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_non_dict_project():
    payload = {
        "project": None,
        "object_attributes": {"iid": 1},
    }
    assert parse_gitlab_webhook(payload) is None
    payload = {
        "project": "team/app",
        "object_attributes": {"iid": 1},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_non_dict_object_attributes():
    payload = {
        "project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"},
        "object_attributes": None,
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_missing_path_with_namespace():
    payload = {
        "project": {"id": 1, "web_url": "https://gl/t/p"},
        "object_attributes": {"iid": 1},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_empty_path_with_namespace():
    payload = {
        "project": {"id": 1, "path_with_namespace": "  ", "web_url": "https://gl/t/p"},
        "object_attributes": {"iid": 1},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_dot_segment_in_path():
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/../p",
            "web_url": "https://gl/t/p",
        },
        "object_attributes": {"iid": 1},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_missing_iid():
    payload = {
        "project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"},
        "object_attributes": {"source_branch": "a", "target_branch": "b"},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_zero_iid():
    payload = {
        "project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"},
        "object_attributes": {"iid": 0},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_non_integer_iid_string():
    payload = {
        "project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"},
        "object_attributes": {"iid": "not-a-number"},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_iid_negative_string():
    payload = {
        "project": {"id": 1, "path_with_namespace": "t/p", "web_url": "https://gl/t/p"},
        "object_attributes": {"iid": "-1"},
    }
    assert parse_gitlab_webhook(payload) is None


def test_parse_gitlab_webhook_non_string_source_target_branch_coerced_to_empty():
    # Non-string branch values are tolerated (set to "") — defensive
    # against partial / corrupt webhook replays.
    payload = {
        "project": {
            "id": 1,
            "path_with_namespace": "t/p",
            "web_url": "https://gl/t/p",
        },
        "object_attributes": {
            "iid": 1,
            "source_branch": 42,
            "target_branch": None,
        },
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.source_branch == ""
    assert ctx.target_branch == ""


def test_parse_gitlab_webhook_missing_project_id_yields_empty_string():
    # ``project.id`` absent — project_id is the empty string (URL-only
    # fallback path is preserved; valid is still True because the rest
    # of the payload is intact).
    payload = {
        "project": {
            "path_with_namespace": "t/p",
            "web_url": "https://gl/t/p",
        },
        "object_attributes": {"iid": 1},
    }
    ctx = parse_gitlab_webhook(payload)
    assert ctx is not None
    assert ctx.project_id == ""
    assert ctx.valid is True
