# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the BOLA/IDOR dual-auth request generator.

Covers:
  * skipping non-candidate endpoints
  * resource ID substitution into path templates
  * victim vs. attacker header construction for known auth schemes
  * required base URL (env-only, no hard-coded fallback)
  * env variables read at call time (monkeypatch works)
  * body synthesis for write methods
  * dispatch_pair issues exactly two requests and passes the PreparedRequest
    as the first positional arg to ``Session.send`` (positional, not kwarg)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from gsc_cli.gsc_bola_fuzzer import (
    ENV_ATTACKER_TOKEN,
    ENV_BASE_URL,
    ENV_VICTIM_TOKEN,
    BOLARequestPair,
    build_bola_pairs,
    dispatch_pair,
)
from gsc_cli.gsc_openapi_parser import (
    OpenAPIAuthRequirement,
    OpenAPIExtractedEndpoint,
    OpenAPIParameter,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

def _make_endpoint(
    *,
    path: str = "/users/{user_id}",
    method: str = "get",
    parameters: list[OpenAPIParameter] | None = None,
    auth: list[OpenAPIAuthRequirement] | None = None,
    is_candidate: bool = True,
    reason: str | None = "Parameter 'user_id' in path looks like a resource ID.",
) -> OpenAPIExtractedEndpoint:
    if parameters is None:
        parameters = [
            OpenAPIParameter(
                name="user_id",
                in_location="path",
                required=True,
                schema_type="string",
            )
        ]
    if auth is None:
        auth = [OpenAPIAuthRequirement(scheme_name="bearerAuth")]
    return OpenAPIExtractedEndpoint(
        path=path,
        method=method,
        parameters=parameters,
        auth_required=auth,
        is_bola_idor_candidate=is_candidate,
        bola_idor_reason=reason,
    )


@pytest.fixture
def base_url(monkeypatch):
    monkeypatch.setenv(ENV_BASE_URL, "https://staging.example.com")
    return "https://staging.example.com"


@pytest.fixture
def tokens(monkeypatch):
    monkeypatch.setenv(ENV_VICTIM_TOKEN, "victim-secret-123")
    monkeypatch.setenv(ENV_ATTACKER_TOKEN, "attacker-secret-456")


# ── build_bola_pairs — basic behaviour ────────────────────────────────────

def test_skips_non_candidate_endpoints(base_url, tokens):
    endpoints = [
        _make_endpoint(is_candidate=False, reason=None),
        _make_endpoint(is_candidate=True),
    ]
    pairs = build_bola_pairs(endpoints)
    assert len(pairs) == 1
    assert pairs[0].endpoint_path == "/users/{user_id}"


def test_substitutes_resource_id_into_path(base_url, tokens):
    endpoints = [_make_endpoint(path="/orders/{order_id}", method="get", parameters=[
        OpenAPIParameter(name="order_id", in_location="path", required=True, schema_type="string"),
    ])]
    pairs = build_bola_pairs(endpoints)
    assert len(pairs) == 1
    pair = pairs[0]
    # Path template must be replaced in the rendered URL.
    assert "{order_id}" not in pair.victim_request.url
    assert pair.victim_request.url.endswith("/orders/1")
    assert pair.attacker_request.url.endswith("/orders/1")


def test_query_param_resource_id_rendered_in_url(base_url, tokens):
    endpoints = [_make_endpoint(
        path="/items",
        method="get",
        parameters=[
            OpenAPIParameter(name="account_id", in_location="query", required=True, schema_type="string"),
        ],
    )]
    pairs = build_bola_pairs(endpoints)
    assert len(pairs) == 1
    url = pairs[0].victim_request.url
    assert url.startswith("https://staging.example.com/items?")
    assert "account_id=1" in url


def test_body_synthesis_for_post(base_url, tokens):
    endpoints = [_make_endpoint(path="/users/{user_id}", method="post", parameters=[
        OpenAPIParameter(name="user_id", in_location="path", required=True, schema_type="string"),
    ], auth=[OpenAPIAuthRequirement(scheme_name="bearerAuth")])]
    pairs = build_bola_pairs(endpoints)
    body = pairs[0].victim_request.json
    assert isinstance(body, dict)
    assert body.get("user_id") == "1"
    assert body.get("_gsc_bola_fuzz") is True


def test_no_body_for_get(base_url, tokens):
    endpoints = [_make_endpoint()]  # method=GET by default
    pairs = build_bola_pairs(endpoints)
    assert pairs[0].victim_request.json is None


# ── Auth header construction ──────────────────────────────────────────────

def test_bearer_auth_headers_distinguish_victim_and_attacker(base_url, tokens):
    pairs = build_bola_pairs([_make_endpoint()])
    v = pairs[0].victim_request.headers
    a = pairs[0].attacker_request.headers
    assert v["Authorization"] == "Bearer victim-secret-123"
    assert a["Authorization"] == "Bearer attacker-secret-456"


def test_apikey_scheme_uses_x_api_key(base_url, tokens):
    pairs = build_bola_pairs([_make_endpoint(
        auth=[OpenAPIAuthRequirement(scheme_name="apiKeyAuth")],
    )])
    assert pairs[0].victim_request.headers["X-API-Key"] == "victim-secret-123"
    assert pairs[0].attacker_request.headers["X-API-Key"] == "attacker-secret-456"


def test_unknown_scheme_falls_back_to_bearer(base_url, tokens):
    pairs = build_bola_pairs([_make_endpoint(
        auth=[OpenAPIAuthRequirement(scheme_name="weirdCustomAuth")],
    )])
    assert pairs[0].victim_request.headers["Authorization"] == "Bearer victim-secret-123"


def test_no_auth_scheme_emits_no_authorization_header(base_url, tokens):
    pairs = build_bola_pairs([_make_endpoint(auth=[])])
    v = pairs[0].victim_request.headers
    assert "Authorization" not in v
    assert "X-API-Key" not in v
    # But the fuzz-role header is always present so downstream filters work.
    assert v["X-GSC-Fuzz-Role"] == "victim"
    assert pairs[0].attacker_request.headers["X-GSC-Fuzz-Role"] == "attacker"


def test_placeholder_tokens_when_env_missing(base_url):
    # No victim/attacker env set — placeholders must be clearly marked.
    pairs = build_bola_pairs([_make_endpoint()])
    a = pairs[0].victim_request.headers["Authorization"]
    assert a.startswith("Bearer PLACEHOLDER-")
    assert "PLACEHOLDER-ATTACKER" in pairs[0].attacker_request.headers["Authorization"]


# ── Env handling: read at call time, never at import ──────────────────────

def test_env_is_read_inside_function(monkeypatch):
    # Import-time env must NOT pre-populate the function. We test that by
    # setting base_url AFTER import.
    monkeypatch.delenv(ENV_BASE_URL, raising=False)
    with pytest.raises(ValueError, match=ENV_BASE_URL):
        build_bola_pairs([_make_endpoint()])
    # And once we set it, the same call works.
    monkeypatch.setenv(ENV_BASE_URL, "https://staging.example.com")
    monkeypatch.setenv(ENV_VICTIM_TOKEN, "v")
    monkeypatch.setenv(ENV_ATTACKER_TOKEN, "a")
    pairs = build_bola_pairs([_make_endpoint()])
    assert len(pairs) == 1


def test_explicit_args_override_env(monkeypatch):
    monkeypatch.setenv(ENV_BASE_URL, "https://env.example.com")
    monkeypatch.setenv(ENV_VICTIM_TOKEN, "env-victim")
    pairs = build_bola_pairs(
        [_make_endpoint()],
        base_url="https://override.example.com",
        victim_token="override-victim",
        attacker_token="override-attacker",
    )
    assert pairs[0].victim_request.url.startswith("https://override.example.com")
    assert pairs[0].victim_request.headers["Authorization"] == "Bearer override-victim"


def test_trailing_slash_on_base_url_is_stripped(base_url, tokens):
    pairs = build_bola_pairs(
        [_make_endpoint()],
        base_url="https://staging.example.com/",  # trailing slash
    )
    # No double slash between host and path.
    assert "//" not in pairs[0].victim_request.url.replace("https://", "")


# ── Output shape ──────────────────────────────────────────────────────────

def test_to_dict_is_json_friendly(base_url, tokens):
    pairs = build_bola_pairs([_make_endpoint()])
    d = pairs[0].to_dict()
    assert d["endpoint_path"] == "/users/{user_id}"
    assert d["endpoint_method"] == "get"
    assert d["resource_id"] == "1"
    assert d["victim_request"]["method"] == "GET"
    assert d["victim_request"]["url"] == "https://staging.example.com/users/1"
    assert d["notes"], "notes must carry at least the BOLA reason"


def test_multiple_endpoints_produce_multiple_pairs(base_url, tokens):
    endpoints = [
        _make_endpoint(path="/users/{user_id}"),
        _make_endpoint(path="/orders/{order_id}", parameters=[
            OpenAPIParameter(name="order_id", in_location="path", required=True, schema_type="string"),
        ]),
        _make_endpoint(is_candidate=False, reason=None),
    ]
    pairs = build_bola_pairs(endpoints)
    assert len(pairs) == 2
    assert {p.endpoint_path for p in pairs} == {"/users/{user_id}", "/orders/{order_id}"}


# ── dispatch_pair — issues two requests with positional PreparedRequest ──

def test_dispatch_pair_sends_two_requests(monkeypatch):
    monkeypatch.setenv(ENV_BASE_URL, "https://staging.example.com")
    monkeypatch.setenv(ENV_VICTIM_TOKEN, "v")
    monkeypatch.setenv(ENV_ATTACKER_TOKEN, "a")
    pairs = build_bola_pairs([_make_endpoint()])
    pair = pairs[0]

    fake_session = MagicMock()
    fake_session.send.side_effect = [
        MagicMock(status_code=200, text="victim-body"),
        MagicMock(status_code=200, text="attacker-body"),
    ]
    victim_resp, attacker_resp = dispatch_pair(pair, session=fake_session)

    assert fake_session.send.call_count == 2
    # Rule #6: Session.send(prepared, timeout=...) is called with the
    # PreparedRequest as the FIRST POSITIONAL arg.
    first_args = fake_session.send.call_args_list[0].args
    assert len(first_args) >= 1
    from requests import PreparedRequest
    assert isinstance(first_args[0], PreparedRequest)
    # Both calls target the same resource URL.
    assert fake_session.send.call_args_list[0].args[0].url == \
           fake_session.send.call_args_list[1].args[0].url
    # Auth headers differ between the two calls.
    assert victim_resp.status_code == 200
    assert attacker_resp.status_code == 200


def test_dispatch_pair_uses_default_session(monkeypatch):
    # No session passed — dispatch_pair must build its own.
    monkeypatch.setenv(ENV_BASE_URL, "https://staging.example.com")
    monkeypatch.setenv(ENV_VICTIM_TOKEN, "v")
    monkeypatch.setenv(ENV_ATTACKER_TOKEN, "a")
    pairs = build_bola_pairs([_make_endpoint()])

    fake_session_cls = MagicMock()
    monkeypatch.setattr(requests, "Session", fake_session_cls)
    fake_session = fake_session_cls.return_value
    fake_session.send.return_value = MagicMock(status_code=204)

    dispatch_pair(pairs[0])
    assert fake_session.send.call_count == 2
