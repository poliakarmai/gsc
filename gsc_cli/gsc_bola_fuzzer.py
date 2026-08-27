# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""BOLA/IDOR dual-auth request generator for OpenAPI-derived endpoints.

Phase 14 / second half of "AI fuzzing of BOLA/IDOR over OpenAPI": for every
``OpenAPIExtractedEndpoint`` flagged as ``is_bola_idor_candidate=True`` this
module produces a pair of fully-formed ``requests.Request`` objects — one for
the legitimate user (victim token) and one for the attacker (attacker token) —
both targeting the *same* resource identifier. The pair is meant to be sent
to a live staging target (or replayed by a test harness) so an IDOR bug shows
up as "attacker got the victim's resource".

This module does NOT perform any network I/O. It only assembles request
structures (method, URL, headers, body, query string, path substitution).
The caller decides whether/where to send them.

Tokens and the base URL are read from the environment *inside* the public
functions, never at module import time, so that tests using
``monkeypatch.setenv`` / ``patch.dict(os.environ)`` behave correctly.

Required env:
    BOLA_FUZZ_BASE_URL       — e.g. ``https://staging.example.com``

Optional env (placeholders are used when missing):
    BOLA_FUZZ_VICTIM_TOKEN   — bearer/apiKey token for the legitimate user
    BOLA_FUZZ_ATTACKER_TOKEN — bearer/apiKey token for the attacker
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import requests

from gsc_cli.gsc_openapi_parser import (
    OpenAPIAuthRequirement,
    OpenAPIExtractedEndpoint,
    OpenAPIParameter,
)

# ── Configuration ─────────────────────────────────────────────────────────

# Environment variable names — read inside functions only.
ENV_BASE_URL = "BOLA_FUZZ_BASE_URL"
ENV_VICTIM_TOKEN = "BOLA_FUZZ_VICTIM_TOKEN"
ENV_ATTACKER_TOKEN = "BOLA_FUZZ_ATTACKER_TOKEN"

# Placeholder tokens when the operator has not provided real ones. The
# placeholders are intentionally distinguishable (start with "PLACEHOLDER-")
# so downstream code/tests can detect "no real auth was supplied".
_VICTIM_PLACEHOLDER = "PLACEHOLDER-VICTIM-TOKEN"
_ATTACKER_PLACEHOLDER = "PLACEHOLDER-ATTACKER-TOKEN"

# Resource-ID placeholder value used in generated requests when the spec
# does not give us an example. The same value is used for both victim and
# attacker — that's the whole point of the test: both clients request the
# same resource, but with different tokens.
_DEFAULT_RESOURCE_ID = "1"

# HTTP methods whose bodies we can synthesize from a JSON example.
_BODY_METHODS = frozenset({"post", "put", "patch", "delete"})


# ── Public dataclasses ────────────────────────────────────────────────────

@dataclass
class BOLARequestPair:
    """A pair of BOLA/IDOR test requests — victim + attacker for one endpoint.

    Attributes:
        endpoint_path:    OpenAPI path template, e.g. ``/users/{user_id}``.
        endpoint_method:  HTTP method in lower case, e.g. ``get``.
        resource_id:      Concrete ID substituted into path/query.
        victim_request:   Fully prepared ``requests.Request`` for the victim.
        attacker_request: Fully prepared ``requests.Request`` for the attacker.
        notes:            Free-form metadata (why this is a BOLA candidate,
                          which parameter drove the decision, etc.).
    """
    endpoint_path: str
    endpoint_method: str
    resource_id: str
    victim_request: requests.Request
    attacker_request: requests.Request
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-friendly view (request objects serialized)."""
        return {
            "endpoint_path": self.endpoint_path,
            "endpoint_method": self.endpoint_method,
            "resource_id": self.resource_id,
            "victim_request": _serialize_request(self.victim_request),
            "attacker_request": _serialize_request(self.attacker_request),
            "notes": list(self.notes),
        }


# ── Public entry points ───────────────────────────────────────────────────

def build_bola_pairs(
    endpoints: Iterable[OpenAPIExtractedEndpoint],
    base_url: str | None = None,
    victim_token: str | None = None,
    attacker_token: str | None = None,
) -> list[BOLARequestPair]:
    """Build BOLA/IDOR request pairs for every candidate endpoint.

    The base URL and tokens default to the corresponding environment
    variables (``BOLA_FUZZ_BASE_URL``, ``BOLA_FUZZ_VICTIM_TOKEN``,
    ``BOLA_FUZZ_ATTACKER_TOKEN``). If a token is not provided, a clearly
    marked placeholder is used so generated requests are still structurally
    valid for tests.

    Args:
        endpoints:      Iterable of ``OpenAPIExtractedEndpoint`` from
                        ``gsc_openapi_parser.parse_openapi_spec``.
        base_url:       Override the base URL (otherwise read from env).
        victim_token:   Override the victim token (otherwise read from env).
        attacker_token: Override the attacker token (otherwise read from env).

    Returns:
        List of ``BOLARequestPair`` — one per BOLA/IDOR candidate endpoint.
        Endpoints with ``is_bola_idor_candidate=False`` are skipped.

    Raises:
        ValueError: If no ``base_url`` is available (neither argument nor env).
    """
    if base_url is None:
        base_url = os.environ.get(ENV_BASE_URL, "")
    base_url = base_url.rstrip("/")
    if not base_url:
        raise ValueError(
            f"{ENV_BASE_URL} is not set and no base_url was provided"
        )
    if victim_token is None:
        victim_token = os.environ.get(ENV_VICTIM_TOKEN) or _VICTIM_PLACEHOLDER
    if attacker_token is None:
        attacker_token = os.environ.get(ENV_ATTACKER_TOKEN) or _ATTACKER_PLACEHOLDER

    pairs: list[BOLARequestPair] = []
    for endpoint in endpoints:
        if not endpoint.is_bola_idor_candidate:
            continue
        # The BOLA/IDOR decision is driven by the first resource-like
        # parameter we find — re-use it to pick a resource value.
        resource_param = _first_resource_param(endpoint.parameters)
        resource_id = _resource_id_for(resource_param)
        pair = _build_pair_for_endpoint(
            endpoint=endpoint,
            base_url=base_url,
            victim_token=victim_token,
            attacker_token=attacker_token,
            resource_id=resource_id,
        )
        pairs.append(pair)
    return pairs


def dispatch_pair(
    pair: BOLARequestPair,
    session: requests.Session | None = None,
    timeout: float = 10.0,
) -> tuple[requests.Response, requests.Response]:
    """Send a single ``BOLARequestPair`` over the wire.

    Provided for callers that want to drive the pair end-to-end. Kept
    separate from :func:`build_bola_pairs` so the build phase remains
    side-effect-free and easy to unit-test.

    The two requests are issued sequentially (victim first, attacker
    second). Each request is prepared and sent with its own auth token.

    Args:
        pair:    A pair returned by :func:`build_bola_pairs`.
        session: Optional ``requests.Session`` for connection pooling /
                 cookies. A fresh session is created if omitted.
        timeout: Per-request timeout in seconds.

    Returns:
        ``(victim_response, attacker_response)`` tuple.
    """
    s = session or requests.Session()
    victim_resp = s.send(pair.victim_request.prepare(), timeout=timeout)
    attacker_resp = s.send(pair.attacker_request.prepare(), timeout=timeout)
    return victim_resp, attacker_resp


# ── Internals ─────────────────────────────────────────────────────────────

def _first_resource_param(
    params: list[OpenAPIParameter],
) -> OpenAPIParameter | None:
    """Return the first path/query parameter that looks like a resource ID."""
    for p in params:
        if p.in_location in ("path", "query"):
            return p
    return None


def _resource_id_for(param: OpenAPIParameter | None) -> str:
    """Pick a concrete resource value for the given parameter.

    No example is read from the spec (the existing parser does not capture
    one), so we default to a benign numeric ID. A stable default keeps the
    generated requests reproducible across runs.
    """
    return _DEFAULT_RESOURCE_ID


def _build_pair_for_endpoint(
    endpoint: OpenAPIExtractedEndpoint,
    base_url: str,
    victim_token: str,
    attacker_token: str,
    resource_id: str,
) -> BOLARequestPair:
    """Construct the victim+attacker request pair for one endpoint."""
    # Resolve path / query / body from the OpenAPI parameter list.
    path = endpoint.path
    query: dict[str, Any] = {}
    body: Any = None
    used_param_names: set[str] = set()

    for p in endpoint.parameters:
        if p.in_location == "path":
            path = path.replace("{" + p.name + "}", resource_id)
            used_param_names.add(p.name)
        elif p.in_location == "query":
            query[p.name] = resource_id
            used_param_names.add(p.name)
        elif p.in_location == "header":
            # Header-bound resource IDs are unusual for BOLA but possible;
            # we still surface them via the auth header path so they are
            # visible in the prepared request.
            used_param_names.add(p.name)

    if endpoint.method in _BODY_METHODS:
        body = _synth_body(endpoint.method, resource_id, used_param_names)

    url = base_url + path
    if query:
        # Use a list-of-tuples to preserve order; dict would also work but
        # explicit ordering is friendlier in test output.
        url = _append_query(url, query)

    # Build one request per auth context. Auth is shaped by the OpenAPI
    # security schemes declared on the endpoint; if none are declared we
    # still attach a header so the request is valid against most APIs.
    auth_scheme = _primary_auth_scheme(endpoint.auth_required)
    victim_headers = _build_auth_headers(
        scheme=auth_scheme, token=victim_token, role="victim"
    )
    attacker_headers = _build_auth_headers(
        scheme=auth_scheme, token=attacker_token, role="attacker"
    )

    victim_request = requests.Request(
        method=endpoint.method.upper(),
        url=url,
        headers=victim_headers,
        json=body if body is not None else None,
    )
    attacker_request = requests.Request(
        method=endpoint.method.upper(),
        url=url,
        headers=attacker_headers,
        json=body if body is not None else None,
    )

    return BOLARequestPair(
        endpoint_path=endpoint.path,
        endpoint_method=endpoint.method,
        resource_id=resource_id,
        victim_request=victim_request,
        attacker_request=attacker_request,
        notes=[
            f"auth_scheme={auth_scheme or 'none'}",
            f"resource_param_used={[p.name for p in endpoint.parameters if p.in_location in ('path','query')]}",
            endpoint.bola_idor_reason or "is_bola_idor_candidate=True",
        ],
    )


def _primary_auth_scheme(
    auth_reqs: list[OpenAPIAuthRequirement],
) -> str | None:
    """Pick a single scheme name to drive header construction."""
    if not auth_reqs:
        return None
    return auth_reqs[0].scheme_name


def _build_auth_headers(
    scheme: str | None,
    token: str,
    role: str,
) -> dict[str, str]:
    """Build an ``Authorization`` / ``X-API-Key`` header pair.

    The mapping from OpenAPI security-scheme name to HTTP header is
    deliberately simple — the real mapping requires the spec's
    ``securitySchemes`` definitions, which the parser does not return.
    A handful of well-known names are recognised; everything else falls
    back to ``Authorization: Bearer <token>``.
    """
    headers: dict[str, str] = {
        "X-GSC-Fuzz-Role": role,  # mark our own traffic for downstream filters
        "X-GSC-Fuzz-Trace": uuid.uuid4().hex,
        "Accept": "application/json",
    }
    if not scheme or not token:
        return headers

    s = scheme.lower()
    if s in {"bearer", "bearerauth", "jwt", "oauth2"}:
        headers["Authorization"] = f"Bearer {token}"
    elif s in {"apikey", "apikeyauth", "x-api-key"}:
        headers["X-API-Key"] = token
    elif s in {"basic", "basicauth"}:
        headers["Authorization"] = f"Basic {token}"
    else:
        # Unknown scheme — try the most common shape.
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _synth_body(
    method: str,
    resource_id: str,
    used_param_names: set[str],
) -> dict[str, Any] | None:
    """Build a minimal JSON body for write methods (POST/PUT/PATCH/DELETE).

    The body intentionally embeds ``resource_id`` for any parameter that
    the OpenAPI spec tied to a path/query position — that way the resulting
    pair exercises the same identifier in both URL and payload.
    """
    body: dict[str, Any] = {"_gsc_bola_fuzz": True}
    for name in sorted(used_param_names):
        body[name] = resource_id
    if method in ("put", "patch") and not used_param_names:
        body["id"] = resource_id
    return body or None


def _append_query(url: str, query: Mapping[str, Any]) -> str:
    """Append a query string to ``url`` while preserving order.

    Uses ``urllib.parse.urlencode`` (stdlib) — we avoid pulling extra deps
    for one line of code.
    """
    from urllib.parse import urlencode
    parts = [(k, "" if v is None else str(v)) for k, v in query.items()]
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urlencode(parts)}"


def _serialize_request(req: requests.Request) -> dict[str, Any]:
    """Render a ``requests.Request`` as a plain dict for JSON output."""
    return {
        "method": req.method,
        "url": req.url,
        "headers": dict(req.headers or {}),
        "json": req.json,
    }
