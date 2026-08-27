#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""Tests for gsc_cli.gsc_subdomain_enum — passive subdomain enumeration via crt.sh.

Pure tests only: parse_crt_sh_json, normalize_subdomains, resolve_host,
filter_live, EnumResult.to_dict. SubdomainClient.fetch is intentionally
NOT exercised here — it would hit the live crt.sh endpoint.

DNS resolution tests are best-effort: ``localhost`` should always resolve
on a sane machine, but a sandboxed CI environment may lack a working
resolver. The test uses a TLD that cannot legally exist
(``.invalid``) for the negative case so the resolver returns
``socket.gaierror`` regardless of environment.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the repo root is importable when pytest is run from any cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gsc_recon.subdomain_enum import (  # noqa: E402
    EnumResult,
    SubdomainClient,
    filter_live,
    normalize_subdomains,
    parse_crt_sh_json,
    resolve_host,
)


# ── Fixtures ──────────────────────────────────────────────
def _valid_crt_sh_payload() -> list:
    """Realistic crt.sh JSON: two records, one with multi-domain name_value."""
    return [
        {
            "issuer_ca_id": 1,
            "issuer_name": "Let's Encrypt",
            "common_name": "example.com",
            "name_value": "a.example.com\n*.example.com",
            "id": 100,
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
        },
        {
            "issuer_ca_id": 2,
            "issuer_name": "DigiCert",
            "common_name": "b.example.com",
            "name_value": "b.example.com",
            "id": 101,
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
        },
    ]


# ── parse_crt_sh_json: happy path ─────────────────────────
class TestParseCrtShJsonValid:
    def test_returns_raw_domains_with_multiline_split(self):
        """Two records, one with newline-separated name_value — must yield
        both ``a.example.com`` and ``*.example.com`` in the raw list."""
        result = parse_crt_sh_json(_valid_crt_sh_payload(), "example.com")
        assert isinstance(result, list)
        assert "a.example.com" in result
        assert "*.example.com" in result
        # The second record contributes its own single-domain name_value.
        assert result.count("b.example.com") == 1

    def test_count_matches_all_split_pieces(self):
        """First record contributes 2 pieces, second contributes 1 -> 3 total."""
        result = parse_crt_sh_json(_valid_crt_sh_payload(), "example.com")
        assert len(result) == 3


# ── parse_crt_sh_json: tolerance ──────────────────────────
class TestParseCrtShJsonTolerant:
    def test_none_returns_empty_list(self):
        assert parse_crt_sh_json(None, "example.com") == []

    def test_non_list_returns_empty_list(self):
        assert parse_crt_sh_json({"not": "a list"}, "example.com") == []
        assert parse_crt_sh_json("string", "example.com") == []
        assert parse_crt_sh_json(42, "example.com") == []

    def test_empty_list_returns_empty_list(self):
        assert parse_crt_sh_json([], "example.com") == []

    def test_record_without_name_value_is_skipped(self):
        payload = [
            {"id": 1, "common_name": "no-name-value.example.com"},
            {"id": 2, "name_value": "ok.example.com"},
        ]
        result = parse_crt_sh_json(payload, "example.com")
        assert result == ["ok.example.com"]

    def test_record_with_empty_name_value_is_skipped(self):
        payload = [
            {"id": 1, "name_value": ""},
            {"id": 2, "name_value": "ok.example.com"},
        ]
        result = parse_crt_sh_json(payload, "example.com")
        assert result == ["ok.example.com"]

    def test_non_dict_records_are_skipped(self):
        payload = [
            "not a dict",
            42,
            None,
            {"id": 1, "name_value": "ok.example.com"},
        ]
        result = parse_crt_sh_json(payload, "example.com")
        assert result == ["ok.example.com"]

    def test_non_string_name_value_is_skipped(self):
        payload = [
            {"id": 1, "name_value": 42},
            {"id": 2, "name_value": None},
            {"id": 3, "name_value": "ok.example.com"},
        ]
        result = parse_crt_sh_json(payload, "example.com")
        assert result == ["ok.example.com"]


# ── normalize_subdomains ──────────────────────────────────
class TestNormalizeSubdomains:
    def test_full_normalisation_example_from_spec(self):
        """Spec example: lower-case, strip ``*.``, drop off-suffix, dedup, sort."""
        result = normalize_subdomains(
            [
                "A.Example.com",
                "*.example.com",
                "example.com",
                "b.example.com",
                "evil.com",
                "a.example.com",
            ],
            "example.com",
        )
        assert result == ["a.example.com", "b.example.com", "example.com"]

    def test_empty_list_returns_empty_list(self):
        assert normalize_subdomains([], "example.com") == []

    def test_none_returns_empty_list(self):
        assert normalize_subdomains(None, "example.com") == []

    def test_non_list_returns_empty_list(self):
        assert normalize_subdomains("not a list", "example.com") == []
        assert normalize_subdomains({"a": 1}, "example.com") == []

    def test_non_string_elements_are_skipped(self):
        result = normalize_subdomains(
            [None, 42, "a.example.com", "", "   ", "b.example.com"],
            "example.com",
        )
        assert result == ["a.example.com", "b.example.com"]

    def test_wildcard_marker_stripped_and_off_suffix_dropped(self):
        result = normalize_subdomains(
            ["*.example.com", "*.evil.com", "sub.evil.com"],
            "example.com",
        )
        # ``*.example.com`` -> ``example.com`` (kept, equals apex).
        # ``*.evil.com`` -> ``evil.com`` (off-suffix, dropped).
        # ``sub.evil.com`` -> off-suffix, dropped.
        assert result == ["example.com"]

    def test_apex_itself_kept_alongside_subs(self):
        result = normalize_subdomains(
            ["example.com", "www.example.com", "api.example.com"],
            "example.com",
        )
        assert result == ["api.example.com", "example.com", "www.example.com"]

    def test_duplicates_removed(self):
        result = normalize_subdomains(
            ["a.example.com", "A.EXAMPLE.com", "*.example.com", "a.example.com"],
            "example.com",
        )
        assert result == ["a.example.com", "example.com"]

    def test_empty_apex_does_not_filter_by_suffix(self):
        """If apex is blank, every cleaned, deduped entry is returned."""
        result = normalize_subdomains(
            ["a.example.com", "B.other.com", "*.example.com", "a.example.com"],
            "",
        )
        # ``*.example.com`` -> ``example.com`` (a new distinct entry).
        # ``a.example.com`` dedupes; ``B.other.com`` lower-cases to ``b.other.com``.
        assert result == ["a.example.com", "b.other.com", "example.com"]


# ── resolve_host ──────────────────────────────────────────
class TestResolveHost:
    def test_localhost_resolves_to_loopback(self):
        """``localhost`` must always resolve to a loopback address in any
        sane environment. We assert it is a non-empty string — not None
        — to stay compatible with sandboxes that may block DNS but
        always have ``/etc/hosts`` for loopback."""
        result = resolve_host("localhost")
        assert result is not None
        assert isinstance(result, str)
        assert result  # non-empty

    def test_nonexistent_invalid_returns_none(self):
        """``.invalid`` is an RFC-2606 reserved TLD that must never resolve."""
        assert resolve_host("nonexistent.invalid") is None

    def test_empty_string_returns_none(self):
        assert resolve_host("") is None
        assert resolve_host("   ") is None

    def test_non_string_returns_none(self):
        assert resolve_host(None) is None  # type: ignore[arg-type]
        assert resolve_host(42) is None  # type: ignore[arg-type]


# ── filter_live ───────────────────────────────────────────
class TestFilterLive:
    def test_keeps_resolvable_drops_unresolvable(self):
        """Live filter must keep ``localhost`` and drop ``nonexistent.invalid``."""
        result = filter_live(["localhost", "nonexistent.invalid"])
        assert "localhost" in result
        assert "nonexistent.invalid" not in result

    def test_empty_list_returns_empty_list(self):
        assert filter_live([]) == []

    def test_none_returns_empty_list(self):
        assert filter_live(None) == []  # type: ignore[arg-type]

    def test_non_string_elements_are_skipped(self):
        result = filter_live([None, 42, "localhost", ""])
        # ``localhost`` survives the non-string filter and resolves; the
        # empty string is dropped before the resolver call.
        assert result == ["localhost"]


# ── EnumResult ────────────────────────────────────────────
class TestEnumResult:
    def test_default_subdomains_is_empty_list(self):
        """Default factory must yield a fresh list per instance (not a
        shared mutable default)."""
        r1 = EnumResult(domain="example.com")
        r2 = EnumResult(domain="other.com")
        assert r1.subdomains == []
        assert r2.subdomains == []
        r1.subdomains.append("a.example.com")
        assert r2.subdomains == []  # isolated from r1's mutation

    def test_to_dict_structure(self):
        r = EnumResult(domain="example.com", subdomains=["a.example.com", "b.example.com"])
        d = r.to_dict()
        assert isinstance(d, dict)
        assert set(d.keys()) == {"domain", "subdomains"}
        assert d["domain"] == "example.com"
        assert d["subdomains"] == ["a.example.com", "b.example.com"]

    def test_to_dict_returns_independent_list_copy(self):
        r = EnumResult(domain="example.com", subdomains=["a.example.com"])
        d = r.to_dict()
        d["subdomains"].append("mutated.example.com")
        # The dataclass's own list must not see the mutation.
        assert r.subdomains == ["a.example.com"]


# ── SubdomainClient construction (no network) ─────────────
class TestSubdomainClientConstruction:
    def test_default_timeout_is_30(self):
        client = SubdomainClient()
        assert client.timeout == 30

    def test_custom_timeout_is_stored(self):
        client = SubdomainClient(timeout=5)
        assert client.timeout == 5
