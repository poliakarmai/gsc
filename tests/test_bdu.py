#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for gsc_core.gsc_bdu — FSTEC BDU catalog client + parsers.

Pure tests only: parse_bdu_json, _normalize_identifier, _normalize_cve,
is_known_bdu, bdu_lookup, bdu_lookup_identifier, BduEntry.to_dict and
BduClient construction. No network calls — BduClient.fetch is
intentionally NOT exercised here, it would hit the live FSTEC feed.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the repo root is importable when pytest is run from any cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gsc_core.gsc_bdu import (  # noqa: E402
    BDU_JSON_URL,
    HTTP_TIMEOUT,
    BduClient,
    BduEntry,
    _normalize_cve,
    _normalize_identifier,
    bdu_lookup,
    bdu_lookup_identifier,
    is_known_bdu,
    parse_bdu_json,
)


# ── Fixtures ──────────────────────────────────────────────
def _sample_records() -> list:
    """Realistic FSTEC BDU export — two records with CVEs and a third
    record that references two CVEs in the comma-separated string form
    the FSTEC public export occasionally uses."""
    return [
        {
            "identifier": "BDU:2025-00001",
            "name": "Уязвимость ядра Linux",
            "description": "Use-after-free в сетевом стеке.",
            "vendor": "Linux",
            "product": "Kernel",
            "vulnerability_class": "Use After Free",
            "cve_identifiers": ["CVE-2025-12345"],
            "cvss_score": "9.8",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "date_discovered": "2025-01-15",
            "date_updated": "2025-01-20",
        },
        {
            "identifier": "BDU:2024-00042",
            "name": "Уязвимость Apache HTTP Server",
            "description": "Path traversal in mod_rewrite.",
            "vendor": "Apache",
            "product": "HTTP Server",
            "vulnerability_class": "Path Traversal",
            "cve_identifiers": ["cve-2024-27316", "CVE-2024-27317"],
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "date_discovered": "2024-03-10",
        },
        {
            "identifier": "BDU:2023-00007",
            "name": "Уязвимость OpenSSL",
            "description": "Memory corruption in TLS handshake.",
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "vulnerability_class": "Memory Corruption",
            # The FSTEC export sometimes uses a single comma-separated
            # string instead of a JSON array.
            "cve_identifiers": "CVE-2023-0286, CVE-2023-0464",
            "cvss_score": "9.8",
            "cvss_vector": "CVSS:3.1/AV:N",
            "date_discovered": "2023-02-08",
        },
    ]


def _parsed() -> list:
    return parse_bdu_json(_sample_records())


# ── _normalize_identifier ─────────────────────────────────
class TestNormalizeIdentifier:
    def test_canonical_passthrough(self):
        assert _normalize_identifier("BDU:2025-00001") == "BDU:2025-00001"

    def test_lowercase_with_short_ordinal_pads_to_5(self):
        # "bdu:2025-1" → "BDU:2025-00001" (case + zero-pad).
        assert _normalize_identifier("bdu:2025-1") == "BDU:2025-00001"

    def test_hyphens_collapse_to_colons(self):
        # Hyphens-as-separators form is tolerated.
        assert _normalize_identifier("BDU-2025-00001") == "BDU:2025-00001"

    def test_no_prefix_year_ordinal_gets_prefix(self):
        # "2025-00042" (no BDU prefix) → "BDU:2025-00042".
        assert _normalize_identifier("2025-00042") == "BDU:2025-00042"

    def test_cve_returns_none(self):
        # CVE-… is not a BDU ID.
        assert _normalize_identifier("CVE-2025-1234") is None

    def test_none_returns_none(self):
        assert _normalize_identifier(None) is None  # type: ignore[arg-type]

    def test_empty_returns_none(self):
        assert _normalize_identifier("") is None

    def test_garbage_returns_none(self):
        assert _normalize_identifier("totally not a bdu id") is None

    def test_whitespace_only_returns_none(self):
        assert _normalize_identifier("   ") is None

    def test_non_string_returns_none(self):
        assert _normalize_identifier(12345) is None  # type: ignore[arg-type]

    def test_uppercase_mixed_is_normalised(self):
        # The prefix is case-insensitive, the result is UPPER.
        assert _normalize_identifier("Bdu:2025-00042") == "BDU:2025-00042"

    def test_embedded_match_extracted(self):
        # If a longer string embeds a BDU token, the regex picks it out.
        assert (
            _normalize_identifier("see record BDU:2025-00099 / log4j")
            == "BDU:2025-00099"
        )

    def test_long_ordinal_padded_not_truncated(self):
        # 6-digit ordinals are zero-padded to 5, then 1 leading zero is
        # added → "BDU:2025-100000" stays "BDU:2025-100000" because
        # zfill(5) is a no-op for inputs ≥ 5 digits.  The point of this
        # test is that the function does not crash on longer ordinals.
        result = _normalize_identifier("BDU:2025-100000")
        assert result == "BDU:2025-100000"


# ── _normalize_cve ────────────────────────────────────────
class TestNormalizeCve:
    def test_lowercase_uppercased(self):
        assert _normalize_cve("cve-2025-1234") == "CVE-2025-1234"

    def test_already_upper(self):
        assert _normalize_cve("CVE-2025-1234") == "CVE-2025-1234"

    def test_xss_returns_none(self):
        # Not a CVE.
        assert _normalize_cve("XSS") is None

    def test_none_returns_none(self):
        assert _normalize_cve(None) is None  # type: ignore[arg-type]

    def test_empty_returns_none(self):
        assert _normalize_cve("") is None

    def test_non_string_returns_none(self):
        assert _normalize_cve(20251234) is None  # type: ignore[arg-type]

    def test_embedded_cve_extracted(self):
        assert _normalize_cve("see CVE-2021-44228 / log4j") == "CVE-2021-44228"


# ── parse_bdu_json: happy path ────────────────────────────
class TestParseBduJsonValid:
    def test_returns_three_entries_for_three_records(self):
        entries = _parsed()
        assert len(entries) == 3

    def test_identifiers_normalised(self):
        entries = _parsed()
        assert entries[0].identifier == "BDU:2025-00001"
        assert entries[1].identifier == "BDU:2024-00042"
        assert entries[2].identifier == "BDU:2023-00007"

    def test_fields_extracted(self):
        entries = _parsed()
        assert entries[0].name == "Уязвимость ядра Linux"
        assert entries[0].vendor == "Linux"
        assert entries[0].product == "Kernel"
        assert entries[0].vuln_class == "Use After Free"
        assert entries[0].cvss_vector.startswith("CVSS:3.1/")

    def test_cve_list_normalised_to_upper(self):
        entries = _parsed()
        assert entries[1].cve_ids == ["CVE-2024-27316", "CVE-2024-27317"]

    def test_cve_string_form_is_split(self):
        entries = _parsed()
        # "CVE-2023-0286, CVE-2023-0464" → two CVEs.
        assert entries[2].cve_ids == ["CVE-2023-0286", "CVE-2023-0464"]

    def test_cvss_score_is_float(self):
        entries = _parsed()
        # "9.8" (str) → 9.8 (float); 7.5 (int) → 7.5 (float).
        assert entries[0].cvss_score == 9.8
        assert entries[1].cvss_score == 7.5
        assert entries[2].cvss_score == 9.8

    def test_date_falls_back_to_date_discovered(self):
        entries = _parsed()
        assert entries[0].date == "2025-01-15"

    def test_accepts_json_string(self):
        import json as _json
        entries = parse_bdu_json(_json.dumps(_sample_records(), ensure_ascii=False))
        assert len(entries) == 3
        assert entries[0].identifier == "BDU:2025-00001"

    def test_accepts_bytes(self):
        import json as _json
        raw = _json.dumps(_sample_records(), ensure_ascii=False).encode("utf-8")
        entries = parse_bdu_json(raw)
        assert len(entries) == 3


# ── parse_bdu_json: defaults & tolerance ──────────────────
class TestParseBduJsonDefaults:
    def test_empty_record_yields_defaults(self):
        entries = parse_bdu_json([{}])
        assert entries == []

    def test_record_without_bdu_identifier_is_skipped(self):
        # A record with no recognisable BDU id is dropped.
        entries = parse_bdu_json([{"name": "orphan", "cve_identifiers": ["CVE-2025-1"]}])
        assert entries == []

    def test_partial_record_uses_string_defaults(self):
        # Only an identifier is required for the entry to exist; the
        # rest defaults to "" / [] / None.
        entries = parse_bdu_json([{"identifier": "BDU:2025-00099"}])
        assert len(entries) == 1
        e = entries[0]
        assert e.identifier == "BDU:2025-00099"
        assert e.name == ""
        assert e.description == ""
        assert e.vendor == ""
        assert e.product == ""
        assert e.vuln_class == ""
        assert e.cve_ids == []
        assert e.cvss_score is None
        assert e.cvss_vector == ""
        assert e.date == ""

    def test_cvss_score_garbage_string_yields_none(self):
        entries = parse_bdu_json(
            [{"identifier": "BDU:2025-00001", "cvss_score": "abc"}]
        )
        assert entries[0].cvss_score is None

    def test_cvss_score_none_yields_none(self):
        entries = parse_bdu_json(
            [{"identifier": "BDU:2025-00001", "cvss_score": None}]
        )
        assert entries[0].cvss_score is None

    def test_cvss_score_int_yields_float(self):
        entries = parse_bdu_json(
            [{"identifier": "BDU:2025-00001", "cvss_score": 7}]
        )
        assert entries[0].cvss_score == 7.0
        assert isinstance(entries[0].cvss_score, float)

    def test_cve_identifiers_mixed_duplicates_dropped(self):
        # Duplicates (and case variants) collapse to one canonical UPPER id.
        entries = parse_bdu_json(
            [
                {
                    "identifier": "BDU:2025-00001",
                    "cve_identifiers": ["CVE-2025-1234", "CVE-2025-1234", "cve-2025-1234"],
                }
            ]
        )
        assert entries[0].cve_ids == ["CVE-2025-1234"]

    def test_cve_identifiers_with_non_strings(self):
        # The FSTEC export sometimes has ints or None inside the list.
        # ``42`` does not match the CVE regex (4-7 digits after the year),
        # so it is dropped; None is skipped; valid CVEs are kept.
        entries = parse_bdu_json(
            [
                {
                    "identifier": "BDU:2025-00001",
                    "cve_identifiers": ["CVE-2025-1234", None, 42, "CVE-2025-1235"],
                }
            ]
        )
        assert entries[0].cve_ids == ["CVE-2025-1234", "CVE-2025-1235"]

    def test_non_dict_records_are_skipped(self):
        entries = parse_bdu_json(
            [
                "BDU:2025-00001",
                42,
                None,
                ["nested", "list"],
                {"identifier": "BDU:2025-00042"},
            ]
        )
        assert len(entries) == 1
        assert entries[0].identifier == "BDU:2025-00042"

    def test_identifier_fallback_alternate_fields(self):
        # Some exports use identifier_number / bdu_id / id instead of identifier.
        entries = parse_bdu_json(
            [
                {"identifier_number": "2025-00042"},
                {"bdu_id": "BDU:2025-00043"},
                {"id": "2025-00044"},
            ]
        )
        assert [e.identifier for e in entries] == [
            "BDU:2025-00042",
            "BDU:2025-00043",
            "BDU:2025-00044",
        ]


# ── parse_bdu_json: bad input → [] ────────────────────────
class TestParseBduJsonBadInput:
    def test_none_returns_empty(self):
        assert parse_bdu_json(None) == []

    def test_empty_string_returns_empty(self):
        assert parse_bdu_json("") == []

    def test_whitespace_string_returns_empty(self):
        assert parse_bdu_json("   \n\t  ") == []

    def test_not_json_returns_empty(self):
        assert parse_bdu_json("not json {{{") == []

    def test_empty_json_array_returns_empty(self):
        assert parse_bdu_json("[]") == []

    def test_non_list_json_returns_empty(self):
        # A JSON object (not an array) is not a BDU export.
        assert parse_bdu_json('{"a": 1}') == []

    def test_bytes_invalid_utf8_returns_empty(self):
        # Bytes that aren't valid UTF-8 (after replacement) AND aren't
        # valid JSON: must not raise.
        assert parse_bdu_json(b"\xff\xfe not json") == []

    def test_bytes_garbage_returns_empty(self):
        assert parse_bdu_json(b"definitely not json") == []

    def test_non_collection_type_returns_empty(self):
        assert parse_bdu_json(42) == []  # type: ignore[arg-type]


# ── BduEntry.to_dict ──────────────────────────────────────
class TestBduEntryToDict:
    def test_minimal_to_dict(self):
        e = BduEntry(identifier="BDU:2025-00001")
        d = e.to_dict()
        assert d == {
            "identifier": "BDU:2025-00001",
            "name": "",
            "description": "",
            "vendor": "",
            "product": "",
            "vuln_class": "",
            "cve_ids": [],
            "cvss_score": None,
            "cvss_vector": "",
            "date": "",
        }

    def test_full_to_dict_round_trip(self):
        e = BduEntry(
            identifier="BDU:2025-00001",
            name="x",
            description="y",
            vendor="v",
            product="p",
            vuln_class="c",
            cve_ids=["CVE-2025-1234"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N",
            date="2025-01-15",
        )
        assert e.to_dict()["identifier"] == "BDU:2025-00001"
        assert e.to_dict()["cvss_score"] == 9.8
        # CVE ordinals are preserved as-is (4-7 digits, no padding).
        assert e.to_dict()["cve_ids"] == ["CVE-2025-1234"]

    def test_to_dict_returns_copy_of_cve_list(self):
        e = BduEntry(identifier="BDU:2025-00001", cve_ids=["CVE-2025-1234"])
        d = e.to_dict()
        d["cve_ids"].append("CVE-2025-9999")
        # Mutating the dict's list must not affect the entry.
        assert e.cve_ids == ["CVE-2025-1234"]


# ── is_known_bdu ──────────────────────────────────────────
class TestIsKnownBdu:
    def test_known_identifier_returns_true(self):
        entries = _parsed()
        assert is_known_bdu(entries, "BDU:2025-00001") is True

    def test_unknown_identifier_returns_false(self):
        entries = _parsed()
        assert is_known_bdu(entries, "BDU:2024-99999") is False

    def test_normalisation_works(self):
        entries = _parsed()
        # Lowercase + short ordinal should still match after padding.
        assert is_known_bdu(entries, "bdu:2025-1") is True
        # Hyphens-as-separator form.
        assert is_known_bdu(entries, "BDU-2025-00001") is True

    def test_empty_entries_returns_false(self):
        assert is_known_bdu([], "BDU:2025-00001") is False

    def test_none_identifier_returns_false(self):
        assert is_known_bdu(_parsed(), None) is False  # type: ignore[arg-type]

    def test_garbage_identifier_returns_false(self):
        assert is_known_bdu(_parsed(), "CVE-2025-1234") is False


# ── bdu_lookup (by CVE) ───────────────────────────────────
class TestBduLookup:
    def test_finds_records_with_matching_cve(self):
        entries = _parsed()
        result = bdu_lookup(entries, "CVE-2025-12345")
        assert len(result) == 1
        assert result[0].identifier == "BDU:2025-00001"

    def test_returns_multiple_records_sharing_a_cve(self):
        # Build a catalog where two records share a CVE.
        entries = parse_bdu_json(
            [
                {
                    "identifier": "BDU:2025-00001",
                    "name": "first",
                    "cve_identifiers": ["CVE-2025-12345"],
                },
                {
                    "identifier": "BDU:2025-00002",
                    "name": "second",
                    "cve_identifiers": ["CVE-2025-12345"],
                },
            ]
        )
        result = bdu_lookup(entries, "CVE-2025-12345")
        assert len(result) == 2
        assert {e.identifier for e in result} == {
            "BDU:2025-00001",
            "BDU:2025-00002",
        }

    def test_unknown_cve_returns_empty(self):
        entries = _parsed()
        assert bdu_lookup(entries, "CVE-1111-0000") == []

    def test_lowercase_cve_is_normalised(self):
        entries = _parsed()
        result = bdu_lookup(entries, "cve-2025-12345")
        assert len(result) == 1

    def test_non_cve_input_returns_empty(self):
        entries = _parsed()
        assert bdu_lookup(entries, "XSS") == []
        assert bdu_lookup(entries, "") == []
        assert bdu_lookup(entries, None) == []  # type: ignore[arg-type]

    def test_empty_entries_returns_empty(self):
        assert bdu_lookup([], "CVE-2025-12345") == []


# ── bdu_lookup_identifier (bonus) ─────────────────────────
class TestBduLookupIdentifier:
    def test_known_identifier_returns_entry(self):
        entries = _parsed()
        result = bdu_lookup_identifier(entries, "BDU:2025-00001")
        assert isinstance(result, BduEntry)
        assert result.identifier == "BDU:2025-00001"

    def test_unknown_identifier_returns_none(self):
        entries = _parsed()
        assert bdu_lookup_identifier(entries, "BDU:2099-99999") is None

    def test_normalisation_works(self):
        entries = _parsed()
        # Case + padding tolerance.
        result = bdu_lookup_identifier(entries, "bdu:2025-1")
        assert result is not None
        assert result.identifier == "BDU:2025-00001"

    def test_non_string_returns_none(self):
        entries = _parsed()
        assert bdu_lookup_identifier(entries, None) is None  # type: ignore[arg-type]
        assert bdu_lookup_identifier(entries, 12345) is None  # type: ignore[arg-type]

    def test_empty_entries_returns_none(self):
        assert bdu_lookup_identifier([], "BDU:2025-00001") is None


# ── BduClient construction (no network) ───────────────────
class TestBduClientConstruction:
    def test_default_construction(self):
        c = BduClient()
        assert c.timeout == HTTP_TIMEOUT == 30
        assert c.url == BDU_JSON_URL == "https://bdu.fstec.ru/api/v1/vul"

    def test_custom_timeout(self):
        c = BduClient(timeout=5)
        assert c.timeout == 5

    def test_custom_url(self):
        c = BduClient(url="https://example.test/bdu.json")
        assert c.url == "https://example.test/bdu.json"

    def test_custom_timeout_and_url(self):
        c = BduClient(timeout=10, url="http://localhost:9/bdu")
        assert c.timeout == 10
        assert c.url == "http://localhost:9/bdu"
