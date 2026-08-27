#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for gsc_core.gsc_kev — CISA KEV catalog client + parsers.

Pure tests only: parse_kev_json, is_known_exploited, kev_lookup, _normalize,
to_dict, ransomware_known flag handling. No network calls (KevClient.fetch
is intentionally NOT exercised here — it would hit the live CISA feed).
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the repo root is importable when pytest is run from any cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gsc_core.gsc_kev import (  # noqa: E402
    KEVCatalog,
    KevClient,
    KevEntry,
    _normalize,
    is_known_exploited,
    kev_lookup,
    parse_kev_json,
)


# ── Fixtures ──────────────────────────────────────────────
def _valid_payload() -> dict:
    """Realistic CISA KEV JSON payload with two entries."""
    return {
        "catalogVersion": "2024.05.10",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 JNDI lookup RCE.",
                "requiredAction": "Upgrade to Log4j 2.17.1 or later.",
                "dueDate": "2022-05-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Log4Shell.",
            },
            {
                "cveID": "CVE-2017-0144",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "vulnerabilityName": "Windows SMB Remote Code Execution (EternalBlue)",
                "dateAdded": "2017-06-22",
                "shortDescription": "SMBv1 RCE.",
                "requiredAction": "Apply MS17-010 patch.",
                "dueDate": "2017-07-22",
                "knownRansomwareCampaignUse": "Known",
                "notes": "EternalBlue.",
            },
        ],
    }


# ── parse_kev_json: happy path ────────────────────────────
class TestParseKevJsonValid:
    def test_count_and_keys_are_upper(self):
        cat = parse_kev_json(_valid_payload())
        assert cat.count == 2
        assert set(cat.vulnerabilities.keys()) == {"CVE-2021-44228", "CVE-2017-0144"}

    def test_catalog_version_preserved(self):
        cat = parse_kev_json(_valid_payload())
        assert cat.catalog_version == "2024.05.10"

    def test_ransomware_known_true_when_known(self):
        cat = parse_kev_json(_valid_payload())
        assert cat.vulnerabilities["CVE-2021-44228"].ransomware_known is True
        assert cat.vulnerabilities["CVE-2017-0144"].ransomware_known is True

    def test_entry_fields_populated(self):
        cat = parse_kev_json(_valid_payload())
        e = cat.vulnerabilities["CVE-2021-44228"]
        assert e.cve_id == "CVE-2021-44228"
        assert e.vendor_project == "Apache"
        assert e.product == "Log4j"
        assert e.date_added == "2021-12-10"
        assert e.due_date == "2022-05-01"
        assert "Upgrade" in e.required_action


# ── parse_kev_json: empty / malformed ─────────────────────
class TestParseKevJsonEmpty:
    def test_empty_dict(self):
        cat = parse_kev_json({})
        assert cat.count == 0
        assert cat.vulnerabilities == {}
        assert cat.catalog_version == ""

    def test_none_input(self):
        cat = parse_kev_json(None)  # type: ignore[arg-type]
        assert cat.count == 0
        assert cat.vulnerabilities == {}

    def test_non_dict_input(self):
        for bad in ["string", 42, [1, 2, 3], 3.14]:
            cat = parse_kev_json(bad)  # type: ignore[arg-type]
            assert cat.count == 0
            assert cat.vulnerabilities == {}

    def test_vulnerabilities_missing(self):
        cat = parse_kev_json({"catalogVersion": "x", "count": 0})
        assert cat.vulnerabilities == {}

    def test_vulnerabilities_not_list(self):
        cat = parse_kev_json({"vulnerabilities": "not-a-list"})
        assert cat.vulnerabilities == {}

    def test_items_not_dict_are_skipped(self):
        payload = {
            "vulnerabilities": [
                "raw-string",
                42,
                {"cveID": "CVE-2020-1234"},
            ]
        }
        cat = parse_kev_json(payload)
        assert list(cat.vulnerabilities.keys()) == ["CVE-2020-1234"]


# ── parse_kev_json: missing fields ────────────────────────
class TestParseKevJsonDefaults:
    def test_missing_due_date_defaults_empty(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2020-1111", "vendorProject": "Acme"}]}
        cat = parse_kev_json(payload)
        e = cat.vulnerabilities["CVE-2020-1111"]
        assert e.due_date == ""
        assert e.ransomware_known is False
        assert e.vendor_project == "Acme"

    def test_missing_ransomware_flag_defaults_false(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2020-2222"}]}
        cat = parse_kev_json(payload)
        assert cat.vulnerabilities["CVE-2020-2222"].ransomware_known is False

    def test_ransomware_known_string_variants(self):
        for raw, expected in [
            ("Known", True),
            ("known", True),  # case-insensitive
            ("KNOWN", True),
            ("Unknown", False),
            ("", False),
        ]:
            payload = {"vulnerabilities": [{"cveID": "CVE-2020-3333",
                                           "knownRansomwareCampaignUse": raw}]}
            cat = parse_kev_json(payload)
            assert cat.vulnerabilities["CVE-2020-3333"].ransomware_known is expected, raw

    def test_missing_cve_id_skipped(self):
        payload = {"vulnerabilities": [{"vendorProject": "Acme"}, {"cveID": "CVE-2020-4444"}]}
        cat = parse_kev_json(payload)
        assert list(cat.vulnerabilities.keys()) == ["CVE-2020-4444"]


# ── is_known_exploited ────────────────────────────────────
class TestIsKnownExploited:
    def _cat(self):
        return parse_kev_json(_valid_payload())

    def test_present_returns_true(self):
        assert is_known_exploited("CVE-2021-44228", self._cat()) is True

    def test_lowercase_input_normalised(self):
        assert is_known_exploited("cve-2021-44228", self._cat()) is True

    def test_absent_returns_false(self):
        assert is_known_exploited("CVE-2099-99999", self._cat()) is False

    def test_none_returns_false(self):
        assert is_known_exploited(None, self._cat()) is False  # type: ignore[arg-type]

    def test_empty_string_returns_false(self):
        assert is_known_exploited("", self._cat()) is False

    def test_non_cve_returns_false(self):
        assert is_known_exploited("GHSA-xxxx-yyyy-zzzz", self._cat()) is False

    def test_empty_catalog_returns_false(self):
        assert is_known_exploited("CVE-2021-44228",
                                  KEVCatalog(catalog_version="", count=0,
                                             vulnerabilities={})) is False


# ── kev_lookup ────────────────────────────────────────────
class TestKevLookup:
    def _cat(self):
        return parse_kev_json(_valid_payload())

    def test_returns_only_present_cves(self):
        result = kev_lookup(
            ["CVE-2021-44228", "CVE-2099-99999", "CVE-2017-0144"], self._cat()
        )
        assert set(result.keys()) == {"CVE-2021-44228", "CVE-2017-0144"}
        assert isinstance(result["CVE-2021-44228"], KevEntry)

    def test_empty_list_returns_empty_dict(self):
        assert kev_lookup([], self._cat()) == {}

    def test_none_entries_skipped(self):
        result = kev_lookup(["CVE-2021-44228", None, "", "GHSA-x"], self._cat())  # type: ignore[list-item]
        assert set(result.keys()) == {"CVE-2021-44228"}

    def test_empty_catalog_returns_empty_dict(self):
        empty = KEVCatalog(catalog_version="", count=0, vulnerabilities={})
        assert kev_lookup(["CVE-2021-44228"], empty) == {}

    def test_normalises_input(self):
        result = kev_lookup(["cve-2021-44228"], self._cat())
        assert "CVE-2021-44228" in result


# ── _normalize ────────────────────────────────────────────
class TestNormalize:
    def test_lowercase_uppercased(self):
        assert _normalize("cve-2021-44228") == "CVE-2021-44228"

    def test_mixed_case_uppercased(self):
        assert _normalize("Cve-2021-44228") == "CVE-2021-44228"

    def test_already_upper(self):
        assert _normalize("CVE-2017-0144") == "CVE-2017-0144"

    def test_ghsa_returns_empty(self):
        # GHSA is not a CVE — KEV only tracks CVEs.
        assert _normalize("GHSA-xxxx-yyyy-zzzz") == ""

    def test_pysec_returns_empty(self):
        assert _normalize("PYSEC-2021-999") == ""

    def test_empty_returns_empty(self):
        assert _normalize("") == ""

    def test_none_returns_empty(self):
        assert _normalize(None) == ""  # type: ignore[arg-type]

    def test_embedded_cve_extracted(self):
        # If a longer string embeds a CVE token, the regex picks it out.
        assert _normalize("see CVE-2021-44228 / log4j") == "CVE-2021-44228"


# ── to_dict round-trip ────────────────────────────────────
class TestToDict:
    def test_kev_entry_to_dict(self):
        e = KevEntry(
            cve_id="CVE-2021-44228", vendor_project="Apache", product="Log4j",
            date_added="2021-12-10", due_date="2022-05-01",
            ransomware_known=True, required_action="Upgrade",
        )
        d = e.to_dict()
        assert d == {
            "cve_id": "CVE-2021-44228",
            "vendor_project": "Apache",
            "product": "Log4j",
            "date_added": "2021-12-10",
            "due_date": "2022-05-01",
            "ransomware_known": True,
            "required_action": "Upgrade",
        }

    def test_kev_catalog_to_dict(self):
        cat = parse_kev_json(_valid_payload())
        d = cat.to_dict()
        assert d["catalog_version"] == "2024.05.10"
        assert d["count"] == 2
        assert "CVE-2021-44228" in d["vulnerabilities"]
        assert d["vulnerabilities"]["CVE-2021-44228"]["ransomware_known"] is True


# ── KevClient construction (no network) ───────────────────
class TestKevClientConstruction:
    def test_default_construction(self):
        c = KevClient()
        assert c.timeout == 30

    def test_custom_timeout(self):
        c = KevClient(timeout=5)
        assert c.timeout == 5
