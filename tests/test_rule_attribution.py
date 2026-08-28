# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for gsc_core.gsc_rule_attribution (legacy title/category → rule_id)."""

from gsc_core.gsc_rule_attribution import (
    LEGACY_SENTINEL,
    QUALITY_TIER,
    attribute,
    attribute_rule_id,
    is_quality,
)


def test_sql_injection():
    assert attribute_rule_id("SQL injection risk: f-string in query") == "GS005"


def test_cyrillic_hardcoded_ip_is_quality():
    # "Хардкод IP адреса" is a removed hardcoded-IP pattern, not a secret —
    # attribute() must bucket it as quality, NOT GS029.
    rid, tier = attribute("Хардкод IP адреса")
    assert rid == LEGACY_SENTINEL
    assert tier == QUALITY_TIER
    # attribute_rule_id() must also NOT map hardcoded-IP to GS029
    # (negative lookahead on the hardcoded/secrets keyword).
    assert attribute_rule_id("Хардкод IP адреса") == LEGACY_SENTINEL
    assert attribute_rule_id("Hardcoded IP address") == LEGACY_SENTINEL


def test_hardcoded_admin_id_and_cidr_are_quality():
    # Hardcoded admin identifier and network CIDR are config smells, not secrets.
    for title in ("Хардкод admin ID", "Хардкод ADMIN_ID в 5 файлах", "Terraform: Hardcoded CIDR"):
        rid, tier = attribute(title)
        assert rid == LEGACY_SENTINEL, title
        assert tier == QUALITY_TIER, title


def test_world_readable():
    assert attribute_rule_id("World-readable sensitive file") == "GS002"


def test_pickle_deserialization():
    assert attribute_rule_id("pickle.load() — unsafe deserialization") == "GS037"


def test_eval_exec():
    assert attribute_rule_id("eval() with dynamic input — code injection") == "GS037"


def test_open_redirect():
    assert attribute_rule_id("Open redirect: user-supplied URL") == "GS022"


def test_legacy_category_redirect():
    assert attribute_rule_id("", "redirect") == "GS022"


def test_legacy_category_ssrf():
    assert attribute_rule_id("", "ssrf") == "GS021"


def test_legacy_category_csrf():
    assert attribute_rule_id("", "csrf") == "GS021"


def test_quality_assert():
    assert is_quality("Python: assert in production")


def test_print_maps_to_debug_detector():
    # print()/console.log/pdb map to GS003 (debug_prints) — consistent with the
    # dedicated debug detector, not a code-quality bucket.
    assert attribute_rule_id("Python print() — debug leftover") == "GS003"


def test_quality_tier():
    # assert-in-production is code-quality, not security.
    rid, tier = attribute("Python: assert in production")
    assert rid == LEGACY_SENTINEL
    assert tier == QUALITY_TIER


def test_ambiguous_falls_through():
    assert attribute_rule_id("Something unrecognizable here") == LEGACY_SENTINEL


def test_empty_title_without_category():
    assert attribute_rule_id("", "") == LEGACY_SENTINEL


def test_file_upload_content_type():
    # Legacy title naming a real security finding (5184 findings in prod DB).
    # Must map to the modern YAML-UPLOAD001 detector, NOT bucket as quality.
    assert attribute_rule_id(
        "Python: File upload without content-type validation"
    ) == "YAML-UPLOAD001"
    rid, tier = attribute(
        "Python: File upload without content-type validation"
    )
    assert rid == "YAML-UPLOAD001"
    assert tier == "normal"


def test_outdated_dependency():
    # Legacy title for an SCA / supply-chain finding (2418 findings in prod DB).
    assert attribute_rule_id("Outdated dependency pattern") == "GS009"
    rid, tier = attribute("Outdated dependency pattern")
    assert rid == "GS009"
    assert tier == "normal"


def test_generic_code_smell_is_quality():
    # The "Generic code smell #N" family (~140k findings) is a placeholder for
    # ambiguous low-signal scans; it must stay out of security attribution.
    for title in ("Generic code smell #1", "Generic code smell #24",
                  "Generic code smell #198"):
        rid, tier = attribute(title)
        assert rid == LEGACY_SENTINEL, title
        assert tier == QUALITY_TIER, title
        assert is_quality(title), title
