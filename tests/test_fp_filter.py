#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for gsc_core.gsc_fp_filter - deterministic FP filters.

Pure tests only: FpVerdict.to_dict, parse_csp, csp_allows_inline,
is_csp_blocking, is_cdn_host, classify, classify_xss, classify_directory_listing.
No network, no I/O. CSP / CDN regex list is exercised end-to-end so any
future change to CDN_PATTERNS that breaks typo-squat resistance (e.g.
removing the end-of-string anchor) will be caught here.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the repo root is importable when pytest is run from any cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gsc_core.gsc_fp_filter import (  # noqa: E402
    CDN_PATTERNS,
    FP_KIND_CDN_HOST,
    FP_KIND_CLEAN,
    FP_KIND_CSP_BLOCKED,
    FpVerdict,
    csp_allows_inline,
    classify,
    classify_directory_listing,
    classify_xss,
    is_cdn_host,
    is_csp_blocking,
    parse_csp,
)


# ── FpVerdict dataclass ────────────────────────────────────
class TestFpVerdict:
    """FpVerdict dataclass + to_dict."""

    def test_to_dict_clean(self):
        v = FpVerdict(kind=FP_KIND_CLEAN, reason="")
        assert v.to_dict() == {"kind": "clean", "reason": ""}

    def test_to_dict_csp_blocked(self):
        v = FpVerdict(
            kind=FP_KIND_CSP_BLOCKED,
            reason="CSP blocks inline",
        )
        out = v.to_dict()
        assert out == {"kind": "csp_blocked", "reason": "CSP blocks inline"}
        assert isinstance(out, dict)
        assert set(out.keys()) == {"kind", "reason"}

    def test_to_dict_cdn_host(self):
        v = FpVerdict(
            kind=FP_KIND_CDN_HOST,
            reason="public CDN",
        )
        assert v.to_dict() == {"kind": "cdn_host", "reason": "public CDN"}


# ── parse_csp ──────────────────────────────────────────────
class TestParseCsp:
    """parse_csp tolerance + tokenisation."""

    def test_basic_script_and_default(self):
        out = parse_csp(
            "default-src 'self'; script-src 'self' https://cdn.example.com"
        )
        assert out == {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
        }

    def test_none_returns_empty(self):
        assert parse_csp(None) == {}

    def test_empty_returns_empty(self):
        assert parse_csp("") == {}

    def test_semicolons_only_returns_empty(self):
        assert parse_csp(";;") == {}

    def test_whitespace_and_newlines(self):
        out = parse_csp(
            "  default-src  'self' ;\n"
            "   script-src  'self'  'unsafe-inline'  ;  "
        )
        assert out == {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
        }

    def test_directive_without_sources(self):
        out = parse_csp("upgrade-insecure-requests; default-src 'self'")
        assert out == {
            "upgrade-insecure-requests": [],
            "default-src": ["'self'"],
        }

    def test_non_string_returns_empty(self):
        # Tolerant: not a string → empty dict, no raise.
        assert parse_csp(123) == {}
        assert parse_csp(["script-src 'self'"]) == {}

    def test_directive_names_lowercased(self):
        out = parse_csp("SCRIPT-SRC 'self'")
        assert "script-src" in out
        assert out["script-src"] == ["'self'"]


# ── csp_allows_inline ──────────────────────────────────────
class TestCspAllowsInline:
    """csp_allows_inline: script-src > default-src, unsafe-inline/eval only."""

    def test_unsafe_inline(self):
        assert csp_allows_inline("script-src 'self' 'unsafe-inline'") is True

    def test_unsafe_eval(self):
        assert csp_allows_inline("script-src 'self' 'unsafe-eval'") is True

    def test_no_inline(self):
        assert csp_allows_inline("script-src 'self'") is False

    def test_script_src_overrides_default(self):
        # default-src allows inline but script-src is strict → False.
        assert csp_allows_inline(
            "default-src 'unsafe-inline'; script-src 'self'"
        ) is False

    def test_default_src_used_when_no_script_src(self):
        # No script-src → fall back to default-src.
        assert csp_allows_inline("default-src 'unsafe-inline'") is True

    def test_no_script_no_default(self):
        assert (
            csp_allows_inline("img-src 'self'; style-src 'self'") is False
        )

    def test_empty(self):
        assert csp_allows_inline("") is False

    def test_none(self):
        assert csp_allows_inline(None) is False

    def test_nonce_only_does_not_count_as_inline(self):
        # Nonces only allow specifically signed scripts, not arbitrary
        # reflection — a reflected payload with no matching nonce is
        # still blocked.
        assert csp_allows_inline(
            "script-src 'self' 'nonce-abc123'"
        ) is False


# ── is_csp_blocking ────────────────────────────────────────
class TestIsCspBlocking:
    """is_csp_blocking: True iff CSP is present and forbids inline/eval."""

    def test_strict_csp_blocks(self):
        assert is_csp_blocking("script-src 'self'") is True

    def test_unsafe_inline_means_not_blocking(self):
        assert (
            is_csp_blocking("script-src 'self' 'unsafe-inline'") is False
        )

    def test_unsafe_eval_means_not_blocking(self):
        assert (
            is_csp_blocking("script-src 'self' 'unsafe-eval'") is False
        )

    def test_empty_not_blocking(self):
        assert is_csp_blocking("") is False

    def test_none_not_blocking(self):
        assert is_csp_blocking(None) is False

    def test_whitespace_only_not_blocking(self):
        assert is_csp_blocking("   \n  ") is False

    def test_unrelated_directive_does_not_block(self):
        # CSP with only img-src cannot block script execution by itself,
        # but presence of any CSP is still a signal. We treat any
        # non-empty parseable CSP without inline/eval as blocking.
        assert is_csp_blocking("img-src 'self'") is True


# ── is_cdn_host ────────────────────────────────────────────
class TestIsCdnHost:
    """is_cdn_host: CDN-suffix match, scheme/port/path stripped."""

    def test_cloudfront_bare(self):
        assert is_cdn_host("d1abc.cloudfront.net") is True

    def test_cloudfront_full_url(self):
        assert (
            is_cdn_host("https://d1abc.cloudfront.net/lib.js") is True
        )

    def test_jsdelivr_full_url(self):
        # Spec example: netloc extraction must work.
        assert is_cdn_host("https://cdn.jsdelivr.net/lib.js") is True

    def test_fastly(self):
        assert is_cdn_host("cdn.example.fastly.net") is True

    def test_cloudflare_root(self):
        assert is_cdn_host("example.cloudflare.com") is True

    def test_akamai(self):
        assert is_cdn_host("x.akamaiedge.net") is True

    def test_s3_website(self):
        assert (
            is_cdn_host("my-bucket.s3-website-us-east-1.amazonaws.com")
            is True
        )

    def test_gcs_storage(self):
        assert (
            is_cdn_host("storage.googleapis.com") is True
        )

    def test_azureedge(self):
        assert is_cdn_host("contoso.azureedge.net") is True

    def test_azurefd(self):
        assert is_cdn_host("contoso.azurefd.net") is True

    def test_cloudinary(self):
        assert is_cdn_host("res.cloudinary.com") is True

    def test_unpkg(self):
        assert is_cdn_host("cdn.jsdelivr.net") is True
        assert is_cdn_host("unpkg.com") is True
        assert is_cdn_host("x.y.unpkg.com") is True

    def test_cdnjs(self):
        assert is_cdn_host("cdnjs.cloudflare.com") is True

    def test_port_stripped(self):
        # Spec example: port in URL must not break the suffix match.
        assert is_cdn_host("cdn.cloudflare.com:443") is True

    def test_port_stripped_full_url(self):
        assert (
            is_cdn_host("https://d1abc.cloudfront.net:8443/x") is True
        )

    def test_non_cdn_host(self):
        assert is_cdn_host("example.com") is False

    def test_typosquat_not_matched(self):
        # ``cloudfront.example.com`` contains the word "cloudfront" but
        # does NOT live under the .cloudfront.net public-suffix domain.
        # Our pattern is anchored, so this must return False.
        assert is_cdn_host("cloudfront.example.com") is False

    def test_typosquat_akamai(self):
        assert is_cdn_host("akamaihd.example.com") is False

    def test_typosquat_jsdelivr(self):
        assert is_cdn_host("jsdelivr.example.org") is False

    def test_userinfo_stripped(self):
        # ``user@host`` should be parsed as host only.
        assert is_cdn_host("https://user@d1abc.cloudfront.net/x") is True

    def test_trailing_dot_stripped(self):
        # DNS root-dot form should still match.
        assert is_cdn_host("d1abc.cloudfront.net.") is True

    def test_none(self):
        assert is_cdn_host(None) is False

    def test_empty(self):
        assert is_cdn_host("") is False

    def test_non_string(self):
        assert is_cdn_host(123) is False
        assert is_cdn_host(["d1abc.cloudfront.net"]) is False

    def test_uppercase_normalised(self):
        # re.IGNORECASE plus lowercased netloc → matches upper-case host.
        assert is_cdn_host("D1ABC.CLOUDFRONT.NET") is True


# ── classify (top-level) ───────────────────────────────────
class TestClassify:
    """classify: CDN-host priority, then CSP, else clean."""

    def test_cdn_host_wins(self):
        # Spec: CDN trumps CSP. Even with a strict CSP, a CDN host is
        # not a security boundary.
        v = classify(
            host="d1abc.cloudfront.net", csp="script-src 'self'"
        )
        assert v.kind == "cdn_host"
        assert v.reason  # non-empty

    def test_csp_blocks(self):
        v = classify(host="example.com", csp="script-src 'self'")
        assert v.kind == "csp_blocked"
        assert v.reason

    def test_clean(self):
        v = classify(host="example.com", csp="")
        assert v.kind == "clean"
        assert v.reason == ""

    def test_cdn_only(self):
        v = classify(host="d1abc.cloudfront.net", csp="")
        assert v.kind == "cdn_host"

    def test_unsafe_inline_clean(self):
        v = classify(host="example.com", csp="script-src 'self' 'unsafe-inline'")
        assert v.kind == "clean"

    def test_defaults_empty(self):
        # classify() with no args should not raise and should return clean.
        v = classify()
        assert v.kind == "clean"

    def test_fpverdict_instance_returned(self):
        v = classify(host="d1abc.cloudfront.net")
        assert isinstance(v, FpVerdict)

    def test_to_dict_round_trip(self):
        v = classify(host="example.com", csp="script-src 'self'")
        out = v.to_dict()
        assert out == {"kind": "csp_blocked", "reason": v.reason}


# ── classify_xss / classify_directory_listing ───────────────
class TestClassifySpecialised:
    """Class-specific shortcuts; both delegate to classify / csp helpers."""

    def test_classify_xss_blocks_on_strict_csp(self):
        v = classify_xss(csp="script-src 'self'")
        assert v.kind == "csp_blocked"

    def test_classify_xss_clean_on_inline(self):
        v = classify_xss(csp="script-src 'self' 'unsafe-inline'")
        assert v.kind == "clean"

    def test_classify_xss_empty(self):
        v = classify_xss()
        assert v.kind == "clean"

    def test_classify_directory_listing_cdn(self):
        v = classify_directory_listing(
            host="cdn.jsdelivr.net", csp=""
        )
        assert v.kind == "cdn_host"

    def test_classify_directory_listing_clean(self):
        v = classify_directory_listing(
            host="example.com", csp=""
        )
        assert v.kind == "clean"


# ── CDN_PATTERNS shape (defensive) ─────────────────────────
class TestCdnPatterns:
    """CDN_PATTERNS structure: every entry is a non-empty lower-case string."""

    def test_at_least_minimum_set(self):
        # Spec: at least the documented CDNs must be present.
        joined = "\n".join(CDN_PATTERNS).lower()
        for needle in (
            "cloudfront",
            "fastly",
            "akamai",
            "cloudflare",
            "amazonaws",
            "googleapis",
            "azureedge",
            "jsdelivr",
            "unpkg",
        ):
            assert needle in joined, f"missing CDN pattern: {needle}"

    def test_every_pattern_anchored(self):
        # Every pattern must end in \Z or \\z so is_cdn_host behaves like
        # a fullmatch. Catches accidental unanchored additions.
        for p in CDN_PATTERNS:
            assert p.endswith("\\Z") or p.endswith("\\z"), (
                f"CDN pattern not anchored: {p!r}"
            )

    def test_every_pattern_non_empty(self):
        for p in CDN_PATTERNS:
            assert isinstance(p, str) and p.strip(), (
                f"empty CDN pattern: {p!r}"
            )
