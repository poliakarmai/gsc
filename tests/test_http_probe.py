#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""
Tests for gsc_recon/http_probe.py
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from gsc_recon.http_probe import (  # type: ignore
    ProbeResult,
    extract_server,
    is_reachable,
    normalize_url,
)


# ── Pure function tests ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host,scheme,expected",
    [
        ("example.com", "https", "https://example.com"),
        ("http://example.com", "https", "http://example.com"),
        ("https://example.com/", "https", "https://example.com"),
        ("example.com/path/", "https", "https://example.com/path"),
        ("example.com", "http", "http://example.com"),
        ("", "https", ""),
        (None, "https", ""),
        (123, "https", ""),  # Non-string input
        ("  example.com  ", "https", "https://example.com"), # Strip whitespace
        ("example.com/path?query=val", "https", "https://example.com/path?query=val"),
        ("example.com:8080", "https", "https://example.com:8080"),
    ],
)
def test_normalize_url(host: Any, scheme: str, expected: str) -> None:
    assert normalize_url(host, scheme) == expected


@pytest.mark.parametrize(
    "headers,expected",
    [
        ({"Server": "nginx"}, "nginx"),
        ({"server": "Apache/2.4"}, "Apache/2.4"),  # Case-insensitive header name
        ({"X-Powered-By": "PHP"}, ""),  # Other header, not "Server"
        ({}, ""),
        (None, ""),
        ({"Server": None}, ""), # None value
        ({"SERVER": "Microsoft-IIS/10.0"}, "Microsoft-IIS/10.0"),
        ({"Content-Type": "application/json"}, ""),
    ],
)
def test_extract_server(headers: Any, expected: str) -> None:
    assert extract_server(headers) == expected


@pytest.mark.parametrize(
    "status_code,expected",
    [
        (200, True),
        (204, True),
        (301, True),
        (302, True),
        (399, True),
        (400, False),
        (404, False),
        (500, False),
        (100, False),
        (0, False),  # Default status code for errors
        (None, False), # Invalid input type
        ("200", False), # Invalid input type
    ],
)
def test_is_reachable(status_code: Any, expected: bool) -> None:
    assert is_reachable(status_code) == expected


# ── ProbeResult tests ─────────────────────────────────────────────────────────

def test_proberesult_to_dict_structure() -> None:
    result = ProbeResult(
        url="https://example.com",
        status_code=200,
        headers={'content-type': 'text/html'},
        server="nginx",
        redirects=['http://example.com'],
        valid=True,
        error="",
    )
    expected_dict = {
        "url": "https://example.com",
        "status_code": 200,
        "headers": {'content-type': 'text/html'},
        "server": "nginx",
        "redirects": ['http://example.com'],
        "valid": True,
        "error": "",
    }
    assert result.to_dict() == expected_dict

def test_proberesult_to_dict_with_error() -> None:
    result = ProbeResult(
        url="https://bad.com",
        valid=False,
        error="timeout",
    )
    expected_dict = {
        "url": "https://bad.com",
        "status_code": 0,
        "headers": {},
        "server": "",
        "redirects": [],
        "valid": False,
        "error": "timeout",
    }
    assert result.to_dict() == expected_dict

def test_proberesult_default_values() -> None:
    result = ProbeResult(url="https://default.com")
    expected_dict = {
        "url": "https://default.com",
        "status_code": 0,
        "headers": {},
        "server": "",
        "redirects": [],
        "valid": False,
        "error": "",
    }
    assert result.to_dict() == expected_dict
