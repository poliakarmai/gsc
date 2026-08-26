# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for the SSRF address guard (ported from openworker web/guard.py)."""

import pytest

from gsc_core.gsc_ssrf_guard import check_url, guard_url, is_blocked


def test_blocks_loopback_literal():
    assert check_url("http://127.0.0.1/") is not None
    assert check_url("http://127.0.0.1:8080/x") is not None


def test_blocks_loopback_hostname():
    # localhost resolves to a loopback address; any blocked answer rejects.
    assert check_url("http://localhost/") is not None


def test_blocks_metadata_endpoint():
    assert check_url("http://169.254.169.254/latest/meta-data/") is not None


def test_blocks_private_ranges():
    assert check_url("http://10.0.0.1/") is not None
    assert check_url("http://192.168.1.1/") is not None
    assert check_url("http://172.16.0.1/") is not None


def test_blocks_cgnat_tailscale():
    assert check_url("http://100.64.0.1/") is not None


def test_blocks_non_http_scheme():
    assert check_url("file:///etc/passwd") is not None
    assert check_url("gopher://127.0.0.1/") is not None


def test_allows_public_literal_ip():
    # Public IPv4 (no DNS dependency in the test).
    assert check_url("https://93.184.216.34/") is None


def test_is_blocked():
    assert is_blocked("http://127.0.0.1/") is True
    assert is_blocked("https://93.184.216.34/") is False


def test_blocks_numeric_ip_forms():
    # inet_aton-style forms some URL parsers accept — must normalize to the v4 they carry.
    assert check_url("http://2130706433/") is not None  # decimal 127.0.0.1
    assert check_url("http://0x7f000001/") is not None  # hex 127.0.0.1


def test_guard_url_raises_on_blocked():
    with pytest.raises(PermissionError):
        guard_url("http://169.254.169.254/")
    guard_url("https://93.184.216.34/")  # no raise for public
