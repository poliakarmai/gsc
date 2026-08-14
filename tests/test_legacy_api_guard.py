# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""tests/test_legacy_api_guard.py — GSC-001: legacy API single-tenant/loopback guard.

The legacy `gsc_api` has one global key and no per-tenant isolation. It must
refuse to bind a non-loopback address unless the operator explicitly opts in.
"""
import os
import sys

# gsc_api refuses to import without a key unless dev mode is on.
os.environ.setdefault("GSC_DEV_MODE", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import gsc_api


def test_loopback_hosts_allowed():
    for host in ("127.0.0.1", "localhost", "::1"):
        gsc_api._enforce_loopback(host)  # must not raise


def test_non_loopback_refused():
    for host in ("0.0.0.0", "192.168.1.10", "example.com"):
        with pytest.raises(SystemExit):
            gsc_api._enforce_loopback(host)


def test_non_loopback_allowed_with_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("GSC_LEGACY_ALLOW_REMOTE", "1")
    gsc_api._enforce_loopback("0.0.0.0")  # must not raise


def test_opt_in_must_be_truthy(monkeypatch):
    monkeypatch.setenv("GSC_LEGACY_ALLOW_REMOTE", "0")
    with pytest.raises(SystemExit):
        gsc_api._enforce_loopback("0.0.0.0")
