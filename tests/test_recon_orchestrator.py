# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GSC recon orchestrator (no network — injected client)."""

from gsc_recon.orchestrator import ReconReport, run_recon


class _FakeClient:
    def __init__(self, domains):
        self._domains = list(domains)

    def fetch(self, domain):
        return list(self._domains)


def test_run_recon_returns_report():
    client = _FakeClient(["a.example.com", "b.example.com"])
    rep = run_recon("example.com", client=client)
    assert rep.domain == "example.com"
    assert rep.subdomains == ["a.example.com", "b.example.com"]
    assert rep.resolved == {}


def test_run_recon_resolve_true_populates_resolved():
    client = _FakeClient(["localhost"])
    rep = run_recon("example.com", resolve=True, client=client)
    assert "localhost" in rep.resolved
    assert rep.resolved["localhost"] is not None


def test_run_recon_empty_client():
    client = _FakeClient([])
    rep = run_recon("example.com", client=client)
    assert rep.subdomains == []
    assert rep.resolved == {}


def test_report_to_dict_shape():
    rep = ReconReport(domain="example.com", subdomains=["a.example.com"],
                      resolved={"a.example.com": "1.2.3.4"})
    d = rep.to_dict()
    assert d["domain"] == "example.com"
    assert d["subdomains"] == ["a.example.com"]
    assert d["resolved"] == {"a.example.com": "1.2.3.4"}


def test_run_recon_live_filters_non_resolving():
    client = _FakeClient(["localhost", "nonexistent.invalid"])
    rep = run_recon("example.com", live=True, client=client)
    assert "localhost" in rep.subdomains
    assert "nonexistent.invalid" not in rep.subdomains
