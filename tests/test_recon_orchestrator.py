# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the GSC recon orchestrator (no network — injected clients)."""

from gsc_recon.dns_enum import DnsRecord
from gsc_recon.http_probe import ProbeResult
from gsc_recon.orchestrator import ReconReport, run_recon


class _FakeClient:
    def __init__(self, domains):
        self._domains = list(domains)

    def fetch(self, domain):
        return list(self._domains)


class _FakeDnsClient:
    def query(self, domain, qtype):
        if qtype == "A":
            return [DnsRecord(name=domain, type="A", ttl=300, data="1.2.3.4")]
        return []


class _FakeHttpClient:
    def __init__(self, results):
        self._results = list(results)

    def probe_hosts(self, hosts, scheme="https"):
        return list(self._results)


def test_run_recon_returns_report():
    client = _FakeClient(["a.example.com", "b.example.com"])
    rep = run_recon("example.com", client=client)
    assert rep.domain == "example.com"
    assert rep.subdomains == ["a.example.com", "b.example.com"]
    assert rep.resolved == {}
    assert rep.dns == {}
    assert rep.http == []
    assert rep.tech == {}


def test_run_recon_resolve_true_populates_resolved():
    client = _FakeClient(["localhost"])
    rep = run_recon("example.com", resolve=True, client=client)
    assert "localhost" in rep.resolved
    assert rep.resolved["localhost"] is not None


def test_run_recon_live_filters_non_resolving():
    client = _FakeClient(["localhost", "nonexistent.invalid"])
    rep = run_recon("example.com", live=True, client=client)
    assert "localhost" in rep.subdomains
    assert "nonexistent.invalid" not in rep.subdomains


def test_run_recon_dns_stage():
    sub = _FakeClient(["a.example.com"])
    dns = _FakeDnsClient()
    rep = run_recon("example.com", dns=True, client=sub, dns_client=dns)
    assert "a.example.com" in rep.dns
    assert rep.dns["a.example.com"][0].data == "1.2.3.4"


def test_run_recon_http_stage():
    sub = _FakeClient(["a.example.com"])
    pr = ProbeResult(url="https://a.example.com", status_code=200, valid=True,
                     headers={"server": "nginx"})
    http = _FakeHttpClient([pr])
    rep = run_recon("example.com", http=True, client=sub, http_client=http)
    assert len(rep.http) == 1
    assert rep.http[0].valid is True


def test_run_recon_tech_stage():
    sub = _FakeClient(["a.example.com"])
    pr = ProbeResult(url="https://a.example.com", status_code=200, valid=True,
                     headers={"server": "nginx"})
    http = _FakeHttpClient([pr])
    rep = run_recon("example.com", http=True, tech=True, client=sub, http_client=http)
    assert "https://a.example.com" in rep.tech
    names = [m.name for m in rep.tech["https://a.example.com"]]
    assert "nginx" in names


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
    assert d["dns"] == {}
    assert d["http"] == []
    assert d["tech"] == {}
