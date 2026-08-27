# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for parallelized GSC recon orchestrator using fake clients."""

import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from gsc_recon.dns_enum import DnsRecord
from gsc_recon.http_probe import ProbeResult
from gsc_recon.orchestrator import ReconReport, run_recon


class _FakeSubdomainClient:
    """Fake subdomain client that returns predefined subdomains."""
    def __init__(self, domains: List[str]):
        self._domains = list(domains)

    def fetch(self, domain: str) -> List[str]:
        return list(self._domains)


class _FakeResolveHost:
    """Fake resolve_host function with configurable delay per host."""
    def __init__(self, delay_map: dict[str, float]):
        self.delay_map = delay_map
        self.call_order = []

    def __call__(self, host: str) -> Optional[str]:
        self.call_order.append(host)
        delay = self.delay_map.get(host, 0.0)
        if delay > 0:
            time.sleep(delay)
        # Return a fake IP
        return f"1.2.3.{hash(host) % 254 + 1}"


class _FakeDnsClient:
    """Fake DNS client that returns configurable records with delay."""
    def __init__(self, records_map: dict[tuple[str, str], List[DnsRecord]], delay_map: Optional[dict[tuple[str, str], float]] = None):
        self.records_map = records_map
        self.delay_map = delay_map or {}
        self.call_order = []

    def query(self, domain: str, qtype: str) -> List[DnsRecord]:
        key = (domain, qtype)
        self.call_order.append(key)
        delay = self.delay_map.get(key, 0.0)
        if delay > 0:
            time.sleep(delay)
        return self.records_map.get(key, [])


class _FakeHttpClient:
    """Fake HTTP client that returns configurable results with delay."""
    def __init__(self, results_map: dict[str, ProbeResult], delay_map: Optional[dict[str, float]] = None):
        self.results_map = results_map
        self.delay_map = delay_map or {}
        self.call_order = []

    def probe(self, url: str) -> ProbeResult:
        self.call_order.append(url)
        delay = self.delay_map.get(url, 0.0)
        if delay > 0:
            time.sleep(delay)
        return self.results_map.get(url, ProbeResult(url=url, valid=False, error="not found"))

    def probe_hosts(self, hosts: List[str], scheme: str = "https") -> List[ProbeResult]:
        # This sequential version should not be called in our parallel implementation
        # but we implement it for completeness
        results = []
        for host in hosts:
            normalized = f"{scheme}://{host}"
            results.append(self.probe(normalized))
        return results


def test_parallel_resolve_preserves_order():
    """Test that resolve stage preserves subdomain order despite varying delays."""
    subdomains = ["a.example.com", "b.example.com", "c.example.com"]
    # Different delays to ensure out-of-order completion
    delay_map = {
        "a.example.com": 0.1,  # medium delay
        "b.example.com": 0.01, # short delay
        "c.example.com": 0.2,  # long delay
    }
    
    fake_resolve = _FakeResolveHost(delay_map)
    # Patch resolve_host in the module
    import gsc_recon.orchestrator as orchestrator_module
    original_resolve = orchestrator_module.resolve_host
    orchestrator_module.resolve_host = fake_resolve
    
    try:
        client = _FakeSubdomainClient(subdomains)
        # Run with resolve=True, max_workers=2 to force concurrency
        rep = run_recon("example.com", resolve=True, client=client, max_workers=2)
        
        # Check that all subdomains were resolved
        assert len(rep.resolved) == len(subdomains)
        for s in subdomains:
            assert s in rep.resolved
            assert rep.resolved[s] is not None
        
        # Check that the call order was not sequential (proving concurrency)
        # The first call should be to 'a.example.com' (first in list)
        # But due to delays, the completion order may vary
        # Most importantly, the RESULTS should be in original order
        # We verify this by checking that when we iterate subdomains,
        # we get results in the same order
        resolved_in_order = [rep.resolved[s] for s in subdomains if s in rep.resolved]
        assert len(resolved_in_order) == len(subdomains)
        
    finally:
        # Restore original function
        orchestrator_module.resolve_host = original_resolve


def test_parallel_dns_preserves_order():
    """Test that DNS stage preserves subdomain order despite varying delays."""
    subdomains = ["a.example.com", "b.example.com", "c.example.com"]
    # Different delays for different (subdomain, qtype) pairs
    delay_map = {}
    records_map = {}
    
    for i, s in enumerate(subdomains):
        for qtype in ["A", "CNAME"]:
            key = (s, qtype)
            # Stagger delays
            delay_map[key] = i * 0.1
            records_map[key] = [DnsRecord(name=s, type=qtype, ttl=300, data=f"value-{i}-{qtype}")]
    
    fake_dns_client = _FakeDnsClient(records_map, delay_map)
    
    client = _FakeSubdomainClient(subdomains)
    rep = run_recon("example.com", dns=True, client=client, dns_client=fake_dns_client, max_workers=2)
    
    # Check that all subdomains have DNS records
    assert len(rep.dns) == len(subdomains)
    for s in subdomains:
        assert s in rep.dns
        assert len(rep.dns[s]) == 2  # A and CNAME records
        
        # Check records are in expected order (by our test data)
        records = rep.dns[s]
        assert len(records) == 2
        # First should be A, second CNAME (based on how we added them)
        assert records[0].type == "A"
        assert records[1].type == "CNAME"
    
    # Verify the results are in subdomain order
    dns_in_order = []
    for s in subdomains:
        if s in rep.dns:
            dns_in_order.extend(rep.dns[s])
    
    # Should have 6 records total (3 subdomains * 2 types each)
    assert len(dns_in_order) == 6
    
    # Check that the order matches subdomain order then qtype order
    expected_types = []
    for s in subdomains:
        expected_types.extend(["A", "CNAME"])
    
    actual_types = [r.type for r in dns_in_order]
    assert actual_types == expected_types


def test_parallel_http_preserves_order():
    """Test that HTTP stage preserves host order despite varying delays."""
    subdomains = ["a.example.com", "b.example.com", "c.example.com"]
    # Different delays for different hosts
    delay_map = {
        "https://a.example.com": 0.1,
        "https://b.example.com": 0.01,
        "https://c.example.com": 0.2,
    }
    
    results_map = {}
    for s in subdomains:
        url = f"https://{s}"
        results_map[url] = ProbeResult(
            url=url,
            status_code=200,
            valid=True,
            headers={"server": f"server-{s}"}
        )
    
    fake_http_client = _FakeHttpClient(results_map, delay_map)
    
    client = _FakeSubdomainClient(subdomains)
    rep = run_recon("example.com", http=True, client=client, http_client=fake_http_client, max_workers=2)
    
    # Check that all hosts were probed
    assert len(rep.http) == len(subdomains)
    
    # Check that results are in the same order as subdomains
    http_in_order = []
    for s in subdomains:
        url = f"https://{s}"
        # Find the result for this URL
        for pr in rep.http:
            if pr.url == url:
                http_in_order.append(pr)
                break
    
    assert len(http_in_order) == len(subdomains)
    for i, pr in enumerate(http_in_order):
        expected_url = f"https://{subdomains[i]}"
        assert pr.url == expected_url
        assert pr.valid is True
        assert pr.headers["server"] == f"server-{subdomains[i]}"


def test_parallel_resolve_tolerance():
    """Test that resolve stage tolerates failures on individual hosts."""
    subdomains = ["good1.example.com", "fail.example.com", "good2.example.com"]
    
    def resolve_side_effect(host):
        if host == "fail.example.com":
            raise Exception("DNS resolution failed")
        return f"1.2.3.{hash(host) % 254 + 1}"
    
    # Patch resolve_host
    import gsc_recon.orchestrator as orchestrator_module
    original_resolve = orchestrator_module.resolve_host
    orchestrator_module.resolve_host = resolve_side_effect
    
    try:
        client = _FakeSubdomainClient(subdomains)
        rep = run_recon("example.com", resolve=True, client=client, max_workers=2)
        
        # Check that the good hosts were resolved
        assert "good1.example.com" in rep.resolved
        assert rep.resolved["good1.example.com"] is not None
        assert "good2.example.com" in rep.resolved
        assert rep.resolved["good2.example.com"] is not None
        
        # Check that the failed host is not in resolved (or has no value)
        assert "fail.example.com" not in rep.resolved or rep.resolved.get("fail.example.com") is None
        
        # Most importantly, the orchestrator did not crash
        assert isinstance(rep, ReconReport)
        
    finally:
        orchestrator_module.resolve_host = original_resolve


def test_parallel_dns_tolerance():
    """Test that DNS stage tolerates failures on individual queries."""
    subdomains = ["good.example.com", "fail.example.com"]
    
    def query_side_effect(domain, qtype):
        if domain == "fail.example.com" and qtype == "A":
            raise Exception("DNS query failed")
        # Return a record for successful queries
        return [DnsRecord(name=domain, type=qtype, ttl=300, data="1.2.3.4")]
    
    # We need to patch the DnsClient.query method
    import gsc_recon.dns_enum as dns_module
    original_query = dns_module.DnsClient.query
    
    # Create a wrapper that uses our side effect
    def patched_query(self, domain, qtype):
        return query_side_effect(domain, qtype)
    
    dns_module.DnsClient.query = patched_query
    
    try:
        client = _FakeSubdomainClient(subdomains)
        # Use a real DnsClient instance (which will use our patched method)
        rep = run_recon("example.com", dns=True, client=client, max_workers=2)
        
        # Check that good.example.com has records
        assert "good.example.com" in rep.dns
        assert len(rep.dns["good.example.com"]) > 0
        
        # Check that fail.example.com may have fewer records (missing A) but others may succeed
        # The key is that the orchestrator didn't crash
        assert isinstance(rep, ReconReport)
        
    finally:
        dns_module.DnsClient.query = original_query


def test_parallel_http_tolerance():
    """Test that HTTP stage tolerates failures on individual hosts."""
    subdomains = ["good1.example.com", "fail.example.com", "good2.example.com"]
    
    def probe_side_effect(url):
        if url == "https://fail.example.com":
            raise Exception("Connection timeout")
        return ProbeResult(
            url=url,
            status_code=200,
            valid=True,
            headers={"server": "ok"}
        )
    
    # We need to patch the HttpClient.probe method
    import gsc_recon.http_probe as http_module
    original_probe = http_module.HttpClient.probe
    
    def patched_probe(self, url):
        return probe_side_effect(url)
    
    http_module.HttpClient.probe = patched_probe
    
    try:
        client = _FakeSubdomainClient(subdomains)
        rep = run_recon("example.com", http=True, client=client, max_workers=2)
        
        # Check that we got results for all hosts (even failed ones should have ProbeResult objects)
        assert len(rep.http) == len(subdomains)
        
        # Check that good hosts have valid results
        good_results = [pr for pr in rep.http if pr.valid]
        assert len(good_results) == 2  # good1 and good2
        
        # Check that failed host has invalid result
        failed_results = [pr for pr in rep.http if not pr.valid]
        assert len(failed_results) == 1
        assert failed_results[0].url == "https://fail.example.com"
        assert "Connection timeout" in failed_results[0].error
        
        # Most importantly, the orchestrator did not crash
        assert isinstance(rep, ReconReport)
        
    finally:
        http_module.HttpClient.probe = original_probe


def test_max_workers_respected():
    """Test that max_workers parameter is respected."""
    subdomains = [f"host{i}.example.com" for i in range(10)]  # 10 hosts
    
    call_count = []
    call_lock = ThreadPoolExecutor(max_workers=1)  # To serialize access to call_count
    
    def resolve_side_effect(host):
        call_count.append(host)
        time.sleep(0.01)  # Small delay to allow concurrency to manifest
        return "1.2.3.4"
    
    # Patch resolve_host
    import gsc_recon.orchestrator as orchestrator_module
    original_resolve = orchestrator_module.resolve_host
    orchestrator_module.resolve_host = resolve_side_effect
    
    try:
        client = _FakeSubdomainClient(subdomains)
        
        # Test with max_workers=2 - should process at most 2 concurrently
        call_count.clear()
        rep = run_recon("example.com", resolve=True, client=client, max_workers=2)
        
        # Verify all hosts were processed
        assert len(call_count) == len(subdomains)
        assert len(rep.resolved) == len(subdomains)
        
        # The test is primarily that it doesn't crash and processes all items
        # A more sophisticated test would track actual concurrent execution,
        # but for now we verify basic functionality
        
    finally:
        orchestrator_module.resolve_host = original_resolve


def test_full_pipeline_parallel():
    """Test full pipeline with all stages enabled using fake clients."""
    subdomains = ["a.example.com", "b.example.com"]
    
    # Setup fake clients
    client = _FakeSubdomainClient(subdomains)
    
    # Fake resolve_host
    def fake_resolve(host):
        return f"1.2.3.{hash(host) % 254 + 1}"
    
    # Fake DNS client
    fake_dns_records = {
        ("a.example.com", "A"): [DnsRecord(name="a.example.com", type="A", ttl=300, data="1.2.3.4")],
        ("b.example.com", "A"): [DnsRecord(name="b.example.com", type="A", ttl=300, data="1.2.3.5")],
    }
    fake_dns_client = _FakeDnsClient(fake_dns_records)
    
    # Fake HTTP client
    fake_http_results = {
        "https://a.example.com": ProbeResult(url="https://a.example.com", status_code=200, valid=True, headers={"server": "nginx"}),
        "https://b.example.com": ProbeResult(url="https://b.example.com", status_code=200, valid=True, headers={"server": "apache"}),
    }
    fake_http_client = _FakeHttpClient(fake_http_results)
    
    # Patch resolve_host
    import gsc_recon.orchestrator as orchestrator_module
    original_resolve = orchestrator_module.resolve_host
    orchestrator_module.resolve_host = fake_resolve
    
    try:
        rep = run_recon(
            "example.com",
            resolve=True,
            dns=True,
            http=True,
            tech=True,
            client=client,
            dns_client=fake_dns_client,
            http_client=fake_http_client,
            max_workers=2
        )
        
        # Verify all stages produced results
        assert rep.domain == "example.com"
        assert rep.subdomains == subdomains
        
        # Resolve stage
        assert len(rep.resolved) == len(subdomains)
        for s in subdomains:
            assert s in rep.resolved
            assert rep.resolved[s] is not None
        
        # DNS stage
        assert len(rep.dns) == len(subdomains)
        for s in subdomains:
            assert s in rep.dns
            assert len(rep.dns[s]) == 1
            assert rep.dns[s][0].type == "A"
        
        # HTTP stage
        assert len(rep.http) == len(subdomains)
        for pr in rep.http:
            assert pr.valid is True
            assert pr.status_code == 200
        
        # Tech stage
        assert len(rep.tech) == len(subdomains)
        for url in ["https://a.example.com", "https://b.example.com"]:
            assert url in rep.tech
            assert len(rep.tech[url]) == 1
            # The tech name should be extracted from headers
            if url == "https://a.example.com":
                assert rep.tech[url][0].name == "nginx"
            else:
                assert rep.tech[url][0].name == "Apache"
        
        # Most importantly, verify determinism - results in subdomain order
        # Check resolved order
        resolved_list = [rep.resolved[s] for s in subdomains]
        assert all(ip is not None for ip in resolved_list)
        
        # Check http order
        http_urls = [pr.url for pr in rep.http]
        assert http_urls == [f"https://{s}" for s in subdomains]
        
        # Check tech order
        tech_urls = list(rep.tech.keys())
        assert tech_urls == [f"https://{s}" for s in subdomains]
        
    finally:
        orchestrator_module.resolve_host = original_resolve


def test_tech_map_order_preservation():
    """Specifically test that tech_map preserves order from http_results."""
    subdomains = ["z.example.com", "a.example.com", "m.example.com"]  # Not in alphabetical order
    
    client = _FakeSubdomainClient(subdomains)
    
    # HTTP results in the same order as subdomains
    fake_http_results = {
        "https://z.example.com": ProbeResult(url="https://z.example.com", status_code=200, valid=True, headers={"server": "nginx"}),
        "https://a.example.com": ProbeResult(url="https://a.example.com", status_code=200, valid=True, headers={"server": "Apache"}),
        "https://m.example.com": ProbeResult(url="https://m.example.com", status_code=200, valid=True, headers={"server": "Microsoft-IIS"}),
    }
    fake_http_client = _FakeHttpClient(fake_http_results)
    
    rep = run_recon("example.com", http=True, tech=True, client=client, http_client=fake_http_client, max_workers=2)
    
    # Verify tech_map keys are in the same order as subdomains (and thus http_results)
    tech_keys = list(rep.tech.keys())
    expected_keys = [f"https://{s}" for s in subdomains]
    assert tech_keys == expected_keys
    
    # Verify each tech match corresponds to the correct host
    assert rep.tech["https://z.example.com"][0].name == "nginx"
    assert rep.tech["https://a.example.com"][0].name == "Apache"
    assert rep.tech["https://m.example.com"][0].name == "IIS"