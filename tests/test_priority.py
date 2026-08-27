# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for GSC priority scoring (real-exploitation prioritisation)."""

from gsc_core.gsc_priority import compute_priority, priority_rank


def test_kev_forces_critical_regardless_of_epss():
    p = compute_priority("HIGH", 0.05, is_kev=True)
    assert p["level"] == "critical"
    assert p["exploitation_probability"] == 1.0
    assert p["score"] == round(0.8 * 1.0, 3)


def test_critical_with_low_epss_no_signal_drops():
    # CRITICAL severity but nobody exploits it -> low priority.
    p = compute_priority("CRITICAL", 0.01)
    assert p["level"] == "low"
    assert p["score"] < 0.15


def test_exploit_raises_probability_floor():
    p = compute_priority("MEDIUM", 0.05, has_exploit=True)
    assert p["exploitation_probability"] == 0.9
    assert p["level"] == "high"  # 0.5 * 0.9 = 0.45


def test_exploit_and_high_epss_keeps_epss():
    # has_exploit floors at 0.9, but a higher epss is kept.
    p = compute_priority("MEDIUM", 0.95, has_exploit=True)
    assert p["exploitation_probability"] == 0.95


def test_kev_beats_exploit():
    p = compute_priority("LOW", 0.0, is_kev=True, has_exploit=True)
    assert p["exploitation_probability"] == 1.0
    # LOW (0.2) * 1.0 = 0.2 -> medium
    assert p["level"] == "medium"


def test_reachability_halves_dev_dependency():
    prod = compute_priority("HIGH", 0.8)
    dev = compute_priority("HIGH", 0.8, reachability=0.5)
    assert dev["score"] == round(prod["score"] * 0.5, 3)
    assert dev["level"] in ("high", "medium")


def test_severity_defaults_to_medium():
    p = compute_priority("", 0.9)
    assert p["signals"]["severity"] == "MEDIUM"
    assert p["score"] == round(0.5 * 0.9, 3)


def test_epss_clamped():
    assert compute_priority("HIGH", 1.5)["exploitation_probability"] == 1.0
    assert compute_priority("HIGH", -0.3)["exploitation_probability"] == 0.0


def test_priority_rank_orders_by_score():
    a = compute_priority("HIGH", 0.9, is_kev=True)
    b = compute_priority("LOW", 0.01)
    assert priority_rank(a) > priority_rank(b)


def test_score_bounds():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for epss in (0.0, 0.5, 1.0):
            p = compute_priority(sev, epss, is_kev=(epss == 1.0))
            assert 0.0 <= p["score"] <= 1.0


# ── integration: enrich_with_priority ───────────────────────────────────


def _kev_catalog_with(*cves):
    from gsc_core.gsc_kev import parse_kev_json
    vulns = [{"cveID": c, "knownRansomwareCampaignUse": "Known"} for c in cves]
    return parse_kev_json({"catalogVersion": "1", "vulnerabilities": vulns})


def _exploit_index_with(*cves):
    from gsc_core.gsc_exploitdb import parse_exploits_csv
    rows = ["id,file,description,date,author,type,platform,port"]
    for i, c in enumerate(cves):
        rows.append(
            f"{i},file{i}.txt,WordPress XSS ({c}),2024-01-01,author,webapps,linux,80"
        )
    return parse_exploits_csv("\n".join(rows))


def test_enrich_with_priority_kev_flag():
    from gsc_core.gsc_epss import enrich_with_priority
    findings = [{"rule_id": "GS030", "severity": "HIGH",
                 "metadata": {"epss": {"cve": "CVE-2021-44228", "score": 0.05},
                              "sca": {}}}]
    kev = _kev_catalog_with("CVE-2021-44228")
    out = enrich_with_priority(findings, kev_catalog=kev)
    assert out[0]["metadata"]["priority"]["signals"]["is_kev"] is True
    assert out[0]["metadata"]["exploit_signal"] == "known_exploited_kev"


def test_enrich_with_priority_exploit_flag():
    from gsc_core.gsc_epss import enrich_with_priority
    findings = [{"rule_id": "GS030", "severity": "MEDIUM",
                 "metadata": {"epss": {"cve": "CVE-2023-12345", "score": 0.1},
                              "sca": {}}}]
    idx = _exploit_index_with("CVE-2023-12345")
    out = enrich_with_priority(findings, exploit_index=idx)
    assert out[0]["metadata"]["priority"]["signals"]["has_exploit"] is True
    assert out[0]["metadata"]["exploit_signal"] == "public_exploit"


def test_enrich_with_priority_no_catalogs_epss_only():
    from gsc_core.gsc_epss import enrich_with_priority
    findings = [{"rule_id": "GS030", "severity": "HIGH",
                 "metadata": {"epss": {"cve": "CVE-2021-44228", "score": 0.05},
                              "sca": {}}}]
    out = enrich_with_priority(findings)
    sig = out[0]["metadata"]["priority"]["signals"]
    assert sig["is_kev"] is False
    assert sig["has_exploit"] is False
