"""tests/test_web3_sca.py — web3 SCA: manual CVE feed + solc known-bugs detection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_sca import (
    Package,
    _collect_solc_packages,
    parse_repo_manifests,
    query_osv,
    sca_findings,
)
from gsc_core import gsc_web3_feed as feed


# ── version parsing ─────────────────────────────────────────────────────────


def test_parse_version():
    assert feed.parse_version("0.8.13") == (0, 8, 13, 0)
    assert feed.parse_version("4.3.2") == (4, 3, 2, 0)
    assert feed.parse_version("v0.7.6") == (0, 7, 6, 0)
    assert feed.parse_version("0") == (0, 0, 0, 0)


def test_parse_version_semver_padding():
    # missing trailing components are zero per semver
    assert feed.parse_version("1.2") == feed.parse_version("1.2.0")
    assert feed.parse_version("1") == feed.parse_version("1.0.0")


def test_version_in_range_half_open():
    assert feed.version_in_range("0.7.6", "0.0.1", "0.8.0") is True
    assert feed.version_in_range("0.8.0", "0.0.1", "0.8.0") is False  # >= fixed
    assert feed.version_in_range("4.2.0", "4.1.0", "4.3.2") is True
    assert feed.version_in_range("4.3.2", "4.1.0", "4.3.2") is False  # fixed excluded


def test_version_in_range_semver_equality():
    # 1.2 == 1.2.0, so it must NOT be flagged vulnerable when fixed at 1.2.0
    assert feed.version_in_range("1.2", "0", "1.2.0") is False


# ── manual CVE feed ─────────────────────────────────────────────────────────


def test_openzeppelin_vulnerable_version():
    vulns = feed.manual_vulns("npm", "@openzeppelin/contracts", "4.2.0")
    ids = {v["id"] for v in vulns}
    assert "CVE-2021-41264" in ids  # UUPSUpgradeable CRITICAL
    assert "CVE-2022-35961" in ids  # ECDSA malleability HIGH
    assert "CVE-2021-39167" in ids  # TimelockController CRITICAL


def test_openzeppelin_safe_version():
    assert feed.manual_vulns("npm", "@openzeppelin/contracts", "4.9.0") == []
    assert feed.manual_vulns("npm", "@openzeppelin/contracts", "5.0.0") == []


def test_unknown_package_no_vulns():
    assert feed.manual_vulns("npm", "left-pad", "1.0.0") == []


def test_manual_vuln_osv_compatible():
    vulns = feed.manual_vulns("npm", "@openzeppelin/contracts", "4.2.0")
    v = vulns[0]
    # shape must flow through sca_findings unchanged
    assert v["id"] and v["database_specific"]["severity"] and v["affected"]


# ── solc known bugs ─────────────────────────────────────────────────────────


def test_solc_pre_080_unchecked_arithmetic():
    names = {v["id"] for v in feed.solc_vulns("0.7.6")}
    assert "SOLC-BUG-UncheckedArithmetic" in names


def test_solc_0813_inline_assembly():
    names = {v["id"] for v in feed.solc_vulns("0.8.13")}
    assert "SOLC-BUG-InlineAssemblyMemorySideEffects" in names
    assert "SOLC-BUG-UncheckedArithmetic" not in names


def test_solc_0820_clean():
    assert feed.solc_vulns("0.8.20") == []


# ── solc detection from manifests ───────────────────────────────────────────


def test_collect_solc_from_sources(tmp_path):
    (tmp_path / "Token.sol").write_text("pragma solidity ^0.7.0;\ncontract Token {}\n")
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc = "0.8.13"\n')
    pkgs = _collect_solc_packages(tmp_path)
    vers = {p.version for p in pkgs}
    assert "0.7.0" in vers
    assert "0.8.13" in vers
    assert all(p.ecosystem == "Solidity" and p.name == "solc" for p in pkgs)


def test_collect_solc_hardhat(tmp_path):
    (tmp_path / "hardhat.config.js").write_text(
        'module.exports = { solidity: { version: "0.8.13" } };\n'
    )
    pkgs = _collect_solc_packages(tmp_path)
    assert any(p.version == "0.8.13" for p in pkgs)


def test_collect_solc_truffle(tmp_path):
    (tmp_path / "truffle-config.js").write_text(
        'module.exports = { compilers: { solc: { version: "0.8.13" } } };\n'
    )
    pkgs = _collect_solc_packages(tmp_path)
    assert any(p.version == "0.8.13" for p in pkgs)


def test_parse_repo_manifests_includes_solc(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Vault.sol").write_text(
        "pragma solidity ^0.6.12;\ncontract Vault {}\n"
    )
    pkgs = parse_repo_manifests(tmp_path)
    solc = [p for p in pkgs if p.ecosystem == "Solidity"]
    assert any(p.version == "0.6.12" for p in solc)


# ── query_osv solc path (no network) ────────────────────────────────────────


def test_query_osv_solc_offline():
    pkgs = [Package(name="solc", version="0.7.6", ecosystem="Solidity",
                    manifest="Token.sol", line=1, raw="pragma solidity ^0.7.0;")]
    results = query_osv(pkgs)  # Solidity ecosystem never hits the network
    key = ("Solidity", "solc", "0.7.6")
    assert key in results
    assert any("UncheckedArithmetic" in v["id"] for v in results[key])


def test_sca_findings_solc():
    pkgs = [Package(name="solc", version="0.7.6", ecosystem="Solidity",
                    manifest="Token.sol", line=1, raw="pragma solidity ^0.7.0;")]
    results = query_osv(pkgs)
    findings = sca_findings(pkgs, results)
    assert findings
    assert findings[0]["title"].startswith("Vulnerable Solidity compiler 0.7.6")
    assert findings[0]["severity"] == "HIGH"


# ── manual feed dedup vs OSV ────────────────────────────────────────────────


def test_manual_feed_dedup_and_fallback(monkeypatch):
    import json
    import urllib.request

    import gsc_core.gsc_sca as sca

    class FakeResp:
        def __init__(self, data):
            self._d = data

        def read(self):
            return json.dumps(self._d).encode()

    def fake_urlopen(req, timeout=None):
        # OSV "up" but returns only ONE CVE — manual feed must fill the rest
        return FakeResp({"results": [{"vulns": [{
            "id": "CVE-2021-41264",
            "summary": "UUPSUpgradeable",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "@openzeppelin/contracts"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "4.1.0"},
                                                 {"fixed": "4.3.2"}]}]}],
        }]}]})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    pkgs = [Package(name="@openzeppelin/contracts", version="4.2.0",
                    ecosystem="npm", manifest="package.json", line=1,
                    raw="@openzeppelin/contracts@4.2.0")]
    results = query_osv(pkgs)
    ids = [v["id"] for v in results[("npm", "@openzeppelin/contracts", "4.2.0")]]

    assert ids.count("CVE-2021-41264") == 1          # no duplicate
    assert "CVE-2022-35961" in ids                   # manual feed filled the gap
    assert "CVE-2021-39167" in ids
