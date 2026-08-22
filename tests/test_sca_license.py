"""GSC SCA License Compliance tests."""
import gsc_core.gsc_sca_license as L
from gsc_core.gsc_sca import Package


def test_classify_permissive():
    assert L.classify("MIT") == "permissive"
    assert L.classify("Apache-2.0") == "permissive"
    assert L.classify("BSD") == "permissive"


def test_classify_copyleft():
    assert L.classify("GPL-3.0") == "copyleft"
    assert L.classify("AGPL-3.0") == "copyleft"
    # worst-case across an SPDX expression
    assert L.classify("GPL-3.0 OR MIT") == "copyleft"
    assert L.classify("MIT AND GPL-3.0") == "copyleft"


def test_classify_weak_copyleft():
    assert L.classify("LGPL-2.1") == "weak-copyleft"
    assert L.classify("MPL-2.0") == "weak-copyleft"


def test_classify_proprietary_and_unknown():
    assert L.classify("Proprietary") == "proprietary"
    assert L.classify("") == "unknown"
    assert L.classify("SomeWeirdLicense-v99") == "unknown"


def test_normalize():
    assert L.normalize_license("MIT") == "MIT"
    assert L.normalize_license("Apache License 2.0") == "Apache-2.0"
    assert L.normalize_license("License :: OSI Approved :: Apache Software License") == "Apache-2.0"
    assert L.normalize_license("") == ""


def test_scan_licenses_all_permissive(monkeypatch):
    monkeypatch.setattr(L, "_lookup", lambda p: {
        "requests": "Apache-2.0", "django": "BSD-3-Clause", "pillow": "MIT",
    }.get(p.name))
    pkgs = [
        Package("requests", "2.31.0", "PyPI", "requirements.txt", 1, "requests==2.31.0"),
        Package("django", "5.0", "PyPI", "requirements.txt", 2, "django==5.0"),
        Package("pillow", "10.0", "PyPI", "requirements.txt", 3, "pillow==10.0"),
    ]
    assert L.scan_licenses(None, pkgs) == []


def test_scan_licenses_copyleft_flagged(monkeypatch):
    monkeypatch.setattr(L, "_lookup", lambda p: "GPL-3.0")
    pkgs = [Package("gplpkg", "1.0", "PyPI", "requirements.txt", 1, "gplpkg==1.0")]
    findings = L.scan_licenses(None, pkgs)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "GS030-LIC-copyleft"
    assert findings[0]["severity"] == "HIGH"


def test_policy_gate():
    copyleft = [{"severity": "HIGH", "metadata": {"sca": {"license_category": "copyleft", "package": "x"}}}]
    pol = L.evaluate_policy(copyleft)
    assert pol["allowed"] is False
    assert len(pol["blocked"]) == 1
    assert L.evaluate_policy([])["allowed"] is True


def test_build_license_map(monkeypatch):
    monkeypatch.setattr(L, "_lookup", lambda p: {
        "requests": "Apache-2.0", "django": "BSD-3-Clause", "nolic": None,
    }.get(p.name))
    pkgs = [
        Package("requests", "2.0", "PyPI", "r.txt", 1, "requests==2.0"),
        Package("django", "5.0", "PyPI", "r.txt", 2, "django==5.0"),
        Package("nolic", "1.0", "PyPI", "r.txt", 3, "nolic==1.0"),
    ]
    m = L.build_license_map(pkgs)
    assert m["PyPI:requests"] == "Apache-2.0"
    assert m["PyPI:django"] == "BSD-3-Clause"
    assert "PyPI:nolic" not in m


def test_sbom_spdx_license_enrichment(monkeypatch):
    from gsc_cli.gsc_sbom import generate_sbom
    from gsc_cli.gsc_spdx import generate_spdx
    monkeypatch.setattr(L, "_lookup", lambda p: "MIT")
    pkgs = [Package("mitpkg", "1.0", "PyPI", "r.txt", 1, "mitpkg==1.0")]
    lic_map = L.build_license_map(pkgs)

    sbom = generate_sbom(pkgs, licenses=lic_map)
    assert sbom["components"][0]["licenses"][0]["license"]["id"] == "MIT"

    spdx = generate_spdx(pkgs, licenses=lic_map)
    assert spdx["packages"][0]["licenseConcluded"] == "MIT"
    assert spdx["packages"][0]["licenseDeclared"] == "MIT"
