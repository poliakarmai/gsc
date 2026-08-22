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
