"""GSC Dependency Proof-of-Fix tests (Фаза 10.1 / VeriPatch)."""
import gsc_verify_fix as V


def _pkg(name, version):
    from gsc_sca import Package
    return Package(name=name, version=version, ecosystem="PyPI",
                   manifest="requirements.txt", line=1, raw=f"{name}=={version}")


def test_verify_dependency_fix_fixed(monkeypatch, tmp_path):
    import gsc_sca
    monkeypatch.setattr(gsc_sca, "parse_repo_manifests",
                        lambda root: [_pkg("requests", "2.32.0")])
    monkeypatch.setattr(gsc_sca, "query_osv", lambda pkgs, db=None: {})
    monkeypatch.setattr(V, "run_tests", lambda repo: (V.StageOutcome.PASSED, "ok"))

    rep = V.verify_dependency_fix("requests", str(tmp_path))
    assert rep.result == V.VerifyResult.PASSED
    assert rep.ready_for_pr is True
    assert rep.evidence == "sca"


def test_verify_dependency_fix_still_vulnerable(monkeypatch, tmp_path):
    import gsc_sca
    monkeypatch.setattr(gsc_sca, "parse_repo_manifests",
                        lambda root: [_pkg("requests", "2.26.0")])
    monkeypatch.setattr(gsc_sca, "query_osv", lambda pkgs, db=None: {
        ("PyPI", "requests", "2.26.0"): [{"id": "CVE-2023-32681"}],
    })

    rep = V.verify_dependency_fix("requests", str(tmp_path))
    assert rep.result == V.VerifyResult.FAILED_RESOLVE
    assert "still has 1 known vuln" in rep.error_message


def test_verify_dependency_fix_missing_package(monkeypatch, tmp_path):
    import gsc_sca
    monkeypatch.setattr(gsc_sca, "parse_repo_manifests",
                        lambda root: [_pkg("requests", "2.32.0")])

    rep = V.verify_dependency_fix("django", str(tmp_path))
    assert rep.result == V.VerifyResult.ERROR
    assert "not found" in rep.error_message
