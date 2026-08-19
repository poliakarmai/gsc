#!/usr/bin/env python3
"""tests/test_sca.py — SCA parser + severity + bump tests (+7)."""
import sys, os, json, tempfile
from pathlib import Path
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_sca import (extract_version, parse_requirements, parse_go_mod,
                     parse_package_json, _cvss_to_severity, _normalize_severity,
                     extract_fixed_version, generate_sca_fix, parse_repo_manifests)

passed = 0
failed = 0

def run_case(name, fn):
    global passed, failed
    try:
        fn()
        print(f'  ✅ {name}')
        passed += 1
    except Exception as e:
        print(f'  ❌ {name}: {e}')
        failed += 1


def t1():
    assert extract_version("==2.25.0") == "2.25.0"
    assert extract_version(">=1.0,<2.0") == "1.0"
    assert extract_version("^4.17.1") == "4.17.1"
    assert extract_version("~=1.4") == "1.4"
    assert extract_version("!=1.5") is None
    assert extract_version("*") is None
    assert extract_version("") is None
run_case('extract_version', t1)


def t2():
    content = ("requests==2.19.0\n"
               "flask>=1.0  # web\n"
               "-r prod.txt\n"
               "# comment\n"
               "django[argon2]==2.2\n")
    pkgs = parse_requirements("requirements.txt", content)
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "flask" in names
    assert "django" in names
    assert "prod.txt" not in names
    django = next(p for p in pkgs if p.name == "django")
    assert django.version == "2.2"
run_case('parse_requirements', t2)


def t3():
    content = ("module example.com/x\n"
               "require (\n"
               "\tgithub.com/gin-gonic/gin v1.7.0\n"
               ")\n")
    pkgs = parse_go_mod("go.mod", content)
    assert pkgs[0].version == "1.7.0"
    assert pkgs[0].ecosystem == "Go"
run_case('parse_go_mod strips v', t3)


def t4():
    content = json.dumps({"dependencies": {"lodash": "4.17.15"},
                          "devDependencies": {"jest": "^27.0.0"}})
    pkgs = parse_package_json("package.json", content)
    nv = {p.name: p.version for p in pkgs}
    assert nv["lodash"] == "4.17.15"
    assert nv["jest"] == "27.0.0"
run_case('parse_package_json', t4)


def t5():
    assert _cvss_to_severity(9.8) == "CRITICAL"
    assert _cvss_to_severity(7.5) == "HIGH"
    assert _cvss_to_severity(5.0) == "MEDIUM"
    assert _cvss_to_severity(2.0) == "LOW"
    assert _normalize_severity("MODERATE") == "MEDIUM"
run_case('severity mapping', t5)


def t6():
    vuln = {"affected": [{"package": {"name": "requests"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "2.20.0"}]}]}]}
    assert extract_fixed_version(vuln, "requests") == "2.20.0"
    assert extract_fixed_version(vuln, "flask") is None
run_case('extract_fixed_version', t6)


def t7():
    finding = {"metadata": {"sca": {"package": "requests",
                                    "current_version": "2.19.0",
                                    "fixed_version": "2.20.0"}}}
    manifest = "flask==1.0\nrequests==2.19.0\n"
    fix = generate_sca_fix(finding, manifest)
    assert fix is not None
    assert "requests==2.20.0" in fix["patched"]
    assert "requests==2.19.0" not in fix["patched"]
    assert "flask==1.0" in fix["patched"]
run_case('sca bump fix', t7)


def t8():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "requirements.txt").write_text("requests==2.33.0\n")
        # fixture dirs MUST be skipped (benchmark/calibration/build)
        for rel, content in [
            ("calibration/repos/sca-vuln-demo", "requests==2.19.0\n"),
            ("benchmark/real_world/piccolo-api", "Jinja2>=2.11.0\n"),
            ("build/lib", "flask==1.0\n"),
        ]:
            d = root / rel
            d.mkdir(parents=True, exist_ok=True)
            (d / "requirements.txt").write_text(content)
        pkgs = parse_repo_manifests(root)
        names = {p.name for p in pkgs}
        assert names == {"requests"}, f"expected only requests, got {names}"
        assert all(p.version == "2.33.0" for p in pkgs)
run_case('parse_repo_manifests skips fixtures', t8)


print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
