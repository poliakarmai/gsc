#!/usr/bin/env python3
"""tests/test_spdx.py — SPDX 2.3 + signing tests (+7)."""
import sys, os, re
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_spdx import (generate_spdx, cdx_to_spdx, _spdx_id, _dl,
                       canonical_json, sign_sbom, verify_sbom)

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    from gsc_sca import Package
    pkgs = [Package("requests","2.25.0","PyPI","r.txt",1,"requests==2.25.0")]
    spdx = generate_spdx(pkgs)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert len(spdx["packages"]) == 1
    assert len(spdx["relationships"]) == 1
    assert spdx["relationships"][0]["relationshipType"] == "DESCRIBES"
run_case('SPDX generation basic', t1)

def t2():
    sid = _spdx_id("@babel/core-7.0.0")
    assert sid.startswith("SPDXRef-Package-")
    assert re.match(r"^SPDXRef-Package-[a-zA-Z0-9.\-]+$", sid)
run_case('SPDX ID sanitization', t2)

def t3():
    assert _dl("PyPI","requests") == "https://pypi.org/project/requests"
    assert _dl("npm","lodash") == "https://www.npmjs.com/package/lodash"
    assert _dl("Unknown","x") == "NOASSERTION"
run_case('download location by ecosystem', t3)

def t4():
    cdx = {"components":[{"type":"library","name":"requests","version":"2.25.0",
            "purl":"pkg:pypi/requests@2.25.0"}],"metadata":{"tools":[{"name":"gsc-sbom"}]}}
    spdx = cdx_to_spdx(cdx)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 1
    assert spdx["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.25.0"
run_case('CDX to SPDX conversion', t4)

def t5():
    assert canonical_json({"b":2,"a":1}) == canonical_json({"a":1,"b":2})
run_case('canonical JSON stable', t5)

def t6():
    from gsc_sca import Package
    pkgs = [Package("flask","2.0.0","PyPI","r.txt",1,"flask==2.0.0")]
    sbom = generate_spdx(pkgs)
    key = b"test-key"
    sig = sign_sbom(sbom, key)
    assert verify_sbom(sbom, sig, key) is True
run_case('sign/verify roundtrip', t6)

def t7():
    from gsc_sca import Package
    pkgs = [Package("flask","2.0.0","PyPI","r.txt",1,"flask==2.0.0")]
    sbom = generate_spdx(pkgs)
    key = b"test-key"
    sig = sign_sbom(sbom, key)
    sbom["packages"][0]["name"] = "tampered"
    assert verify_sbom(sbom, sig, key) is False
run_case('tamper detection', t7)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
