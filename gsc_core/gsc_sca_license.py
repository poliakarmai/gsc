#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""GSC SCA License Compliance (v1.0).

Detects dependency licenses from manifests and classifies them for
commercial-safety: permissive vs weak-copyleft vs copyleft vs proprietary.

Reuses ``parse_repo_manifests`` from gsc_sca (requirements.txt / package.json /
go.mod). License lookup via PyPI JSON API / npm registry (no API key, no LLM);
falls back to an offline SPDX normalizer when a package is not reachable.

CLI: ``gsc sca-license --repo ./project``
"""

from __future__ import annotations

import json
import re
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional

from .gsc_sca import parse_repo_manifests, Package

HTTP_TIMEOUT = 5

# ── SPDX classification ────────────────────────────────────────────

_PERMISSIVE = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause",
    "ISC", "0BSD", "Unlicense", "Zlib", "Python-2.0", "WTFPL", "CC0-1.0",
    "BSL-1.0", "PostgreSQL", "MIT-0",
}

_WEAK_COPYLEFT = {
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL-2.0-only", "LGPL-2.1-only",
    "LGPL-3.0-only", "MPL-1.0", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1", "CPL-1.0",
}

_STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-3.0", "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later",
    "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "OSL-3.0", "CPAL-1.0",
}

_PROPRIETARY = {"Proprietary", "Commercial", "UNLICENSED", "All-Rights-Reserved"}

# SPDX-expression prefix → category (handles "MIT AND GPL-3.0", "GPL-3.0 OR MIT")
_CATEGORY_PRIORITY = ["copyleft", "weak-copyleft", "proprietary", "permissive"]


def _classify_single(spdx: str) -> str:
    s = spdx.strip()
    if s in _STRONG_COPYLEFT or s.startswith("AGPL") or s.startswith("GPL") or s.startswith("SSPL"):
        return "copyleft"
    if s in _WEAK_COPYLEFT or s.startswith("LGPL") or s.startswith("MPL") or s.startswith("EPL"):
        return "weak-copyleft"
    if s in _PROPRIETARY or s.lower() in ("proprietary", "commercial", "unlicensed"):
        return "proprietary"
    if s in _PERMISSIVE:
        return "permissive"
    return "unknown"


def classify(license_str: Optional[str]) -> str:
    """Classify a license string (may be an SPDX expression) → worst category.

    Returns one of: copyleft | weak-copyleft | proprietary | permissive | unknown.
    """
    if not license_str:
        return "unknown"
    raw = license_str.strip()
    cats = set()
    for part in re.split(r"\s+(?:AND|OR|WITH)\s+", raw):
        spdx = normalize_license(part)
        if spdx:
            cats.add(_classify_single(spdx))
    if not cats:
        return "unknown"
    for prio in _CATEGORY_PRIORITY:
        if prio in cats:
            return prio
    return "permissive"


# ── License string → SPDX normalization ────────────────────────────

_LICENSE_ALIASES = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "isc": "ISC",
    "gpl-3.0": "GPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "gplv3": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "agpl-3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "lgpl-3.0": "LGPL-3.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "epl-2.0": "EPL-2.0",
    "eclipse public license": "EPL-2.0",
    "python-2.0": "Python-2.0",
    "psf": "Python-2.0",
    "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "zlib": "Zlib",
    "wtfpl": "WTFPL",
    "proprietary": "Proprietary",
    "commercial": "Commercial",
    "unlicensed": "UNLICENSED",
}


def normalize_license(license_str: str) -> str:
    """Map a raw license string (PyPI/npm) to an SPDX id, or '' if unknown."""
    raw = (license_str or "").strip()
    if not raw:
        return ""
    # already an SPDX id
    if raw in _STRONG_COPYLEFT or raw in _WEAK_COPYLEFT or raw in _PERMISSIVE or raw in _PROPRIETARY:
        return raw
    # PyPI classifier "License :: OSI Approved :: Apache Software License"
    m = re.search(r"License\s*::\s*OSI Approved\s*::\s*(.+)", raw, re.IGNORECASE)
    if m:
        raw = m.group(1).strip()
    key = raw.lower().strip()
    return _LICENSE_ALIASES.get(key, "")


# ── License lookup (PyPI / npm) ────────────────────────────────────

_LICENSE_CACHE: Dict[str, Optional[str]] = {}


def _http_get_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "gsc-sca-license/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None


def lookup_pypi_license(name: str) -> Optional[str]:
    key = f"pypi:{name}"
    if key in _LICENSE_CACHE:
        return _LICENSE_CACHE[key]
    data = _http_get_json(f"https://pypi.org/pypi/{name}/json")
    lic = None
    if data:
        info = data.get("info", {})
        lic = info.get("license") or ""
        if not lic:
            for c in info.get("classifiers", []) or []:
                if c.startswith("License :: OSI Approved ::") or c.startswith("License ::"):
                    lic = c
                    break
    _LICENSE_CACHE[key] = lic
    return lic


def lookup_npm_license(name: str) -> Optional[str]:
    key = f"npm:{name}"
    if key in _LICENSE_CACHE:
        return _LICENSE_CACHE[key]
    data = _http_get_json(f"https://registry.npmjs.org/{name}")
    lic = None
    if data:
        raw = data.get("license")
        if isinstance(raw, str):
            lic = raw
        elif isinstance(raw, dict):
            lic = raw.get("type", "")
    _LICENSE_CACHE[key] = lic
    return lic


def _lookup(pkg: Package) -> Optional[str]:
    if pkg.ecosystem == "PyPI":
        return lookup_pypi_license(pkg.name)
    if pkg.ecosystem == "npm":
        return lookup_npm_license(pkg.name)
    # Go: go.mod does not carry licenses — leave to manual review
    return None


def build_license_map(packages: List[Package]) -> Dict[str, str]:
    """Return {"ecosystem:name": spdx_id} for packages with a known license.

    Used by SBOM/SPDX generators to enrich components with ``licenseConcluded`` /
    ``licenses`` fields.
    """
    result: Dict[str, str] = {}
    for pkg in packages:
        key = f"{pkg.ecosystem}:{pkg.name.lower()}"
        if key in result:
            continue
        spdx = normalize_license(_lookup(pkg) or "")
        if spdx:
            result[key] = spdx
    return result


# ── Findings ───────────────────────────────────────────────────────

_SEVERITY = {
    "copyleft": "HIGH",
    "proprietary": "HIGH",
    "weak-copyleft": "MEDIUM",
    "unknown": "LOW",
    "permissive": None,  # not reported
}


def _finding(pkg: Package, license_str: Optional[str], category: str, severity: str) -> dict:
    key = hashlib.sha256(f"GS030-license{pkg.ecosystem}{pkg.name}{license_str}".encode()).hexdigest()[:12]
    return {
        "finding_key": key,
        "rule_id": f"GS030-LIC-{category}",
        "title": f"Dependency {pkg.name}@{pkg.version or '?'} has {category} license: {license_str or 'unknown'}",
        "severity": severity,
        "category": severity,
        "confidence": 0.90,
        "file_path": pkg.manifest,
        "line_number": pkg.line,
        "detail": f"{pkg.name} ({pkg.ecosystem}) — {license_str or 'license unknown'}; {category}",
        "metadata": {
            "detector": "GS030-license",
            "sca": {"package": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem,
                    "license": license_str, "license_category": category},
        },
    }


def scan_licenses(root, packages: Optional[List[Package]] = None) -> List[dict]:
    """Return license-compliance findings for every non-permissive dependency."""
    if packages is None:
        packages = parse_repo_manifests(Path(root) if isinstance(root, str) else root)
    findings: List[dict] = []
    seen: set = set()
    for pkg in packages:
        dedup = (pkg.ecosystem, pkg.name.lower())
        if dedup in seen:
            continue
        seen.add(dedup)
        lic = _lookup(pkg)
        cat = classify(lic)
        sev = _SEVERITY.get(cat)
        if sev is None:
            continue
        findings.append(_finding(pkg, lic, cat, sev))
    findings.sort(key=lambda f: ({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f["severity"], 0), f["rule_id"]), reverse=True)
    return findings


# ── Policy ─────────────────────────────────────────────────────────

DEFAULT_FORBIDDEN = {"copyleft", "proprietary"}
DEFAULT_APPROVED = {"permissive", "weak-copyleft"}


def evaluate_policy(findings: List[dict], forbidden: Optional[set] = None) -> dict:
    """Return {allowed: bool, blocked: [...], warnings: [...]} against policy."""
    forbidden = forbidden if forbidden is not None else DEFAULT_FORBIDDEN
    blocked = [f for f in findings if f["metadata"]["sca"]["license_category"] in forbidden]
    warnings = [f for f in findings if f["severity"] == "MEDIUM"]
    return {"allowed": not blocked, "blocked": blocked, "warnings": warnings}


# ── CLI ────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC SCA License Compliance")
    p.add_argument("--repo", default=".", help="Repository root")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--gate", action="store_true", help="Exit 1 if forbidden licenses found (PR-gate)")
    args = p.parse_args()

    packages = parse_repo_manifests(args.repo)
    if not packages:
        print("No dependency manifests found.")
        return

    findings = scan_licenses(args.repo, packages)
    policy = evaluate_policy(findings)

    print(f"📦 {len(packages)} dependencies scanned for licenses")
    if not findings:
        print("All dependencies use permissive/approved licenses ✅")
        return

    print(f"\n{'Sev':<8} {'Package':<28} {'Category':<14} {'License'}")
    print("-" * 78)
    for f in findings:
        sca = f["metadata"]["sca"]
        print(f"{f['severity']:<8} {sca['package']:<28} {sca['license_category']:<14} {sca['license'] or '?'}")

    print(f"\n{len(findings)} license findings "
          f"({len(policy['blocked'])} forbidden, {len(policy['warnings'])} warnings)")
    print(f"Policy gate: {'BLOCKED 🚫' if not policy['allowed'] else 'PASS ✅'}")
    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    if args.gate and not policy["allowed"]:
        import sys
        sys.exit(1)


if __name__ == "__main__":
    main()
