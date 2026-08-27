#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC SCA — Software Composition Analysis (v0.28).

Scans dependency manifests for known CVEs via OSV.dev (free, no API key).
Supports: requirements.txt (PyPI), package.json (npm), go.mod (Go).

CLI: gsc sca --repo ./project
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100
HTTP_TIMEOUT = 30

# ── Package model ──────────────────────────────────────────
@dataclass
class Package:
    name: str
    version: Optional[str]          # None = unpinned
    ecosystem: str                  # PyPI | npm | Go
    manifest: str                   # file path
    line: int
    raw: str


# ── Version extraction ─────────────────────────────────────
_VER_RE = re.compile(r"^(==|>=|<=|~=|!=|===|\^|~|>|<)?\s*([0-9][0-9A-Za-z.\-]*)")


def extract_version(spec: str) -> Optional[str]:
    """Return concrete version for OSV. Ranges → lower bound (conservative)."""
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return None
    first = spec.split(",")[0].strip()
    m = _VER_RE.match(first)
    if not m:
        return None
    op, ver = m.group(1), m.group(2)
    if op == "!=":
        return None  # excluded version — can't pin
    return ver


# ── Manifest parsers ───────────────────────────────────────
def parse_requirements(path: str, content: str) -> List[Package]:
    packages = []
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.split("#")[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._\[\]-]+)\s*(.*)$", stripped)
        if not m:
            continue
        name = re.sub(r"\[.*\]", "", m.group(1))  # strip [extras]
        spec = m.group(2).strip()
        packages.append(Package(
            name=name, version=extract_version(spec),
            ecosystem="PyPI", manifest=path, line=line_no, raw=stripped))
    return packages


def parse_package_lock(content: str) -> dict:
    """Parse package-lock.json → {name: exact_version} for hoisted (depth-1)
    dependencies only (npm lockfile v2/v3). Nested transitive copies
    (node_modules/a/node_modules/b) are skipped so a transitive version never
    overwrites the direct dependency's version."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {}
    out: dict = {}
    for pkg_key, meta in (data.get("packages") or {}).items():
        if not isinstance(meta, dict):
            continue
        if not pkg_key.startswith("node_modules/"):
            continue  # skip root "" and workspace source entries
        if "/node_modules/" in pkg_key:
            continue  # skip nested transitive copies
        name = pkg_key[len("node_modules/"):]
        ver = meta.get("version")
        if name and ver:
            out[name] = ver
    return out


def parse_yarn_lock(content: str) -> dict:
    """Parse yarn.lock (classic v1 and berry v2+) → {name: exact_version}.

    Handles both header styles — v1 ``name@spec:`` + ``version "x.y.z"``, and
    berry ``"name@npm:^spec":`` + ``version: x.y.z`` — including @scoped names."""
    out: dict = {}
    current: Optional[str] = None
    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # Header line at column 0 (no leading indent): name@spec: (v1) or "name@npm:^spec": (berry).
        # Indented lines inside a block (version/resolved/dependencies) never parse as headers.
        if s == line and s.endswith(":") and "@" in s and not s.lower().startswith(("version", "__")):
            body = s.rstrip(":").strip().strip('"')
            if body.startswith("@"):
                # @scope/name@spec → keep the leading @scope
                name = "@" + body[1:].split("@", 1)[0]
            else:
                name = body.split("@", 1)[0]
            current = name
            continue
        # Version line: version "x.y.z" (v1) or version: x.y.z (berry)
        m = re.match(r'^version\s*:?\s*["\']?\s*([0-9][0-9A-Za-z.\-+]*)', s, re.IGNORECASE)
        if m and current:
            out[current] = m.group(1)
            current = None
    return out


def parse_go_sum(content: str) -> dict:
    """Parse go.sum → {module: exact_version}. Lines are ``module version h1:...``;
    ``module version/go.mod h1:...`` entries are checksum-only and skipped."""
    out: dict = {}
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("h1:"):
            if parts[1].endswith("/go.mod"):
                continue  # checksum-only entry, not a concrete version line
            out[parts[0]] = parts[1].lstrip("v")
    return out


_RANGE_HINT = re.compile(r'[\^~><*|]| - ')


def parse_package_json(path: str, content: str,
                       lock_versions: Optional[dict] = None) -> List[Package]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages = []
    lines = content.splitlines()
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec_str = str(spec)
            version = extract_version(spec_str)
            # DD-06: a manifest range (^15.5.16) must resolve to the exact
            # version pinned in package-lock.json — otherwise the lower bound
            # makes an actually-patched dependency look vulnerable.
            if (lock_versions and name in lock_versions
                    and _RANGE_HINT.search(spec_str)):
                version = lock_versions[name]
            packages.append(Package(
                name=name, version=version,
                ecosystem="npm", manifest=path,
                line=_find_line(lines, f'"{name}"'),
                raw=f"{name}@{spec}"))
    return packages


def _find_line(lines: List[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0


def parse_go_mod(path: str, content: str, go_sum: Optional[dict] = None) -> List[Package]:
    packages = []
    in_block = False
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.split("//")[0].strip()
        if stripped.startswith("require ("):
            in_block = True; continue
        if in_block and stripped == ")":
            in_block = False; continue
        if stripped.startswith("require ") and "(" not in stripped:
            parts = stripped[len("require "):].split()
            if len(parts) >= 2:
                packages.append(_go_pkg(parts[0], parts[1], go_sum, path, line_no, stripped))
            continue
        if in_block and stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                packages.append(_go_pkg(parts[0], parts[1], go_sum, path, line_no, stripped))
    return packages


def _go_pkg(name: str, version: str, go_sum: Optional[dict],
            path: str, line_no: int, raw: str) -> Package:
    # DD-06: go.sum holds the actually-built version — prefer it over the require pin.
    if go_sum and name in go_sum:
        version = go_sum[name]
    return Package(name=name, version=version.lstrip("v"), ecosystem="Go",
                   manifest=path, line=line_no, raw=raw)


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
}


# Directories never descended into (mirrors _SKIP_DIRS in gsc_supply_chain_chains.py
# so SCA reports GSC's OWN dependency posture, not fixture noise).
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
              "vendor", "tests", "test", "dist", "build", "OWASPBenchmark",
              "HuixiangDou", "benchmark", "calibration", "example_projects",
              "gsc-vscode", "corpus", "FastAPI-ML"}


# ── Solidity compiler version (solc) detection ──────────────────────────────
_SOLIDITY_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_FOUNDRY_SOLC_RE = re.compile(r"(?i)^\s*solc(?:_version)?\s*=\s*[\"']?([0-9][0-9A-Za-z.\-]*)")
_JS_SOLC_VERSION_RE = re.compile(r"(?i)\bversion\s*:\s*[\"']([0-9][0-9A-Za-z.\-]*)[\"']")

# config files that pin a concrete solc version
_SOLC_PIN_FILES = {"foundry.toml", "hardhat.config.js", "hardhat.config.ts",
                   "truffle-config.js", "truffle.js"}


def _collect_solc_packages(root: Path) -> List[Package]:
    """Return deduped solc Package entries (ecosystem='Solidity').

    Scans .sol ``pragma solidity`` directives and concrete solc pins in
    foundry.toml / hardhat.config.js / truffle-config.js. One entry per
    distinct detected version.
    """
    seen: dict[str, tuple[str, int, str]] = {}  # version -> (manifest, line, raw)

    for fp in root.rglob("*.sol"):
        if any(p in _SKIP_DIRS for p in fp.parts):
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            m = _SOLIDITY_PRAGMA_RE.search(line)
            if not m:
                continue
            ver = extract_version(m.group(1))
            if ver and ver not in seen:
                seen[ver] = (str(fp), line_no, line.strip())

    for fname in _SOLC_PIN_FILES:
        for fp in root.rglob(fname):
            if any(p in _SKIP_DIRS for p in fp.parts):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rx = _FOUNDRY_SOLC_RE if fp.name == "foundry.toml" else _JS_SOLC_VERSION_RE
            for line_no, line in enumerate(content.splitlines(), 1):
                m = rx.search(line)
                if not m:
                    continue
                ver = extract_version(m.group(1))
                if ver and ver not in seen:
                    seen[ver] = (str(fp), line_no, line.strip())

    return [Package(name="solc", version=v, ecosystem="Solidity",
                    manifest=mf, line=ln, raw=raw)
            for v, (mf, ln, raw) in seen.items()]


def _load_lock_versions(manifest: Path) -> dict:
    """Load exact versions from sibling lockfiles (package-lock.json or yarn.lock)."""
    for lockname, parser in (("package-lock.json", parse_package_lock),
                              ("yarn.lock", parse_yarn_lock)):
        lock = manifest.with_name(lockname)
        if not lock.exists():
            continue
        try:
            return parser(lock.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return {}


def _load_go_sum(manifest: Path) -> dict:
    """Load exact versions from the sibling go.sum, if present."""
    lock = manifest.with_name("go.sum")
    if not lock.exists():
        return {}
    try:
        return parse_go_sum(lock.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {}


def parse_repo_manifests(root) -> List[Package]:
    """Collect all packages from all manifests in repo (incl. solc versions)."""
    root = Path(root)
    packages = []
    for manifest_name, parser in MANIFEST_PARSERS.items():
        for manifest in root.rglob(manifest_name):
            if any(p in _SKIP_DIRS for p in manifest.parts):
                continue
            try:
                content = manifest.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if manifest_name == "package.json":
                lock_versions = _load_lock_versions(manifest)
                packages.extend(parser(str(manifest), content, lock_versions=lock_versions))
            elif manifest_name == "go.mod":
                go_sum = _load_go_sum(manifest)
                packages.extend(parser(str(manifest), content, go_sum=go_sum))
            else:
                packages.extend(parser(str(manifest), content))
    packages.extend(_collect_solc_packages(root))
    return packages


# ── OSV client with cache ──────────────────────────────────
def query_osv(packages: List[Package], db=None) -> dict:
    """Query OSV.dev batch + manual web3/solc feed. Returns {(eco,name,ver): [vulns]}."""
    from gsc_core.gsc_web3_feed import manual_vulns, solc_vulns

    results: dict = {}
    to_query: List[Tuple[Package, tuple]] = []

    for p in packages:
        if not p.version:
            continue
        key = (p.ecosystem, p.name, p.version)
        if p.ecosystem == "Solidity":
            # solc is not an OSV ecosystem — manual known-bugs feed only
            vulns = solc_vulns(p.version)
            if vulns:
                results[key] = vulns
            continue
        cached = _cache_get(db, key) if db else None
        if cached is not None:
            results[key] = cached
        else:
            to_query.append((p, key))

    for i in range(0, len(to_query), BATCH_SIZE):
        batch = to_query[i:i + BATCH_SIZE]
        queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem},
                    "version": p.version} for p, _ in batch]
        try:
            import urllib.request as request
            body = json.dumps({"queries": queries}).encode()
            req = request.Request(OSV_BATCH_URL, data=body)
            req.add_header("Content-Type", "application/json")
            with request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                vulns_per_query = json.loads(resp.read()).get("results", [])
        except Exception:
            continue  # batch failed — skip, don't crash scan

        for (p, key), res in zip(batch, vulns_per_query):
            vulns = res.get("vulns", [])
            results[key] = vulns
            if db:
                _cache_put(db, key, vulns)

    # augment with manual web3 CVE feed (offline fallback — only fills gaps OSV missed)
    for p in packages:
        if not p.version or p.ecosystem == "Solidity":
            continue
        key = (p.ecosystem, p.name, p.version)
        existing_ids = {v.get("id") for v in results.get(key, [])}
        extra = [v for v in manual_vulns(p.ecosystem, p.name, p.version)
                 if v["id"] not in existing_ids]
        if extra:
            results[key] = results.get(key, []) + extra

    return results


def _cache_key_hash(key: tuple) -> str:
    return hashlib.sha256(f"{key[0]}:{key[1]}:{key[2]}".encode()).hexdigest()[:16]


def _cache_get(db, key) -> Optional[list]:
    if not db:
        return None
    row = db.conn.execute(
        "SELECT vulns_json FROM sca_cache WHERE ecosystem=? AND package=? AND version=?",
        key).fetchone()
    if row:
        try:
            return json.loads(row["vulns_json"])
        except json.JSONDecodeError:
            return None
    return None


def _cache_put(db, key, vulns: list):
    if not db:
        return
    db.conn.execute(
        "INSERT OR REPLACE INTO sca_cache (ecosystem, package, version, vulns_json) VALUES (?,?,?,?)",
        (key[0], key[1], key[2], json.dumps(vulns)))
    db.conn.commit()


# ── Severity + findings ────────────────────────────────────
def vuln_severity(vuln: dict) -> Tuple[str, Optional[float]]:
    """Returns (severity, cvss_score)."""
    for holder in [vuln] + vuln.get("affected", []):
        for sev in holder.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score = _cvss_score(sev.get("score", ""))
                if score is not None:
                    return _cvss_to_severity(score), score

    for holder in vuln.get("affected", []) + [vuln]:
        ds = holder.get("database_specific", {}) or {}
        if ds.get("severity"):
            return _normalize_severity(ds["severity"]), None

    return "MEDIUM", None


def _cvss_score(vector: str) -> Optional[float]:
    try:
        from cvss import CVSS3
        return float(CVSS3(vector).base_score)
    except Exception:
        return None


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _normalize_severity(raw: str) -> str:
    raw = raw.upper()
    for level in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        if level in raw:
            return "MEDIUM" if level == "MODERATE" else level
    return "MEDIUM"


def extract_fixed_version(vuln: dict, package_name: str) -> Optional[str]:
    """Find the version where this CVE is fixed."""
    fixed = None
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != package_name:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed = ev["fixed"]  # last one wins
    return fixed


_SEV_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def sca_findings(packages: List[Package], osv_results: dict,
                 usage: dict | None = None) -> List[dict]:
    findings = []
    for p in packages:
        if not p.version:
            continue
        key = (p.ecosystem, p.name, p.version)
        for vuln in osv_results.get(key, []):
            vuln_id = vuln.get("id", "UNKNOWN")
            severity, cvss = vuln_severity(vuln)
            fixed = extract_fixed_version(vuln, p.name)
            snippet = p.raw or f"{p.name}=={p.version}"

            # Ф5 reachability: not-reachable → downgrade severity
            reachable = True
            original_severity = severity
            if usage is not None:
                from gsc_reachability import is_reachable
                reachable = is_reachable(p.name, usage, ecosystem=p.ecosystem)
                if not reachable:
                    severity = _SEV_DOWNGRADE.get(severity, severity)

            finding_key = hashlib.sha256(
                f"GS030-{vuln_id}{p.manifest}{snippet}".encode()
            ).hexdigest()[:12]
            meta = {
                "sca": {
                    "package": p.name,
                    "ecosystem": p.ecosystem,
                    "current_version": p.version,
                    "vuln_id": vuln_id,
                    "cvss_score": cvss,
                    "fixed_version": fixed,
                    "aliases": vuln.get("aliases", []),
                },
                "reachability": "reachable" if reachable else "not_reachable",
            }
            if not reachable:
                meta["original_severity"] = original_severity
            if p.ecosystem == "Solidity":
                title = f"Vulnerable Solidity compiler {p.version}: {vuln.get('summary', vuln_id)}"
            else:
                title = f"Vulnerable dependency {p.name}@{p.version}: {vuln.get('summary', vuln_id)}"
            findings.append({
                "finding_key": finding_key,
                "rule_id": f"GS030-{vuln_id}",
                "title": title,
                "severity": severity,
                "confidence": 0.90,
                "file_path": p.manifest,
                "line_number": p.line,
                "detail": snippet,
                "metadata": meta,
            })
    return findings


# ── Deterministic bump fix ─────────────────────────────────
def generate_sca_fix(finding: dict, manifest_content: str) -> Optional[dict]:
    """Deterministic fix: bump version. No LLM needed."""
    sca = finding.get("metadata", {}).get("sca", {})
    fixed = sca.get("fixed_version")
    current = sca.get("current_version")
    pkg = sca.get("package")
    if not fixed or not current or not pkg:
        return None
    pattern = re.compile(
        rf"^({re.escape(pkg)}\s*==\s*){re.escape(current)}\s*$",
        re.MULTILINE | re.IGNORECASE)
    new_content, n = pattern.subn(rf"\g<1>{fixed}", manifest_content)
    if n == 0:
        return None
    return {"type": "sca-bump", "patched": new_content,
            "from": current, "to": fixed}


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC SCA — dependency CVE scan")
    p.add_argument("--repo", default=".", help="Repository root")
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args()

    packages = parse_repo_manifests(args.repo)
    if not packages:
        print("No dependency manifests found.")
        return

    # Ф5 reachability: собрать импорты/вызовы по экосистемам (Python + JS/TS + Go)
    from gsc_reachability import collect_usage
    usage = collect_usage(args.repo)

    py_imports = len(usage["PyPI"].get("imports", set()))
    js_imports = len(usage["npm"].get("imports", set()))
    go_imports = len(usage["Go"].get("imports", set()))
    print(f"📦 {len(packages)} packages in manifests")
    print(f"🔍 Reachability: {py_imports} py / {js_imports} js / {go_imports} go imports, "
          f"{len(usage['PyPI'].get('calls', set()))} py calls")
    results = query_osv(packages)
    findings = sca_findings(packages, results, usage=usage)
    findings.sort(key=lambda f: (-_sev_rank(f["severity"]), f["rule_id"]))

    if not findings:
        print("No CVEs found ✅")
        return

    print(f"\n{'Sev':<10} {'Package':<25} {'Current':<12} {'Fixed':<12} {'CVE'}")
    print("-" * 80)
    for f in findings:
        sca = f.get("metadata", {}).get("sca", {})
        reach = f.get("metadata", {}).get("reachability", "?")
        print(f"{f['severity']:<10} {sca.get('package',''):<25} "
              f"{sca.get('current_version',''):<12} {sca.get('fixed_version','') or '?':<12} "
              f"{sca.get('vuln_id','?')} [{reach}]")

    print(f"\n{len(findings)} CVEs found")
    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))


def _sev_rank(s):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)


if __name__ == "__main__":
    main()
