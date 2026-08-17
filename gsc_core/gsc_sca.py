#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC SCA — Software Composition Analysis (v0.28).

Scans dependency manifests for known CVEs via OSV.dev (free, no API key).
Supports: requirements.txt (PyPI), package.json (npm), go.mod (Go).

CLI: gsc sca --repo ./project
"""

from __future__ import annotations

import json, re, hashlib, os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


def parse_package_json(path: str, content: str) -> List[Package]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages = []
    lines = content.splitlines()
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            packages.append(Package(
                name=name, version=extract_version(str(spec)),
                ecosystem="npm", manifest=path,
                line=_find_line(lines, f'"{name}"'),
                raw=f"{name}@{spec}"))
    return packages


def _find_line(lines: List[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0


def parse_go_mod(path: str, content: str) -> List[Package]:
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
                packages.append(Package(
                    name=parts[0], version=parts[1].lstrip("v"),
                    ecosystem="Go", manifest=path, line=line_no, raw=stripped))
            continue
        if in_block and stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                packages.append(Package(
                    name=parts[0], version=parts[1].lstrip("v"),
                    ecosystem="Go", manifest=path, line=line_no, raw=stripped))
    return packages


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
}


def parse_repo_manifests(root) -> List[Package]:
    """Collect all packages from all manifests in repo."""
    root = Path(root)
    packages = []
    skip_dirs = {"node_modules", "vendor", ".git", "venv", ".venv",
                 "__pycache__", "tests", "test", "dist"}
    for manifest_name, parser in MANIFEST_PARSERS.items():
        for manifest in root.rglob(manifest_name):
            if any(p in skip_dirs for p in manifest.parts):
                continue
            try:
                content = manifest.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            packages.extend(parser(str(manifest), content))
    return packages


# ── OSV client with cache ──────────────────────────────────
def query_osv(packages: List[Package], db=None) -> dict:
    """Query OSV.dev batch. Returns {(ecosystem, name, version): [vulns]}."""
    results: dict = {}
    to_query: List[Tuple[Package, tuple]] = []

    for p in packages:
        if not p.version:
            continue
        key = (p.ecosystem, p.name, p.version)
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
                reachable = is_reachable(p.name, usage)
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
            findings.append({
                "finding_key": finding_key,
                "rule_id": f"GS030-{vuln_id}",
                "title": f"Vulnerable dependency {p.name}@{p.version}: {vuln.get('summary', vuln_id)}",
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

    # Ф5 reachability: собрать импорты/вызовы из Python-кода
    from gsc_reachability import collect_python_usage
    usage = collect_python_usage(args.repo)

    print(f"📦 {len(packages)} packages in manifests")
    print(f"🔍 Reachability: {len(usage.get('imports', []))} imported modules, "
          f"{len(usage.get('calls', []))} called functions")
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
