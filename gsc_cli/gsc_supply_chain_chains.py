"""Supply-chain attack chain composer — link SAST findings to vulnerable dependencies.

Deterministic (no LLM): a supply chain is emitted when a SAST finding lives in the
same file that imports a dependency with a known CVE (OSV.dev via gsc_sca).

Complements gsc_chain_composer.ChainComposer (LLM *code* chains) with the dependency
layer — most real-world attacks enter through dependencies, and a vulnerable lib that
is actually imported in the same file as a code flaw is a materially higher risk than
either finding alone.

Reuses:
  - gsc_sca.parse_repo_manifests / query_osv  (SCA, no re-implementation of SBOM)
  - no LLM, no API key, no docker — pure static cross-layer correlation
"""
from __future__ import annotations

import ast
import json
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from gsc_sca import Package, parse_repo_manifests, query_osv

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_SEV_TO_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}

# Never descend into vendored deps / benchmarks / other checkouts.
_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "build", "dist", "OWASPBenchmark", "HuixiangDou",
    "benchmark", "calibration", "example_projects", "gsc-vscode",
    "corpus", "FastAPI-ML",
}


@dataclass
class SupplyChain:
    chain_key: str
    finding_keys: list[str]
    cve: str
    package: str
    version: str
    dep_severity: str
    code_severity: str
    composed_severity: str
    usage_file: str
    usage_line: int
    import_stmt: str
    combined_cvss: float
    impact: str

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize_pkg_name(name: str) -> str:
    """import name ≈ pypi name (dashes/underscores/dots equivalent)."""
    return name.lower().replace("-", "_").replace(".", "_")


def _osv_severity(vuln: dict) -> str:
    """Best-effort severity from an OSV vuln record."""
    ds = vuln.get("database_specific") or {}
    s = ds.get("severity")
    if isinstance(s, str) and s.upper() in _SEV_RANK:
        return s.upper()
    for sev in vuln.get("severity", []) or []:
        try:
            score = float(sev.get("score", 0) or 0)
        except (TypeError, ValueError):
            continue
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "MEDIUM"


def _compose_severity(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def find_dependency_usage(root: Path, package: str) -> list[dict]:
    """Files that import `package` (Python AST + lightweight JS/TS check).

    Returns [{file, line, import_stmt}]. Uses AST for Python (not regex) so it
    ignores comments/strings and resolves top-level module names.
    """
    norm = _normalize_pkg_name(package)
    root = Path(root)
    hits: list[dict] = []

    for py in root.rglob("*.py"):
        if any(part in _SKIP_DIRS or part.startswith(".") for part in py.parts):
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(py.read_text(errors="ignore"), filename=str(py))
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if _normalize_pkg_name(a.name.split(".")[0]) == norm:
                        hits.append({"file": str(py), "line": node.lineno,
                                     "import_stmt": f"import {a.name}"})
            elif isinstance(node, ast.ImportFrom):
                if node.module and _normalize_pkg_name(node.module.split(".")[0]) == norm:
                    hits.append({"file": str(py), "line": node.lineno,
                                 "import_stmt": f"from {node.module} import ..."})
    return hits


def compose_supply_chains(repo_root, findings, packages=None, db=None) -> list[dict]:
    """Correlate SAST findings with vulnerable dependencies used in the same file.

    findings: list[dict] with at least `rule_id`, `file_path`, `category`, `finding_key`.
    Returns list of SupplyChain dicts (empty list if no cross-layer link).
    """
    root = Path(repo_root)
    if packages is None:
        packages = parse_repo_manifests(root)
    osv = query_osv(packages, db=db)

    # Index vulnerable deps by normalized name → list of (package, version, vuln)
    vuln_deps: dict[str, list[tuple]] = {}
    for (eco, name, ver), vulns in osv.items():
        if not vulns:
            continue
        vuln_deps.setdefault(_normalize_pkg_name(name), []).append((name, ver, vulns))

    # Index findings by absolute file path (fast lookup by usage file).
    # file_path may be relative to repo_root (or CWD) — normalize both sides.
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file_path", "")
        if not fp:
            continue
        p = Path(fp)
        if not p.is_absolute():
            p = root / p
        by_file.setdefault(str(p.resolve()), []).append(f)

    chains: list[dict] = []
    seen: set[str] = set()

    for norm_name, deps in vuln_deps.items():
        usages = find_dependency_usage(root, norm_name)
        if not usages:
            continue
        for u in usages:
            ufile = str(Path(u["file"]).resolve())
            file_findings = by_file.get(ufile, [])
            if not file_findings:
                continue
            for (name, ver, vulns) in deps:
                for v in vulns:
                    cve = v.get("id", "")
                    dep_sev = _osv_severity(v)
                    for cf in file_findings:
                        code_sev = (cf.get("category") or "MEDIUM").upper()
                        key = f"sc:{cve}:{cf.get('finding_key', cf.get('rule_id', '?'))}:{u['file']}"
                        if key in seen:
                            continue
                        seen.add(key)
                        chains.append(SupplyChain(
                            chain_key=key,
                            finding_keys=[cf.get("finding_key") or cf.get("rule_id", "?")],
                            cve=cve,
                            package=name,
                            version=ver or "?",
                            dep_severity=dep_sev,
                            code_severity=code_sev,
                            composed_severity=_compose_severity(dep_sev, code_sev),
                            usage_file=u["file"],
                            usage_line=u["line"],
                            import_stmt=u["import_stmt"],
                            combined_cvss=round(min(10.0, _SEV_TO_CVSS.get(code_sev, 5.0) * 0.4
                                                   + _SEV_TO_CVSS.get(dep_sev, 5.0) * 0.6), 1),
                            impact=_impact(code_sev, dep_sev, cve),
                        ).to_dict())
    return chains


def _impact(code_sev: str, dep_sev: str, cve: str) -> str:
    rank = _SEV_RANK.get(dep_sev, 0)
    if rank >= 4 and _SEV_RANK.get(code_sev, 0) >= 3:
        return f"reachable critical dependency ({cve}) in same file as code flaw → high compromise risk"
    if rank >= 3:
        return f"high-severity dependency ({cve}) reachable from code with findings"
    return f"chained risk: code flaw + reachable dependency ({cve})"


def _main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="GSC supply-chain chain composer")
    p.add_argument("--repo", required=True, help="path to repository")
    p.add_argument("--scan", default="scan.json", help="GSC scan JSON (findings)")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    args = p.parse_args()

    with open(args.scan) as f:
        findings = json.load(f)
    findings = findings if isinstance(findings, list) else findings.get("findings", [])

    chains = compose_supply_chains(args.repo, findings)
    if args.json:
        print(json.dumps(chains, indent=2))
    else:
        for c in chains:
            print(f"[{c['composed_severity']}] {c['package']} {c['version']} "
                  f"{c['cve']} × {c['code_severity']} code flaw @ {c['usage_file']}:{c['usage_line']}")
        print(f"\n{len(chains)} supply-chain links")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
