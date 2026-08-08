#!/usr/bin/env python3
"""GSC Reachability Analyzer — Python AST-based call graph.

Определяет, вызывается ли уязвимый код из зависимостей
в реальном проекте. 90% CVE недостижимы — этот анализатор
отсеивает ложные срабатывания SCA.

Usage:
    python3 gsc_reachability.py --repo /path/to/project --cve CVE-2024-1234
    python3 gsc_reachability.py --repo . --sca-file sca_findings.json
"""

import ast, json, os, sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple


class ImportVisitor(ast.NodeVisitor):
    """Collect all imports and their aliases."""
    def __init__(self):
        self.imports: Dict[str, Set[str]] = defaultdict(set)  # module → {names}
        self.from_imports: Dict[str, Dict[str, str]] = defaultdict(dict)  # module → {name: alias}
        self.aliases: Dict[str, str] = {}  # alias → full_name

    def visit_Import(self, node):
        for alias in node.names:
            mod = alias.name
            asname = alias.asname or mod
            self.imports[mod].add(asname)
            self.aliases[asname] = mod
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            full = f"{mod}.{name}" if mod else name
            self.from_imports[mod][name] = asname
            self.aliases[asname] = full
        self.generic_visit(node)


class CallVisitor(ast.NodeVisitor):
    """Collect all function calls and their context."""
    def __init__(self):
        self.calls: List[Tuple[str, str, int]] = []  # (name, module_hint, line)

    def visit_Call(self, node):
        name = self._get_name(node.func)
        if name:
            self.calls.append((name, "", node.lineno))
        self.generic_visit(node)

    def _get_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        return ""


def analyze_project(repo_path: str) -> Tuple[ImportVisitor, CallVisitor, Dict[str, Set[str]]]:
    """Analyze a Python project: imports, calls, and usage graph."""
    repo = Path(repo_path)
    imp_visitor = ImportVisitor()
    call_visitor = CallVisitor()
    usage_graph: Dict[str, Set[str]] = defaultdict(set)  # module → {symbols_used}

    for py_file in repo.rglob("*.py"):
        if any(p in str(py_file) for p in [".venv", "venv", "__pycache__", "node_modules",
                                             ".git", "tests", "test_"]):
            continue
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
            imp_visitor.visit(tree)
            call_visitor.visit(tree)

            # Build usage per file
            relative = py_file.relative_to(repo)
            for call_name, _, line in call_visitor.calls:
                usage_graph[str(relative)].add(call_name)

        except (SyntaxError, UnicodeDecodeError, IsADirectoryError):
            continue

    return imp_visitor, call_visitor, usage_graph


def check_reachability(
    vulnerable_package: str,
    vulnerable_functions: List[str],
    imp_visitor: ImportVisitor,
    call_visitor: CallVisitor,
    usage_graph: Dict[str, Set[str]],
) -> dict:
    """
    Check if vulnerable functions from a package are reachable.

    Returns: {
        "reachable": bool,
        "evidence": [...],  # files and lines where vulnerable code is used
        "imported": bool,
        "called": bool,
        "confidence": float,
    }
    """
    result = {
        "reachable": False,
        "evidence": [],
        "imported": False,
        "called": False,
        "confidence": 0.0,
    }

    # Check if package is imported at all
    package_imported = False
    for mod, names in imp_visitor.imports.items():
        if mod == vulnerable_package or mod.startswith(f"{vulnerable_package}."):
            package_imported = True
            break
    for mod in imp_visitor.from_imports:
        if mod == vulnerable_package or mod.startswith(f"{vulnerable_package}."):
            package_imported = True
            break

    result["imported"] = package_imported

    if not package_imported:
        result["confidence"] = 0.95
        return result  # Package not imported → definitely not reachable

    # Check if vulnerable functions are called
    for vuln_func in vulnerable_functions:
        # Try various import paths
        patterns = [
            vuln_func,
            f"{vulnerable_package}.{vuln_func}",
            f"{vulnerable_package}.{vuln_func.split('.')[-1]}",
        ]

        for file, symbols in usage_graph.items():
            for call in symbols:
                for pattern in patterns:
                    if pattern in call or call.endswith(f".{vuln_func.split('.')[-1]}"):
                        result["evidence"].append({
                            "file": file,
                            "symbol": call,
                            "vulnerable": vuln_func,
                        })
                        result["called"] = True
                        break

        # Also check call visitor
        for call_name, mod_hint, line in call_visitor.calls:
            for pattern in patterns:
                if pattern in call_name:
                    result["evidence"].append({
                        "file": "unknown",
                        "line": line,
                        "symbol": call_name,
                        "vulnerable": vuln_func,
                    })
                    result["called"] = True
                    break

    if result["called"]:
        result["reachable"] = True
        result["confidence"] = 0.85
    elif package_imported:
        result["reachable"] = False
        result["confidence"] = 0.70  # Imported but not obviously called
    else:
        result["reachable"] = False
        result["confidence"] = 0.95  # Not imported

    return result


def analyze_sca_findings(sca_file: str, repo_path: str) -> List[dict]:
    """Analyze SCA findings for reachability."""
    with open(sca_file) as f:
        findings = json.load(f)
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    imp_visitor, call_visitor, usage_graph = analyze_project(repo_path)

    results = []
    for finding in findings:
        pkg = finding.get("package", finding.get("dependency", ""))
        vuln_funcs = finding.get("vulnerable_functions", [])
        cve = finding.get("cve_id", finding.get("id", "UNKNOWN"))

        if not pkg:
            continue

        # If no specific functions listed, check commonly vulnerable parts
        if not vuln_funcs:
            vuln_funcs = _guess_vulnerable_functions(pkg, finding)

        reach = check_reachability(pkg, vuln_funcs, imp_visitor, call_visitor, usage_graph)
        reach["cve"] = cve
        reach["package"] = pkg
        results.append(reach)

    return results


def _guess_vulnerable_functions(package: str, finding: dict) -> List[str]:
    """Guess which functions might be vulnerable based on package name and description."""
    desc = finding.get("description", finding.get("title", "")).lower()

    # Common patterns
    if "deserial" in desc or "pickle" in desc:
        return ["loads", "load", "Unpickler"]
    if "injection" in desc or "sqli" in desc:
        return ["execute", "raw", "executemany"]
    if "xxe" in desc or "xml" in desc:
        return ["parse", "fromstring", "parseString"]
    if "ssrf" in desc or "request" in desc:
        return ["get", "post", "request", "urlopen"]
    if "xss" in desc:
        return ["escape", "mark_safe", "format_html"]

    # Default: check if common entry points are used
    return ["__init__", "main", "run", "handle", "process"]


def generate_report(sca_results: List[dict]) -> str:
    """Generate human-readable reachability report."""
    total = len(sca_results)
    reachable = [r for r in sca_results if r["reachable"]]
    not_reachable = [r for r in sca_results if not r["reachable"]]
    imported_only = [r for r in sca_results if r["imported"] and not r["called"]]

    lines = [
        "## 📊 GSC Reachability Report",
        "",
        f"**Total CVEs:** {total}",
        f"**Reachable (real risk):** {len(reachable)} 🔴",
        f"**Imported but not called:** {len(imported_only)} 🟡",
        f"**Not imported (no risk):** {len(not_reachable) - len(imported_only)} 🟢",
        "",
    ]

    if reachable:
        lines.append("### 🔴 Reachable — Action Required")
        for r in reachable:
            lines.append(f"- **{r['cve']}** ({r['package']}) — {len(r['evidence'])} usage sites")
            for e in r["evidence"][:3]:
                lines.append(f"  - `{e.get('file', '?')}` → `{e.get('symbol', '?')}`")

    if imported_only:
        lines.append("")
        lines.append("### 🟡 Imported but Usage Unclear")
        for r in imported_only[:5]:
            lines.append(f"- **{r['cve']}** ({r['package']}) — imported, no direct calls detected")

    if not_reachable and len(not_reachable) - len(imported_only) > 0:
        lines.append("")
        lines.append("### 🟢 Not Reachable — Safe to Defer")
        lines.append(f"{len(not_reachable) - len(imported_only)} CVEs in dependencies not imported by this project.")

    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="GSC Reachability Analyzer")
    ap.add_argument("--repo", "-r", default=".", help="Path to project")
    ap.add_argument("--cve", help="Check specific CVE (requires --package)")
    ap.add_argument("--package", help="Vulnerable package name")
    ap.add_argument("--functions", nargs="*", help="Vulnerable function names")
    ap.add_argument("--sca-file", help="JSON file with SCA findings")
    ap.add_argument("--json", action="store_true", help="Output JSON")

    args = ap.parse_args()

    if args.cve and args.package:
        imp_visitor, call_visitor, usage_graph = analyze_project(args.repo)
        vuln_funcs = args.functions if args.functions else _guess_vulnerable_functions(args.package, {})
        result = check_reachability(args.package, vuln_funcs, imp_visitor, call_visitor, usage_graph)
        result["cve"] = args.cve

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"CVE: {args.cve} | Package: {args.package}")
            print(f"Reachable: {'🔴 YES' if result['reachable'] else '🟢 NO'}")
            print(f"Imported: {'Yes' if result['imported'] else 'No'}")
            print(f"Called: {'Yes' if result['called'] else 'No'}")
            print(f"Confidence: {result['confidence']:.0%}")
            if result["evidence"]:
                print("Evidence:")
                for e in result["evidence"]:
                    print(f"  {e['file']} → {e['symbol']}")

    elif args.sca_file:
        results = analyze_sca_findings(args.sca_file, args.repo)
        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            print(generate_report(results))

    else:
        # Demo mode
        print("🔍 GSC Reachability Analyzer")
        print(f"   Analyzing {args.repo}...")
        imp, call, usage = analyze_project(args.repo)
        modules = list(imp.imports.keys()) + list(imp.from_imports.keys())
        print(f"   📦 {len(set(modules))} unique imports")
        print(f"   📞 {len(call.calls)} function calls")
        print(f"   📁 {len(usage)} files with usage data")
        print(f"\n   Example: python3 gsc_reachability.py --repo . --cve CVE-2024-1234 --package requests")
