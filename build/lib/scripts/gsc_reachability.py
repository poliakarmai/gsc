#!/usr/bin/env python3
"""GSC Reachability Analysis — MVP. Checks if vulnerable files are actually imported."""
import os, sys, json, re, subprocess
from pathlib import Path
from collections import defaultdict


def build_import_graph(project_path: str) -> dict[str, set[str]]:
    """Build a directed graph: file → set of files it imports."""
    graph = defaultdict(set)
    project = Path(project_path)

    py_files = list(project.rglob("*.py"))
    # Exclude test files, __pycache__, migrations
    py_files = [f for f in py_files if not any(
        kw in str(f) for kw in ["/test_", "/tests/", "__pycache__", "/migrations/", "/venv/", "/.venv/"]
    )]

    import_re = re.compile(r"^(?:from\s+(\S+)\s+import|import\s+(\S+))", re.MULTILINE)

    for f in py_files:
        try:
            content = f.read_text()
            imports = import_re.findall(content)
            for from_imp, direct_imp in imports:
                module = from_imp or direct_imp
                # Convert module path to approximate file path
                module_path = module.replace(".", "/")
                for candidate in [f"{module_path}.py", f"{module_path}/__init__.py"]:
                    candidate_path = project / candidate
                    if candidate_path.exists():
                        graph[str(f.relative_to(project))].add(str(candidate_path.relative_to(project)))
        except Exception:
            pass

    return dict(graph)


def is_reachable(file_path: str, import_graph: dict[str, set[str]]) -> bool:
    """Check if a file is imported by any other file (reachable)."""
    fp = Path(file_path)

    # Skip reachability check for non-code files — permissions matter regardless
    CODE_EXTS = {".py", ".go", ".ts", ".tsx", ".js", ".rs", ".java", ".c", ".cpp", ".h"}
    if fp.suffix not in CODE_EXTS:
        return True  # Always consider data/config files as reachable

    # Normalize paths
    rel = str(fp)

    # Check if any file imports this one
    for importer, imported in import_graph.items():
        if rel in imported or fp.name in str(imported):
            return True

    # Check if it's an entry point (main, __init__, app)
    name = fp.name
    if name in ("__init__.py", "__main__.py", "main.py", "app.py", "manage.py", "cli.py"):
        return True

    return False


def analyze_reachability(findings: list[dict], project_path: str) -> list[dict]:
    """Add reachability info to findings. Unreachable → downgrade severity."""
    try:
        graph = build_import_graph(project_path)
    except Exception:
        return findings

    for f in findings:
        fp = f.get("file_path", "")
        if not fp:
            continue

        if not is_reachable(fp, graph):
            # Downgrade unreachable code
            old_cat = f.get("category", "LOW")
            if old_cat == "CRITICAL":
                f["category"] = "HIGH"
                f["detail"] = (f.get("detail", "") + " [UNREACHABLE: file not imported]").strip()
            elif old_cat == "HIGH":
                f["category"] = "MEDIUM"
                f["detail"] = (f.get("detail", "") + " [UNREACHABLE: file not imported]").strip()

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gsc_reachability.py <project_path> [findings.json]")
        sys.exit(1)

    project_path = sys.argv[1]
    graph = build_import_graph(project_path)
    print(f"Files in import graph: {len(graph)}")
    
    # Show orphan files (not imported by anyone)
    all_imported = set()
    for imports in graph.values():
        all_imported.update(imports)
    orphans = [f for f in graph.keys() if f not in all_imported 
               and not f.endswith(("__init__.py", "__main__.py", "main.py", "app.py", "cli.py"))]
    
    if orphans:
        print(f"\nOrphan files (not imported by anyone, may be dead code):")
        for o in orphans[:10]:
            print(f"  {o}")
        if len(orphans) > 10:
            print(f"  ... and {len(orphans) - 10} more")
