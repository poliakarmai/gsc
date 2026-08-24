# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Reachability Analysis (Ф5).

Определяет, используется ли уязвимая зависимость в коде (import / call), чтобы
отличить **reachable** (реальный риск) от **not-reachable** (установлена, но не
используется). Reachability-анализ для SCA.

Контракт (закреплён в tests/test_phases_2_6.py::TestReachability):
  analyze_project(root) → (ImportVisitor, CallVisitor, usage)
  check_reachability(package, functions, imp, call, usage) → verdict dict
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Set, Tuple

# PyPI package name → import module name (неочевидные соответствия)
PACKAGE_IMPORT_MAP = {
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "pillow": "pil",
    "beautifulsoup4": "bs4",
    "python-dotenv": "dotenv",
    "opencv-python": "cv2",
    "scikit-learn": "sklearn",
    "psycopg2-binary": "psycopg2",
    "mysqlclient": "mysqldb",
    "google-api-python-client": "googleapiclient",
}

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules",
              "site-packages", "dist-packages"}


class ImportVisitor(ast.NodeVisitor):
    """Собирает импортируемые модули: `import X` → .imports, `from X import Y` → .from_imports."""

    def __init__(self):
        self.imports: Dict[str, int] = {}
        self.from_imports: Dict[str, int] = {}

    def visit_Import(self, node: ast.Import):
        for a in node.names:
            root = a.name.split(".")[0]
            self.imports[root] = self.imports.get(root, 0) + 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and node.level == 0:
            root = node.module.split(".")[0]
            self.from_imports[root] = self.from_imports.get(root, 0) + 1
        self.generic_visit(node)


class CallVisitor(ast.NodeVisitor):
    """Собирает вызываемые функции/методы."""

    def __init__(self):
        self.calls: Set[str] = set()

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            self.calls.add(node.func.attr)
        elif isinstance(node.func, ast.Name):
            self.calls.add(node.func.id)
        self.generic_visit(node)


def normalize_module(name: str) -> str:
    return name.lower().replace("-", "_")


def module_names_for_package(package_name: str) -> Set[str]:
    """Возможные import-модули для PyPI-пакета."""
    norm = normalize_module(package_name)
    names = {norm, package_name.lower()}
    mapped = PACKAGE_IMPORT_MAP.get(norm)
    if mapped:
        names.add(mapped)
    return names


def analyze_project(root) -> Tuple[ImportVisitor, CallVisitor, dict]:
    """Просканировать все .py под root → (imp, call, usage)."""
    imp = ImportVisitor()
    call = CallVisitor()
    root = Path(root)
    if root.is_dir():
        for py in root.rglob("*.py"):
            if any(part in _SKIP_DIRS for part in py.parts):
                continue
            try:
                tree = ast.parse(py.read_text(errors="replace"))
            except (SyntaxError, ValueError, UnicodeDecodeError):
                continue
            imp.visit(tree)
            call.visit(tree)
    usage = {
        "imports": set(imp.imports.keys()) | set(imp.from_imports.keys()),
        "calls": set(call.calls),
    }
    return imp, call, usage


def check_reachability(package_name: str, functions, imp: ImportVisitor,
                       call: CallVisitor, usage: dict | None = None) -> dict:
    """Вердикт reachability: imported, called, reachable, confidence.

    reachable = пакет импортирован И (уязвимая) функция вызвана.
    confidence — уверенность в вердикте: not-imported → высокая, imported+not-called → низкая
    (функция может вызываться динамически через getattr/рефлексию).
    """
    imports = set(imp.imports.keys()) | set(imp.from_imports.keys())
    imports_norm = {normalize_module(m) for m in imports}

    imported = any(
        normalize_module(mod) in imports_norm
        for mod in module_names_for_package(package_name)
    )
    called = any(f in call.calls for f in (functions or []))

    reachable = imported and called
    if not imported:
        confidence = 0.95
    elif called:
        confidence = 0.85
    else:
        confidence = 0.60

    return {"imported": imported, "called": called,
            "reachable": reachable, "confidence": confidence}


# ── Совместимость с gsc_sca ─────────────────────────────────

def collect_python_usage(root) -> Dict[str, Set[str]]:
    """Обёртка: {imports: set, calls: set} для gsc_sca.py."""
    _, _, usage = analyze_project(root)
    return usage


def is_reachable(package_name: str, usage: Dict[str, Set[str]],
                 vulnerable_funcs: Set[str] | None = None) -> bool:
    """Reachable, если модуль пакета импортирован ИЛИ уязвимая функция вызвана."""
    imports = usage.get("imports", set())
    calls = usage.get("calls", set())
    imports_norm = {normalize_module(m) for m in imports}

    for mod in module_names_for_package(package_name):
        if normalize_module(mod) in imports_norm:
            return True

    if vulnerable_funcs and any(f in calls for f in vulnerable_funcs):
        return True

    return False
