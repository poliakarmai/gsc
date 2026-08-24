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
import re
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


# ── JS/TS reachability (npm) ────────────────────────────────

# ESM `import x from 'pkg'` / side-effect `import 'pkg'` / CJS `require('pkg')` /
# dynamic `import('pkg')`. `(?<![\w$])` blocks `myimport …` identifiers.
_JS_IMPORT_RE = re.compile(
    r"(?<![\w$])"
    r"(?:import\s+(?:[\w*\s{},]*\s+from\s+)?|import\s*\(\s*|require\s*\(\s*)"
    r"\s*['\"]([^'\"]+)['\"]"
)


def _js_root_specifier(spec: str) -> str:
    """npm package name from an import specifier: `@scope/pkg/sub` → `@scope/pkg`,
    `pkg/sub` → `pkg`, relative (`./x`) and builtins (`node:fs`) → None."""
    spec = spec.strip()
    if not spec or spec.startswith(".") or spec.startswith("node:"):
        return ""
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return spec.split("/")[0]


def _strip_js_comments(content: str) -> str:
    """Remove // and /* */ comments so commented-out imports don't count as reachable."""
    content = re.sub(r"//[^\n]*", "", content)
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    return content


def collect_js_usage(root) -> Dict[str, Set[str]]:
    """Collect imported npm packages from .js/.ts/.jsx/.tsx (import + require).

    Returns {imports: set} — root package specifiers (`lodash`, `@scope/pkg`),
    with relative/builtin specifiers dropped and comments stripped."""
    root = Path(root)
    imports: Set[str] = set()
    exts = (".js", ".ts", ".jsx", ".tsx")
    if root.is_dir():
        for fp in root.rglob("*"):
            if fp.suffix not in exts:
                continue
            if any(part in _SKIP_DIRS for part in fp.parts):
                continue
            try:
                content = fp.read_text(errors="replace")
            except OSError:
                continue
            content = _strip_js_comments(content)
            for m in _JS_IMPORT_RE.finditer(content):
                root_spec = _js_root_specifier(m.group(1))
                if root_spec:
                    imports.add(root_spec)
    return {"imports": imports}


# ── Go reachability ─────────────────────────────────────────

_GO_SINGLE_IMPORT_RE = re.compile(r"\bimport\s+(?:[\w.\s]*)\s*\"([^\"]+)\"")
_GO_BLOCK_IMPORT_RE = re.compile(r"\bimport\s*\(\s*([^)]*)\)", re.DOTALL)
_GO_PATH_RE = re.compile(r"\"([^\"]+)\"")


def collect_go_usage(root) -> Dict[str, Set[str]]:
    """Collect imported Go module paths from `import` statements.

    Returns {imports: set} — full module paths (`github.com/gin-gonic/gin`).
    Handles single-line, aliased (`import _ "x"` / `import . "x"` / `import f "x"`)
    and parenthesised import blocks; strips comments so commented-out imports
    don't count as reachable."""
    root = Path(root)
    imports: Set[str] = set()
    if not root.is_dir():
        return {"imports": imports}
    for fp in root.rglob("*.go"):
        if any(part in _SKIP_DIRS for part in fp.parts):
            continue
        try:
            content = fp.read_text(errors="replace")
        except OSError:
            continue
        content = re.sub(r"//[^\n]*", "", content)
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
        for m in _GO_SINGLE_IMPORT_RE.finditer(content):
            imports.add(m.group(1))
        for m in _GO_BLOCK_IMPORT_RE.finditer(content):
            for pm in _GO_PATH_RE.finditer(m.group(1)):
                imports.add(pm.group(1))
    return {"imports": imports}


def collect_usage(root) -> Dict[str, Dict[str, Set[str]]]:
    """Collect reachability usage for all ecosystems in one structured dict.

    Returns {ecosystem: {imports, calls}} — PyPI/npm/Go layers kept SEPARATE so
    a Python module name can never satisfy an npm reachability check (and vice
    versa). This is the shape sca_findings() expects."""
    return {
        "PyPI": collect_python_usage(root),
        "npm": collect_js_usage(root),
        "Go": collect_go_usage(root),
    }


def _usage_layer(usage: dict, ecosystem: str) -> Dict[str, Set[str]]:
    """Resolve the per-ecosystem layer from a usage dict.

    Structured usage ({ecosystem: {imports, calls}}) → the matching layer.
    Flat legacy usage ({imports, calls}) → used as-is (PyPI semantics)."""
    if isinstance(usage, dict) and ecosystem in usage \
            and isinstance(usage[ecosystem], dict):
        return usage[ecosystem]
    return usage


def is_reachable(package_name: str, usage: Dict[str, Set[str]],
                 vulnerable_funcs: Set[str] | None = None,
                 ecosystem: str = "PyPI") -> bool:
    """Reachable, если пакет реально используется в коде.

    - ecosystem="PyPI" (default): модуль пакета импортирован ИЛИ уязвимая
      функция вызвана (поведение как раньше).
    - ecosystem="npm": пакет импортирован в JS/TS (import/require).
    - ecosystem="Go": module path импортирован в .go (точное или по префиксу `pkg/`).
    """
    layer = _usage_layer(usage, ecosystem)

    if ecosystem == "npm":
        imports = layer.get("imports", set())
        target = _js_root_specifier(package_name)
        for mod in module_names_for_package(package_name):
            if mod in imports:
                return True
        return target in imports

    if ecosystem == "Go":
        imports = layer.get("imports", set())
        for imp in imports:
            if imp == package_name or imp.startswith(package_name + "/"):
                return True
        return False

    # PyPI (default) — original behaviour
    imports = layer.get("imports", set())
    calls = layer.get("calls", set())
    imports_norm = {normalize_module(m) for m in imports}

    for mod in module_names_for_package(package_name):
        if normalize_module(mod) in imports_norm:
            return True

    if vulnerable_funcs and any(f in calls for f in vulnerable_funcs):
        return True

    return False
