# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC AST-based intra-procedural taint tracking for Python (v0.21).

Rules:
  - Assignment from source → variable is tainted
  - Clean reassignment or sanitizer → taint removed
  - Sink call with tainted variable in args → violation
    (unless sink call itself contains sanitizer)
  - Overapproximation: taint propagates through branches intentionally
    (fewer false negatives; FPs handled by feedback loop)

Requires Python >= 3.9 (ast.unparse).
"""

import ast, re
from typing import Optional


class PythonTaintAnalyzer:
    def __init__(self, source_re: re.Pattern, sink_re: re.Pattern,
                 sanitizer_re: re.Pattern):
        self.source_re = source_re
        self.sink_re = sink_re
        self.sanitizer_re = sanitizer_re

    def analyze(self, content: str) -> Optional[list[int]]:
        """List of violation line numbers. None → AST not applicable (fallback to regex)."""
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return None
        violations: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                violations.extend(self._analyze_function(node))
        return sorted(set(violations))

    # ── Function-level analysis ──────────────────────────────

    def _analyze_function(self, func) -> list[int]:
        tainted: dict[str, int] = {}  # name → line of taint origin
        violations: list[int] = []
        for stmt in self._linearize(func.body):
            self._update_taint(stmt, tainted)
            violations.extend(self._find_sink_violations(stmt, tainted))
        return violations

    def _linearize(self, stmts) -> list[ast.stmt]:
        """Ordered traversal — ast.walk does NOT guarantee order."""
        out: list[ast.stmt] = []
        for s in stmts:
            out.append(s)
            if isinstance(s, ast.If):
                out.extend(self._linearize(s.body))
                out.extend(self._linearize(s.orelse))
            elif isinstance(s, (ast.For, ast.While, ast.AsyncFor)):
                out.extend(self._linearize(s.body))
                out.extend(self._linearize(s.orelse))
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                out.extend(self._linearize(s.body))
            elif isinstance(s, ast.Try):
                out.extend(self._linearize(s.body))
                for h in s.handlers:
                    out.extend(self._linearize(h.body))
                out.extend(self._linearize(s.orelse))
                out.extend(self._linearize(s.finalbody))
            # Nested FunctionDef/ClassDef intentionally NOT expanded —
            # they're analyzed separately by ast.walk(tree)
        return out

    # ── Taint tracking ───────────────────────────────────────

    def _update_taint(self, stmt, tainted: dict[str, int]) -> None:
        # -- Assign: x = expr --
        if isinstance(stmt, ast.Assign):
            expr_src = self._unparse(stmt.value)
            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            if self.sanitizer_re.search(expr_src):
                for t in targets:
                    tainted.pop(t, None)
            elif self.source_re.search(expr_src):
                for t in targets:
                    tainted[t] = stmt.lineno
            elif self._references_tainted(expr_src, tainted):
                for t in targets:
                    tainted[t] = stmt.lineno
            else:
                for t in targets:       # clean reassignment → clear taint
                    tainted.pop(t, None)

        # -- AnnAssign: x: Type = expr --
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            expr_src = self._unparse(stmt.value)
            if isinstance(stmt.target, ast.Name):
                name = stmt.target.id
                if self.sanitizer_re.search(expr_src):
                    tainted.pop(name, None)
                elif (self.source_re.search(expr_src)
                      or self._references_tainted(expr_src, tainted)):
                    tainted[name] = stmt.lineno
                else:
                    tainted.pop(name, None)

        # -- AugAssign: x += expr --
        elif isinstance(stmt, ast.AugAssign):
            expr_src = self._unparse(stmt.value)
            if isinstance(stmt.target, ast.Name):
                name = stmt.target.id
                if (self.source_re.search(expr_src)
                    or self._references_tainted(expr_src, tainted)):
                    tainted[name] = stmt.lineno

        # -- For: for x in iterable --
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_src = self._unparse(stmt.iter)
            names = [t.id for t in ast.walk(stmt.target)
                     if isinstance(t, ast.Name)]
            if (self.source_re.search(iter_src)
                or self._references_tainted(iter_src, tainted)):
                for n in names:
                    tainted[n] = stmt.lineno

    def _references_tainted(self, expr_src: str,
                            tainted: dict[str, int]) -> bool:
        return any(re.search(rf"\b{re.escape(name)}\b", expr_src)
                   for name in tainted)

    # ── Sink detection ───────────────────────────────────────

    def _find_sink_violations(self, stmt,
                              tainted: dict[str, int]) -> list[int]:
        if not tainted:
            return []
        out: list[int] = []
        for call in ast.walk(stmt):
            if not isinstance(call, ast.Call):
                continue
            call_src = self._unparse(call)
            if not self.sink_re.search(call_src):
                continue
            # db.query(sanitize(x)) — sanitizer inside sink call itself
            if self.sanitizer_re.search(call_src):
                continue
            args_src = " ".join(
                [self._unparse(a) for a in call.args]
                + [self._unparse(k.value) for k in call.keywords])
            for name in tainted:
                if re.search(rf"\b{re.escape(name)}\b", args_src):
                    out.append(call.lineno)
                    break
        return out

    @staticmethod
    def _unparse(node) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""
