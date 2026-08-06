# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
"""
GSC Security Invariant Engine v0.20.

Policy-as-code: verify structural invariants declared in .gsc-audit.yml
of the scanned repository. Deterministic, no LLM required.

Three invariant types:
  pattern    — regex across file
  structural — match → require nearby pattern (auth decorators, etc.)
  dataflow   — source → sink without sanitizer within one function

Design decisions:
  - Stateless: no DB migration needed
  - Fork-safe: engine disabled in safe_mode (config is untrusted)
  - Fail fast: invalid config → InvariantLoadError → exit 2
"""

import fnmatch, os, re
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

VALID_TYPES = {"pattern", "structural", "dataflow"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
MAX_PATTERN_LEN = 200  # ReDoS protection for untrusted repo configs

# Heuristic function start (Python/Go/Rust/TS/Java)
FUNC_START = re.compile(
    r"^[ \t]*(?:export\s+)?(?:async\s+)?(?:def|func|fn|function)\b"
    r"|^[ \t]*(?:public|private|protected)\s+[\w<>\[\],\s]+?\s+\w+\s*\(",
    re.MULTILINE,
)


class InvariantLoadError(Exception):
    """Configuration error → exit code 2."""


@dataclass
class Invariant:
    id: str
    name: str
    type: str          # pattern | structural | dataflow
    severity: str
    rule: dict
    paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class InvariantViolation:
    invariant_id: str
    invariant_type: str
    file: str
    line: int
    severity: str
    message: str
    snippet: str = ""


# ═══════════════════════════════════════════════════════════════
# BLOCK 1: Loader with validation (fail fast)
# ═══════════════════════════════════════════════════════════════

def load_invariants(config_path: str) -> list[Invariant]:
    """Load and validate invariants from .gsc-audit.yml."""
    if yaml is None:
        return []

    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return []
    except yaml.YAMLError as e:
        raise InvariantLoadError(f"YAML parse error: {e}")

    raw = cfg.get("invariants") or []
    if not isinstance(raw, list):
        raise InvariantLoadError("'invariants' must be a list")

    seen_ids = set()
    result = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise InvariantLoadError(f"invariant[{idx}] must be a mapping")
        for req in ("id", "name", "type", "severity", "rule"):
            if req not in item:
                raise InvariantLoadError(f"invariant[{idx}]: missing '{req}'")
        if item["id"] in seen_ids:
            raise InvariantLoadError(f"duplicate invariant id: {item['id']}")
        seen_ids.add(item["id"])
        if item["type"] not in VALID_TYPES:
            raise InvariantLoadError(
                f"{item['id']}: invalid type '{item['type']}'")
        severity = str(item["severity"]).upper()
        if severity not in VALID_SEVERITIES:
            raise InvariantLoadError(
                f"{item['id']}: invalid severity '{item['severity']}'")
        if not isinstance(item["rule"], dict):
            raise InvariantLoadError(f"{item['id']}: 'rule' must be a mapping")
        result.append(Invariant(
            id=item["id"], name=item["name"], type=item["type"],
            severity=severity, rule=item["rule"],
            paths=list(item.get("paths") or []),
            exclude_paths=list(item.get("exclude_paths") or []),
            enabled=bool(item.get("enabled", True)),
        ))
    return result


# ═══════════════════════════════════════════════════════════════
# BLOCK 2: Compile rules + path matching
# ═══════════════════════════════════════════════════════════════

def compile_invariant(inv: Invariant) -> dict[str, Any]:
    """Compile regexes from rule. Invalid regex → InvariantLoadError."""
    rule = inv.rule

    def _compile(field_name: str) -> re.Pattern:
        pattern = rule.get(field_name)
        if not isinstance(pattern, str) or not pattern:
            raise InvariantLoadError(
                f"{inv.id}: rule.{field_name} must be a non-empty string")
        if len(pattern) > MAX_PATTERN_LEN:
            raise InvariantLoadError(
                f"{inv.id}: rule.{field_name} exceeds {MAX_PATTERN_LEN} chars "
                f"(ReDoS protection)")
        try:
            return re.compile(pattern, re.MULTILINE)
        except re.error as e:
            raise InvariantLoadError(
                f"{inv.id}: rule.{field_name} invalid regex: {e}")

    if inv.type == "pattern":
        return {"pattern": _compile("pattern")}
    if inv.type == "structural":
        return {
            "match": _compile("match"),
            "require": _compile("require"),
            "within_lines": int(rule.get("within_lines", 3)),
            "lookbehind_lines": int(rule.get("lookbehind_lines", 2)),
        }
    if inv.type == "dataflow":
        return {
            "source": _compile("source"),
            "sink": _compile("sink"),
            "sanitizer": _compile("must_pass_through"),
        }
    raise InvariantLoadError(f"{inv.id}: unknown type '{inv.type}'")


def _glob_match(path: str, pattern: str) -> bool:
    """Segment-based glob: tests/ matches dir prefix, not substring."""
    if pattern.endswith("/"):
        return path.startswith(pattern) or f"/{pattern}" in path
    if fnmatch.fnmatch(path, pattern):
        return True
    return fnmatch.fnmatch(path.split("/")[-1], pattern)


def _match_paths(file_path: str, paths: list[str],
                 exclude_paths: list[str]) -> bool:
    norm = file_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    for excl in exclude_paths:
        if _glob_match(norm, excl):
            return False
    if not paths:
        return True
    return any(_glob_match(norm, p) for p in paths)


# ═══════════════════════════════════════════════════════════════
# BLOCK 3: Pattern + Structural checks
# ═══════════════════════════════════════════════════════════════

def _line_of_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, line: int) -> str:
    lines = content.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def check_pattern(inv: Invariant, compiled: dict[str, Any],
                  file_path: str, content: str) -> list[InvariantViolation]:
    if not _match_paths(file_path, inv.paths, inv.exclude_paths):
        return []
    violations = []
    for m in compiled["pattern"].finditer(content):
        line = _line_of_offset(content, m.start())
        violations.append(InvariantViolation(
            invariant_id=inv.id, invariant_type="pattern",
            file=file_path, line=line, severity=inv.severity,
            message=f"Invariant {inv.id} violated: {inv.name}",
            snippet=_line_snippet(content, line),
        ))
    return violations


def check_structural(inv: Invariant, compiled: dict[str, Any],
                     file_path: str, content: str) -> list[InvariantViolation]:
    if not _match_paths(file_path, inv.paths, inv.exclude_paths):
        return []
    lines = content.splitlines()
    violations = []
    for m in compiled["match"].finditer(content):
        line = _line_of_offset(content, m.start())
        start = max(0, line - 1 - compiled["lookbehind_lines"])
        end = min(len(lines), line + compiled["within_lines"])
        window = "\n".join(lines[start:end])
        if not compiled["require"].search(window):
            violations.append(InvariantViolation(
                invariant_id=inv.id, invariant_type="structural",
                file=file_path, line=line, severity=inv.severity,
                message=(f"Invariant {inv.id}: missing required pattern "
                         f"near line {line}: {inv.name}"),
                snippet=_line_snippet(content, line),
            ))
    return violations


# ═══════════════════════════════════════════════════════════════
# BLOCK 4: Dataflow check
# ═══════════════════════════════════════════════════════════════

def _split_functions(content: str) -> list[tuple[int, str]]:
    """Split file into function blocks with absolute offsets."""
    starts = [m.start() for m in FUNC_START.finditer(content)]
    if not starts:
        return [(0, content)]
    blocks: list[tuple[int, str]] = []
    if starts[0] > 0:
        blocks.append((0, content[:starts[0]]))
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(content)
        blocks.append((s, content[s:e]))
    return blocks


def check_dataflow(inv: Invariant, compiled: dict[str, Any],
                   file_path: str, content: str,
                   use_ast: bool = True) -> list[InvariantViolation]:
    if not _match_paths(file_path, inv.paths, inv.exclude_paths):
        return []

    # v0.21: AST path for Python
    if use_ast and file_path.endswith(".py"):
        try:
            from gsc_ast_dataflow import PythonTaintAnalyzer
        except ImportError:
            pass
        else:
            analyzer = PythonTaintAnalyzer(
                compiled["source"], compiled["sink"], compiled["sanitizer"])
            lines = analyzer.analyze(content)
            if lines is not None:
                return [InvariantViolation(
                    invariant_id=inv.id, invariant_type="dataflow",
                    file=file_path, line=ln, severity=inv.severity,
                    message=(f"Dataflow invariant {inv.id}: tainted value "
                             f"reaches sink: {inv.name}"),
                    snippet=_line_snippet(content, ln),
                ) for ln in lines]
            # None → AST failed to parse → fall through to regex heuristic

    # v0.20 regex heuristic (unchanged) — for non-Python + fallback
    violations = []
    for offset, block in _split_functions(content):
        src = compiled["source"].search(block)
        sink = compiled["sink"].search(block)
        if not src or not sink:
            continue
        if src.start() > sink.start():
            continue  # sink before source → not a data flow
        if compiled["sanitizer"].search(block):
            continue  # sanitizer present anywhere in function
        abs_sink_pos = offset + sink.start()
        line = _line_of_offset(content, abs_sink_pos)
        violations.append(InvariantViolation(
            invariant_id=inv.id, invariant_type="dataflow",
            file=file_path, line=line, severity=inv.severity,
            message=(f"Dataflow invariant {inv.id}: source reaches sink "
                     f"without sanitizer: {inv.name}"),
            snippet=_line_snippet(content, line),
        ))
    return violations


# ═══════════════════════════════════════════════════════════════
# BLOCK 5: Facade
# ═══════════════════════════════════════════════════════════════

class InvariantEngine:
    """Loads invariants, compiles regexes, verifies files."""

    def __init__(self, config_path: str, use_ast: bool = True):
        self.config_path = config_path
        self.use_ast = use_ast
        self.invariants = load_invariants(config_path)
        self.compiled: dict[str, dict[str, Any]] = {}
        for inv in self.invariants:
            if inv.enabled:
                self.compiled[inv.id] = compile_invariant(inv)

    def verify_file(self, file_path: str,
                    content: str) -> list[InvariantViolation]:
        violations: list[InvariantViolation] = []
        for inv in self.invariants:
            if not inv.enabled or inv.id not in self.compiled:
                continue
            compiled = self.compiled[inv.id]
            if inv.type == "pattern":
                violations += check_pattern(inv, compiled, file_path, content)
            elif inv.type == "structural":
                violations += check_structural(inv, compiled, file_path, content)
            elif inv.type == "dataflow":
                violations += check_dataflow(inv, compiled, file_path,
                                             content, use_ast=self.use_ast)
        return violations
