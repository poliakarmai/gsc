#!/usr/bin/env python3
"""
GSC Security Invariant Engine v1.0.

Verifies user-declared invariants: rules that must hold across the codebase.
Unlike detectors (pattern matching), invariants check structural properties:
- "All /api/* routes require auth"
- "No secrets in non-test files"
- "DB queries must use parameterized statements"

Invariants are declared in .gsc-audit.yml under 'invariants:' key.
Violations are reported with HIGH confidence (deterministic checks).

Usage:
  python3 gsc_invariant_engine.py verify .             # check current dir
  python3 gsc_invariant_engine.py verify . --config .gsc-audit.yml
"""

import re, sys, yaml
from pathlib import Path
from dataclasses import dataclass, field

DEFAULT_CONFIG = ".gsc-audit.yml"


@dataclass
class InvariantViolation:
    invariant_id: str
    file: str
    line: int
    severity: str
    message: str
    snippet: str = ""


class InvariantEngine:
    """Verifies structural security invariants."""

    def __init__(self, config_path: str = DEFAULT_CONFIG):
        self.config_path = Path(config_path)
        self.invariants = []
        if self.config_path.exists():
            try:
                cfg = yaml.safe_load(self.config_path.read_text()) or {}
                self.invariants = cfg.get("invariants", [])
            except Exception:
                pass

    def verify_file(self, file_path: str, content: str) -> list[InvariantViolation]:
        violations = []
        for inv in self.invariants:
            if not inv.get("rule"):
                continue
            if inv.get("type") == "pattern":
                violations += self._check_pattern(inv, file_path, content)
            elif inv.get("type") == "structural":
                violations += self._check_structural(inv, file_path, content)
            elif inv.get("type") == "dataflow":
                violations += self._check_dataflow(inv, file_path, content)
        return violations

    def verify_dir(self, root: Path = Path(".")) -> list[InvariantViolation]:
        if isinstance(root, str):
            root = Path(root)
        all_violations = []
        for fp in root.rglob("*"):
            if not fp.is_file():
                continue
            if fp.suffix not in {'.py', '.js', '.ts', '.tsx', '.go', '.rs', '.java', '.rb', '.php'}:
                continue
            if any(d in fp.parts for d in {'node_modules', '.git', '__pycache__', 'venv', '.venv'}):
                continue
            try:
                content = fp.read_text(errors='replace')
            except Exception:
                continue
            violations = self.verify_file(str(fp.relative_to(root)), content)
            all_violations += violations
        return all_violations

    def _check_pattern(self, inv, file_path, content):
        """Pattern-based invariant: regex across file."""
        rule = inv.get("rule", {})
        pattern = rule.get("pattern", "")
        exclude = rule.get("exclude_paths", [])

        for excl in exclude:
            if excl.replace("*", "") in file_path:
                return []

        violations = []
        for m in re.finditer(pattern, content, re.MULTILINE):
            line_no = content[:m.start()].count('\n') + 1
            violations.append(InvariantViolation(
                invariant_id=inv.get("id", "INV-?"),
                file=file_path,
                line=line_no,
                severity=inv.get("violation_severity", "HIGH"),
                message=f"Invariant violated: {inv.get('name', 'unnamed')}",
                snippet=content.splitlines()[line_no - 1].strip()[:120],
            ))
        return violations

    def _check_structural(self, inv, file_path, content):
        """Structural invariant: for each match, check if required pattern is nearby."""
        rule = inv.get("rule", {})
        match_regex = rule.get("match", "")
        require_regex = rule.get("require", "")
        within_lines = rule.get("within_lines", 5)

        violations = []
        for m in re.finditer(match_regex, content, re.MULTILINE):
            line_no = content[:m.start()].count('\n') + 1
            lines = content.splitlines()
            start = max(0, line_no - 1)
            end = min(len(lines), line_no + within_lines)
            window = "\n".join(lines[start:end])

            if not re.search(require_regex, window):
                violations.append(InvariantViolation(
                    invariant_id=inv.get("id", "INV-?"),
                    file=file_path,
                    line=line_no,
                    severity=inv.get("violation_severity", "HIGH"),
                    message=f"Missing: {require_regex} near {match_regex}",
                    snippet=lines[line_no - 1].strip()[:120],
                ))
        return violations

    def _check_dataflow(self, inv, file_path, content):
        """Simplified dataflow: source+sink in same function, no sanitizer."""
        rule = inv.get("rule", {})
        source_pat = rule.get("source", "")
        sink_pat = rule.get("sink", "")
        sanitizer_pat = rule.get("must_pass_through", "")

        # Split into functions (heuristic by def/func/function)
        funcs = re.split(r'\n(?=(?:def|func|function|public|private|protected)\s)', content)

        violations = []
        for func in funcs:
            has_source = re.search(source_pat, func, re.IGNORECASE)
            has_sink = re.search(sink_pat, func, re.IGNORECASE)
            has_sanitizer = re.search(sanitizer_pat, func, re.IGNORECASE)

            if has_source and has_sink and not has_sanitizer:
                idx = content.find(func)
                line_no = content[:idx].count('\n') + 1 if idx >= 0 else 1
                violations.append(InvariantViolation(
                    invariant_id=inv.get("id", "INV-?"),
                    file=file_path,
                    line=line_no,
                    severity=inv.get("violation_severity", "HIGH"),
                    message=f"Dataflow: source→sink without sanitizer ({inv.get('name','')})",
                    snippet=func.strip()[:120],
                ))
        return violations


# ── CLI ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GSC Security Invariant Engine")
    p.add_argument("command", choices=["verify"], help="verify: check invariants")
    p.add_argument("target", nargs="?", default=".", help="Directory or file to check")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="Path to .gsc-audit.yml")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    args = p.parse_args()

    if not Path(args.config).exists():
        print(f"No config found at {args.config} — add 'invariants:' section to .gsc-audit.yml")
        sys.exit(0)

    engine = InvariantEngine(args.config)

    if len(engine.invariants) == 0:
        print("No invariants declared in config.")
        sys.exit(0)

    violations = engine.verify_dir(args.target)

    if args.json:
        import json
        print(json.dumps([{
            "invariant_id": v.invariant_id,
            "file": v.file,
            "line": v.line,
            "severity": v.severity,
            "message": v.message,
        } for v in violations], indent=2))
    else:
        if not violations:
            print(f"✅ All {len(engine.invariants)} invariants passed")
        else:
            for v in violations:
                print(f"❌ [{v.severity}] {v.invariant_id}: {v.message}")
                print(f"     {v.file}:{v.line}")
            print(f"\n📊 {len(violations)} violations across {len(engine.invariants)} invariants")
        sys.exit(1 if violations else 0)
