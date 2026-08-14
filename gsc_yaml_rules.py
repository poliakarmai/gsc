#!/usr/bin/env python3
"""GSC YAML Rule Compiler — Semgrep-совместимый DSL.

Позволяет писать кастомные правила на YAML и компилировать их
в GSC-детекторы без написания Python-кода.

Формат совместим с Semgrep rule schema v1.0.

Usage:
    python3 gsc_yaml_rules.py compile rules/my-rule.yml
    python3 gsc_yaml_rules.py compile rules/  # директория
    python3 gsc_yaml_rules.py registry update  # обновить из GitHub
"""

import hashlib, json, os, re, subprocess, sys, yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── YAML Schema ──────────────────────────────────────────────────────
#
# rules:
#   - id: my-rule-id
#     severity: CRITICAL|HIGH|MEDIUM|LOW
#     confidence: 0.85
#     languages: [python, javascript]
#     message: "Description of the vulnerability"
#     patterns:
#       - regex: "eval\\s*\\("
#         title: "eval() with user input"
#       - regex: "exec\\s*\\("
#         title: "exec() with user input"
#     fix: "Use safer alternative..."
#     references:
#       - "https://cwe.mitre.org/data/definitions/95.html"
#
# ИЛИ Semgrep-стиль:
#
# rules:
#   - id: my-rule-id
#     severity: ERROR       # → CRITICAL
#     message: "..."
#     pattern: "eval($X)"   # → один pattern
#     languages: [python]


SEVERITY_MAP = {
    "ERROR": "CRITICAL", "CRITICAL": "CRITICAL",
    "WARNING": "HIGH", "HIGH": "HIGH",
    "INFO": "MEDIUM", "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def semgrep_pattern_to_regex(pattern: str) -> str:
    """Translate Semgrep pattern syntax into a best-effort regex.

    Supported constructs:
      $X        → metavariable (identifier/expression)
      $...ARGS  → spread (zero+ arguments)
      ...       → ellipsis (zero+ of anything, incl. newlines)
      /regex/   → inline regex literal (pass-through)
      literals  → regex-escaped

    This is an APPROXIMATION: Semgrep matches on the AST, we match on source
    text. Good enough for the common community rules (function calls, imports,
    assignments), not for deep structural patterns. Precision-first: metavars
    match identifier-like text, not arbitrary expressions.
    """
    stripped = pattern.strip()
    # Inline regex literal: /.../ → pass-through
    if len(stripped) >= 2 and stripped.startswith("/") and stripped.endswith("/"):
        return stripped[1:-1]

    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        # spread: $...ARGS
        if c == "$" and pattern.startswith("$...", i):
            j = i + 4
            while j < n and (pattern[j].isalnum() or pattern[j] == "_"):
                j += 1
            out.append(r"[\s\S]*?")
            i = j
            continue
        # metavariable: $X
        if c == "$" and i + 1 < n and (pattern[i + 1].isalpha() or pattern[i + 1] == "_"):
            j = i + 1
            while j < n and (pattern[j].isalnum() or pattern[j] == "_"):
                j += 1
            out.append(r"[\w.]+")
            i = j
            continue
        # ellipsis: ...
        if pattern.startswith("...", i):
            out.append(r"[\s\S]*?")
            i += 3
            continue
        # literal
        out.append(re.escape(c))
        i += 1
    return "".join(out)


class YamlRule:
    """Compiled YAML rule ready for GSC."""
    def __init__(self, rule_dict: dict, source_file: str = ""):
        self.id = rule_dict["id"]
        self.severity = SEVERITY_MAP.get(
            rule_dict.get("severity", "MEDIUM").upper(), "MEDIUM")
        self.confidence = float(rule_dict.get("confidence", 0.80))
        self.message = rule_dict.get("message", "")
        self.languages = rule_dict.get("languages", ["python"])
        self.fix = rule_dict.get("fix", "")
        self.references = rule_dict.get("references", [])
        self.source_file = source_file

        # Parse patterns
        self.patterns: List[Tuple[str, str]] = []

        # Semgrep-style: single `pattern` (compiled to regex) or `pattern-regex` (raw)
        if "pattern" in rule_dict:
            self.patterns.append(
                (semgrep_pattern_to_regex(rule_dict["pattern"]), self.message))
        elif "pattern-regex" in rule_dict:
            self.patterns.append((rule_dict["pattern-regex"], self.message))

        # Semgrep-style: `pattern-either` — OR of alternatives
        for alt in rule_dict.get("pattern-either", []):
            if isinstance(alt, dict):
                if "pattern" in alt:
                    self.patterns.append(
                        (semgrep_pattern_to_regex(alt["pattern"]), self.message))
                elif "pattern-regex" in alt:
                    self.patterns.append((alt["pattern-regex"], self.message))
            elif isinstance(alt, str):
                self.patterns.append(
                    (semgrep_pattern_to_regex(alt), self.message))

        # GSC-style `patterns` list AND Semgrep AND-list (`patterns:`).
        for p in rule_dict.get("patterns", []):
            if isinstance(p, str):
                self.patterns.append((p, self.message))
            elif isinstance(p, dict):
                # Semgrep AND-operator: positive `pattern` → compile
                if "pattern" in p:
                    self.patterns.append(
                        (semgrep_pattern_to_regex(p["pattern"]), self.message))
                elif "pattern-regex" in p:
                    self.patterns.append((p["pattern-regex"], self.message))
                # GSC-style: `regex` + optional title
                elif "regex" in p:
                    title = p.get("title") or p.get("message") or self.message
                    self.patterns.append((p["regex"], title))

        # Validate
        if not self.patterns:
            raise ValueError(f"Rule '{self.id}': no patterns defined")
        for regex, _ in self.patterns:
            try:
                re.compile(regex)
            except re.error as e:
                raise ValueError(f"Rule '{self.id}': invalid regex '{regex[:50]}...': {e}")

    def to_detector_code(self) -> str:
        """Generate Python detector code from YAML rule."""
        rule_id = self._make_rule_id()
        patterns_repr = json.dumps(self.patterns, ensure_ascii=False)

        return f'''# Auto-generated from {self.source_file}
# Rule: {self.id} — {self.message[:80]}

from gsc_detectors.base import RegexDetector

RULE_ID = "{rule_id}"
ECHELON = 2
NOISE_TIER = "custom"
description = """{self.message}"""

patterns = {patterns_repr}

detector = RegexDetector(
    rule_id=RULE_ID,
    name="{self.id}",
    patterns=patterns,
    severity="{self.severity}",
    confidence={self.confidence},
    languages={tuple(self.languages)},
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
'''

    def _make_rule_id(self) -> str:
        """Generate stable GSC rule ID from YAML rule ID."""
        # Use hash for custom rules to avoid collisions with built-in GS000-GS035
        h = hashlib.sha256(f"yaml:{self.id}".encode()).hexdigest()[:8].upper()
        return f"YAML-{h}"


def compile_rules(path: str) -> List[YamlRule]:
    """Compile YAML rules from file or directory."""
    path = Path(path)
    rules = []

    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))

    for f in files:
        try:
            with open(f) as fh:
                data = yaml.safe_load(fh)
            if not data or "rules" not in data:
                continue
            for r in data["rules"]:
                try:
                    rule = YamlRule(r, str(f))
                    rules.append(rule)
                except ValueError as e:
                    print(f"⚠️  {e}", file=sys.stderr)
        except Exception as e:
            print(f"❌ {f}: {e}", file=sys.stderr)

    return rules


def compile_and_write(rules: List[YamlRule], output_dir: str):
    """Write compiled rules as Python detectors."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    for rule in rules:
        module_name = rule.id.replace("-", "_")
        py_file = output / f"{module_name}.py"
        code = rule.to_detector_code()
        py_file.write_text(code)
        print(f"✅ {rule.id} → {py_file} ({len(rule.patterns)} patterns)")

    # Write __init__.py to auto-load all
    module_names = []
    init_code = "# Auto-generated YAML rule loader\n"
    for rule in rules:
        module_name = rule.id.replace("-", "_")
        module_names.append(module_name)
        init_code += f"from . import {module_name}\n"
    init_code += f"\n__all__ = {module_names!r}\n"
    (output / "__init__.py").write_text(init_code)

    print(f"\n📦 {len(rules)} rules compiled to {output}/")


def create_sample_rule():
    """Create a sample YAML rule for demonstration."""
    return {
        "rules": [
            {
                "id": "no-eval-exec",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "languages": ["python", "javascript"],
                "message": "Use of eval() or exec() with dynamic input can lead to code injection",
                "patterns": [
                    {"regex": r"\beval\s*\(", "title": "eval() call — potential code injection"},
                    {"regex": r"\bexec\s*\(", "title": "exec() call — potential code injection"},
                    {"regex": r"\bcompile\s*\([^,]+,\s*['\"](eval|exec|single)['\"]", "title": "compile() in exec/eval mode"},
                ],
                "fix": "Use safer alternatives: ast.literal_eval() for data, or sandboxed execution",
                "references": [
                    "https://cwe.mitre.org/data/definitions/95.html",
                    "https://owasp.org/www-community/attacks/Code_Injection",
                ],
            },
            {
                "id": "no-debug-true",
                "severity": "MEDIUM",
                "confidence": 0.85,
                "languages": ["python"],
                "message": "DEBUG=True in production Django/Flask config",
                "patterns": [
                    {"regex": r"\bDEBUG\s*=\s*True\b", "title": "DEBUG=True — should be False in production"},
                ],
                "fix": "Set DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'",
            },
            {
                "id": "no-print-secrets",
                "severity": "HIGH",
                "confidence": 0.75,
                "languages": ["python"],
                "message": "Printing potentially sensitive data to stdout",
                "patterns": [
                    {"regex": r"\bprint\s*\(.*(?:password|secret|token|key|api_key)", "title": "print() with sensitive variable"},
                    {"regex": r"\blogging\.\w+\(.*(?:password|secret|token|key|api_key)", "title": "logging sensitive data"},
                ],
                "fix": "Never log secrets. Use redacted logging: log.debug('Auth with key: %s', key[:4] + '***')",
            },
        ]
    }


def update_registry(source: str, output_dir: str = "gsc_detectors/yaml_rules") -> int:
    """Import community rules from a Semgrep registry (directory or git URL).

    Clones a git URL into a temp dir if needed, compiles every rule our
    best-effort compiler supports (pattern / pattern-regex / pattern-either),
    and writes them as Python detectors. Rules using unsupported Semgrep
    operators (pattern-not, metavariable-regex, taint) are skipped.
    """
    import shutil
    import tempfile

    src = Path(source)
    tmp = None
    if source.startswith(("http://", "https://", "git@")):
        tmp = Path(tempfile.mkdtemp(prefix="gsc-registry-"))
        print(f"⬇️  Cloning {source} ...")
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none",
             source, str(tmp)], timeout=300)
        if r.returncode != 0:
            print("❌ clone failed")
            shutil.rmtree(tmp, ignore_errors=True)
            return 1
        src = tmp

    if not src.exists():
        print(f"❌ {source}: not found")
        return 1

    rules = compile_rules(str(src))
    if not rules:
        print("❌ No compilable rules found")
        return 1

    compile_and_write(rules, output_dir)
    print(f"📦 {len(rules)} community rules imported → {output_dir}/")

    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="GSC YAML Rule Compiler")
    sub = ap.add_subparsers(dest="command")

    compile_ap = sub.add_parser("compile", help="Compile YAML → Python detectors")
    compile_ap.add_argument("path", help="YAML file or directory")
    compile_ap.add_argument("-o", "--output", default="gsc_detectors/yaml_rules",
                           help="Output directory for compiled rules")

    init_ap = sub.add_parser("init", help="Create sample rule file")
    init_ap.add_argument("-o", "--output", default="gsc-rules/sample.yml")

    reg_ap = sub.add_parser("registry", help="Manage the rule registry")
    reg_sub = reg_ap.add_subparsers(dest="reg_command")
    reg_update = reg_sub.add_parser(
        "update", help="Import community rules from a directory or git URL")
    reg_update.add_argument("source", help="Path or git URL to a Semgrep rules registry")
    reg_update.add_argument("-o", "--output", default="gsc_detectors/yaml_rules")

    args = ap.parse_args()

    if args.command == "compile":
        rules = compile_rules(args.path)
        if not rules:
            print("❌ No rules compiled. Create with: gsc_yaml_rules.py init", file=sys.stderr)
            sys.exit(1)
        compile_and_write(rules, args.output)

    elif args.command == "init":
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(yaml.dump(create_sample_rule(), default_flow_style=False, allow_unicode=True))
        print(f"✅ Sample rules → {out}")
        print(f"   Compile: python3 gsc_yaml_rules.py compile {out}")

    elif args.command == "registry" and getattr(args, "reg_command", None) == "update":
        sys.exit(update_registry(args.source, args.output))

    else:
        ap.print_help()
