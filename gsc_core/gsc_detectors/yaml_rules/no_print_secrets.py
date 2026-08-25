# YAML-B39DC08C — "print() with sensitive variable"
#
# AST-based detector. Replaces the naive regex that flagged ANY print(...)
# containing the substring password/secret/token/key/api_key — including
# diagnostic log literals like `print(f"[+] Scanning for secrets...")`.
#
# Logic: only flag when print() receives a VARIABLE / expression reference to
# a sensitive name, not a plain string literal.

import ast

from ..base import BaseDetector, make_finding

RULE_ID = "YAML-B39DC08C"
ECHELON = 2
NOISE_TIER = "custom"
description = """Printing potentially sensitive data to stdout"""

_SENSITIVE = ("password", "secret", "token", "api_key")


class PrintSecretDetector(BaseDetector):
    name = "no-print-secrets"
    rule_id = RULE_ID
    severity = "HIGH"
    confidence = 0.85
    languages = ("python",)
    # Marker: gsc_cli/main.py's check_plugin_detectors() treats detectors that
    # expose `_compiled` as file-based — detect(file_path, content) — vs ctx-based.
    # This AST detector is file-based, so expose the marker (empty: no regex).
    _compiled = ()

    def detect(self, file_path, content, language="auto"):
        if language not in ("python", "auto"):
            return []
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return []
        findings = []
        seen = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"):
                for arg in node.args:
                    name = self._sensitive_name(arg)
                    if name and name not in seen:
                        seen.add(name)
                        findings.append(make_finding(
                            rule_id=RULE_ID,
                            title="print() with sensitive variable",
                            severity=self.severity,
                            confidence=self.confidence,
                            file=file_path,
                            line=getattr(node, "lineno", 0),
                            snippet=name,
                            metadata={"sensitive_name": name}))
        return findings

    def _sensitive_name(self, arg):
        """Return the sensitive identifier name referenced by a print()
        argument, or None if it is a literal / non-sensitive expression."""
        if isinstance(arg, ast.Constant):
            return None  # string literal → log message, not a leak
        if isinstance(arg, ast.JoinedStr):
            # f-string: sensitive only if an interpolated expression names a secret
            for v in arg.values:
                if isinstance(v, ast.FormattedValue):
                    name = self._sensitive_name(v.value)
                    if name:
                        return name
            return None
        if isinstance(arg, ast.Name):
            return arg.id if self._is_sensitive(arg.id) else None
        if isinstance(arg, ast.Attribute):
            if self._is_sensitive(arg.attr):
                return arg.attr
            return self._sensitive_name(arg.value)
        if isinstance(arg, ast.Subscript):
            return self._sensitive_name(arg.value)
        if isinstance(arg, ast.Call):
            for a in arg.args:
                name = self._sensitive_name(a)
                if name:
                    return name
            return None
        return None

    @staticmethod
    def _is_sensitive(name):
        low = name.lower()
        return any(kw == low or kw in low.split("_") for kw in _SENSITIVE)


detector = PrintSecretDetector()


def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
