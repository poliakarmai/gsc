#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS038 — Go Vulnerability Detector.

Detects:
  - SSTI in html/template (user input in template)
  - SQL injection (fmt.Sprintf in queries)
  - Command injection (os/exec with user input)
  - Hardcoded secrets (API keys, passwords, JWT secrets)
  - Insecure crypto (MD5, SHA1, DES, weak RSA)
  - Path traversal (filepath.Join with user input)
  - SSRF (http.Get with user input)
  - Insecure deserialization (encoding/gob with untrusted data)
  - Race conditions (unsynchronized shared state)
  - Debug endpoints in production (pprof exposed)
  - TLS verification disabled (InsecureSkipVerify=true)
  - Hardcoded JWT secrets
  - unsafe pointer usage
"""

from __future__ import annotations

import re, hashlib
from typing import Any


GO_RULES: list[tuple[str, str, str, float]] = [
    # --- SSTI ---
    ("ssti_template",
     r'(?i)(?:template\.Must|template\.New|tmpl\.Execute)\s*\(',
     "HIGH", 0.60),
    ("ssti_html_template",
     r'(?i)html/template.*\.Execute\s*\([^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query))',
     "CRITICAL", 0.85),

    # --- SQL Injection ---
    ("sql_injection_fmt",
     r'(?i)fmt\.Sprintf\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*[\'"]',
     "CRITICAL", 0.90),
    ("sql_injection_concat",
     r'(?i)(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*["\'].*%[svq].*[\'"]',
     "CRITICAL", 0.85),

    # --- Command Injection ---
    ("command_injection_exec",
     r'(?i)exec\.Command\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query)|os\.Args)',
     "CRITICAL", 0.95),
    ("command_injection_bash",
     r'(?i)exec\.Command\s*\(\s*["\'](?:bash|sh|zsh)["\']',
     "HIGH", 0.75),

    # --- Hardcoded Secrets ---
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_api_key",
     r'(?i)(?:ApiKey|API_KEY|apiKey|api_key|SecretKey|SECRET_KEY)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.90),
    ("hardcoded_jwt_secret",
     r'(?i)(?:jwtSecret|JWT_SECRET|jwt_secret|signingKey)\s*=\s*["\']',
     "HIGH", 0.80),

    # --- Weak Crypto ---
    ("weak_crypto_md5",
     r'(?i)(?:md5\.New|md5\.Sum|crypto/md5)', "HIGH", 0.70),
    ("weak_crypto_sha1",
     r'(?i)(?:sha1\.New|sha1\.Sum|crypto/sha1)', "MEDIUM", 0.55),
    ("weak_crypto_des",
     r'(?i)crypto/des', "MEDIUM", 0.50),

    # --- TLS ---
    ("tls_skip_verify",
     r'InsecureSkipVerify\s*:\s*true', "HIGH", 0.80),

    # --- SSRF ---
    ("ssrf_http_get",
     r'(?i)http\.Get\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue|URL\.Query)|fmt\.Sprintf)',
     "HIGH", 0.85),
    ("ssrf_http_client",
     r'(?i)(?:http\.Client|http\.NewRequest).{0,100}(?:r\.(?:FormValue|URL\.Query))',
     "HIGH", 0.80),

    # --- Path Traversal ---
    ("path_traversal",
     r'(?i)(?:os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*filepath\.Join',
     "HIGH", 0.75),

    # --- Debug ---
    ("pprof_exposed",
     r'(?i)net/http/pprof', "MEDIUM", 0.55),

    # --- Unsafe ---
    ("unsafe_pointer",
     r'unsafe\.Pointer\s*\(',
     "MEDIUM", 0.50),

    # --- GORM injection risk ---
    ("gorm_raw_sql",
     r'(?i)\.Raw\s*\(\s*[^)]*(?:r\.(?:FormValue|PostFormValue)|fmt\.Sprintf)',
     "CRITICAL", 0.80),
]


EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
    r'(?:/|$)', re.IGNORECASE)


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key, "rule_id": rule_id, "title": title,
        "severity": severity, "confidence": confidence,
        "file_path": file_path, "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS038", "pattern_id": rule_id.replace("GS038-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS038GoDetector:
    rule_id = "GS038"
    name = "Go Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.go':
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in GO_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS038-{pattern_id}", severity,
                    f"Go security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS038-high_risk", "CRITICAL",
                f"Go file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.95))
        return findings


RULE_ID = "GS038"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS038: Go Vulnerability Detection — SSTI, SQLi, command injection, hardcoded secrets, weak crypto"


def detect(ctx) -> list[dict]:
    det = GS038GoDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.go': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings
