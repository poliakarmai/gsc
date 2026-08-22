#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS036 — Node.js/JavaScript Vulnerability Detector.

Detects:
  - Prototype pollution (__proto__, constructor.prototype assignments)
  - eval() with user input / dynamic strings
  - Command injection (child_process.exec with user input)
  - Path traversal (path.join with user-controlled segments)
  - SSRF via fetch/axios/request with user-provided URLs
  - NoSQL injection ($where, $regex with user input in MongoDB)
  - JWT none algorithm / hardcoded secret
  - dangerouslySetInnerHTML in JSX
  - Hardcoded secrets (API keys, tokens, passwords)
  - require() with dynamic paths
  - Insecure deserialization (node-serialize, js-yaml load)
  - ReDoS (regex with user input)
"""

from __future__ import annotations

import re
import hashlib
from typing import Any


NODE_RULES: list[tuple[str, str, str, float]] = [
    # --- Prototype Pollution ---
    ("prototype_pollution_proto",
     r'(?:obj|target|dest|data)\[["\']__proto__["\']\]\s*=',
     "CRITICAL", 0.95),
    ("prototype_pollution_constructor",
     r'(?:obj|target|dest|data)\.constructor\.prototype\s*=',
     "CRITICAL", 0.95),
    ("prototype_pollution_merge",
     r'(?i)(?:\.extend|\.merge|\.assign|Object\.assign)\s*\([^)]*req\.(?:body|query|params)',
     "CRITICAL", 0.90),

    # --- eval() injection ---
    ("eval_user_input",
     r'(?:eval|new\s+Function)\s*\(\s*(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params)|ctx\.request\.(?:body|query)|process\.argv|location\.(?:hash|search)|document\.cookie|URLSearchParams|localStorage\.\w+|window\.name|postMessage|fs\.(?:readFile|readFileSync))',
     "CRITICAL", 0.98),

    # --- Command Injection ---
    ("command_injection_exec",
     r'(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^)]*(?:req\.(?:body|query|params)|process\.argv)',
     "CRITICAL", 0.95),
    ("command_injection_shell",
     r'(?:exec|execSync)\s*\([^,]*,[^{]*\{[^}]*shell\s*:\s*true',
     "HIGH", 0.80),

    # --- Path Traversal ---
    ("path_traversal",
     r'path\.(?:join|resolve)\s*\([^)]*req\.(?:body|query|params)',
     "HIGH", 0.85),
    ("path_traversal_fs",
     r'(?:readFileSync|readFile|createReadStream|createWriteStream)\s*\(\s*[^)]*req\.',
     "HIGH", 0.80),

    # --- SSRF ---
    ("ssrf_fetch",
     r'(?:fetch|axios|request|got|superagent)\s*\(\s*req\.(?:body|query|params)',
     "HIGH", 0.85),
    ("ssrf_http",
     r'(?:http\.get|http\.request|https\.get|https\.request)\s*\(\s*req\.',
     "HIGH", 0.80),

    # --- NoSQL Injection ---
    ("nosql_injection_where",
     r'\$(?:where|regex|ne|gt|lt|in|nin)\s*:',
     "HIGH", 0.70),
    ("nosql_injection_user_input",
     r'(?:\.find|\.findOne|\.update|\.deleteOne)\s*\(\s*req\.(?:body|query)',
     "HIGH", 0.75),

    # --- JWT ---
    ("jwt_none_algorithm",
     r'(?i)algorithm\s*:\s*["\']none["\']',
     "CRITICAL", 0.95),
    ("jwt_hardcoded_secret",
     r'(?i)(?:jwt\.sign|jwt\.verify)\s*\([^)]*["\'][A-Za-z0-9_-]{20,}["\']',
     "HIGH", 0.80),

    # --- React XSS ---
    ("dangerously_set_html",
     r'dangerouslySetInnerHTML\s*=\s*\{',
     "MEDIUM", 0.60),

    # --- Hardcoded Secrets ---
    ("hardcoded_api_key",
     r'(?i)(?:apiKey|api_key|apiSecret|api_secret|secretKey|secret_key)\s*[:=]\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_token",
     r'(?i)(?:token|authToken|accessToken)\s*[:=]\s*["\'](?:ghp_|gho_|github_pat_|sk-)[A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.90),

    # --- Dynamic require ---
    ("require_user_input",
     r'require\s*\(\s*req\.(?:body|query|params)',
     "CRITICAL", 0.90),

    # --- Deserialization ---
    ("insecure_deserialization",
     r'(?i)(?:serialize\.unserialize|js-yaml\.load|yaml\.load)\s*\(',
     "HIGH", 0.75),

    # --- ReDoS ---
    ("redos",
     r'(?:\.test|\.match|\.exec|\.replace)\s*\(\s*new\s+RegExp\s*\(\s*',
     "LOW", 0.40),

    # --- npm pre/postinstall — supply chain ---
    ("npm_lifecycle_script",
     r'"(?:preinstall|postinstall|install)"\s*:\s*"(?:node|sh|bash|curl|wget)',
     "CRITICAL", 0.90),
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
        "metadata": {"detector": "GS036", "pattern_id": rule_id.replace("GS036-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS036NodeDetector:
    rule_id = "GS036"
    name = "Node.js Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext not in ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'):
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in NODE_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS036-{pattern_id}", severity,
                    f"Node.js security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        # Individual Node.js rules above carry exact locations; no count-derived
        # CRITICAL aggregate.
        return findings


RULE_ID = "GS036"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS036: Node.js Vulnerability Detection — prototype pollution, eval, command injection, SSRF, NoSQLi"


def detect(ctx) -> list[dict]:
    det = GS036NodeDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file(): continue
        ext = fp.suffix.lower()
        if ext not in ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'): continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings
