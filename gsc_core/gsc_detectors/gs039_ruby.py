#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GS039 — Ruby Vulnerability Detector.

Detects:
  - YAML deserialization RCE (YAML.load/Psych.load with untrusted data)
  - Mass assignment (params.permit! / without strong params)
  - SSTI in ERB (ERB.new with user input)
  - Command injection (system/exec/backticks with user input)
  - SQL injection (string interpolation in ActiveRecord queries)
  - Hardcoded secrets (API keys, passwords, secret_key_base)
  - Open redirect (redirect_to with params)
  - Insecure deserialization (Marshal.load with untrusted data)
  - eval() with user input
  - SSRF (Net::HTTP/open-uri with user-provided URL)
  - Session fixation / cookie security
  - Dangerous send() with user-controlled method name
  - File disclosure (send_file with params[:file])
"""

from __future__ import annotations

import re, hashlib
from typing import Any


RUBY_RULES: list[tuple[str, str, str, float]] = [
    # --- YAML Deserialization ---
    ("yaml_load",
     r'(?i)YAML\.load\s*\(\s*(?!.*safe_load)',
     "CRITICAL", 0.90),
    ("yaml_unsafe",
     r'(?i)(?:YAML\.unsafe_load|Psych\.load|YAML\.load_file)\s*\(',
     "CRITICAL", 0.90),

    # --- Mass Assignment ---
    ("mass_assignment_permit_all",
     r'(?i)(?:\.permit!|params\.permit\s*\(\s*\)\s*(?!.*require))',
     "HIGH", 0.75),

    # --- SSTI (ERB) ---
    ("ssti_erb",
     r'(?i)ERB\.new\s*\(\s*[^)]*\#\{',
     "CRITICAL", 0.90),
    ("ssti_erb_user_input",
     r'(?i)ERB\.new\s*\(\s*params\[',
     "CRITICAL", 0.95),

    # --- Command Injection ---
    ("command_injection_system",
     r'(?i)(?:system|exec|spawn)\s*\(\s*[^)]*params\[',
     "CRITICAL", 0.95),
    ("command_injection_backtick",
     r'`[^`]*\#\{[^\}]*params\[[^\}]*\}[^`]*`',
     "CRITICAL", 0.90),
    ("command_injection_io",
     r'(?i)IO\.popen\s*\(\s*[^)]*params\[',
     "CRITICAL", 0.90),

    # --- SQL Injection ---
    ("sql_injection_where",
     r'(?i)\.where\s*\(\s*["\'].*\#\{',
     "CRITICAL", 0.85),
    ("sql_injection_find_by_sql",
     r'(?i)(?:find_by_sql|execute|select_all|select_rows)\s*\(\s*["\'].*\#\{',
     "CRITICAL", 0.90),

    # --- Hardcoded Secrets ---
    ("hardcoded_secret_key_base",
     r'(?i)secret_key_base\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.92),
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "CRITICAL", 0.85),
    ("hardcoded_api_key",
     r'(?i)(?:api_key|API_KEY|api_secret|API_SECRET)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "CRITICAL", 0.90),

    # --- Open Redirect ---
    ("open_redirect",
     r'(?i)redirect_to\s+params\[',
     "HIGH", 0.80),

    # --- Marshal Deserialization ---
    ("marshal_load",
     r'(?i)Marshal\.load\s*\(\s*(?:params|request|cookies)', "CRITICAL", 0.90),

    # --- eval ---
    ("eval_user_input",
     r'(?i)eval\s*\(\s*params\[', "CRITICAL", 0.95),

    # --- Dangerous send ---
    ("dangerous_send",
     r'(?i)\.send\s*\(\s*params\[', "HIGH", 0.75),

    # --- SSRF ---
    ("ssrf_open_uri",
     r'(?i)(?:open|URI\.open|open-uri)\s*\(\s*params\[', "HIGH", 0.80),
    ("ssrf_net_http",
     r'(?i)Net::HTTP\.(?:get|post|get_response)\s*\([^)]*params\[', "HIGH", 0.80),

    # --- File Disclosure ---
    ("file_disclosure_send_file",
     r'(?i)send_file\s+params\[', "HIGH", 0.80),

    # --- Session ---
    ("session_secret_weak",
     r'(?i)Rails\.application\.config\.secret_key_base', "LOW", 0.40),

    # --- Regex DoS ---
    ("regex_dos",
     r'(?i)\.(?:match|match\?|=~)\s*\/.*[\+\*]{2,}.*\/', "LOW", 0.40),
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
        "metadata": {"detector": "GS039", "pattern_id": rule_id.replace("GS039-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS039RubyDetector:
    rule_id = "GS039"
    name = "Ruby Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.rb':
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in RUBY_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS039-{pattern_id}", severity,
                    f"Ruby security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        # Individual Ruby rules above carry exact locations; no count-derived
        # CRITICAL aggregate.
        return findings


RULE_ID = "GS039"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS039: Ruby Vulnerability Detection — YAML RCE, mass assignment, SSTI, SQLi, Marshal"


def detect(ctx) -> list[dict]:
    det = GS039RubyDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.rb': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings
