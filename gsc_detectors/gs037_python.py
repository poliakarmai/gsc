#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""
GS037 — Python Vulnerability Detector.

Detects:
  - pickle RCE (pickle.loads with untrusted data)
  - eval()/exec() with user input
  - SSTI in Jinja2 (render_template_string with user input)
  - Command injection (os.system/subprocess with user input)
  - YAML deserialization (yaml.load with unsafe Loader)
  - Hardcoded secrets (API keys, passwords, tokens)
  - Path traversal (open/os.path.join with user input)
  - SQL injection (string formatting in queries)
  - Insecure tempfile (tempfile.mktemp)
  - Debug mode enabled in production (DEBUG=True, Flask)
  - Insecure deserialization (marshal.loads with untrusted data)
  - XML external entity (XXE) in lxml/etree
"""

from __future__ import annotations

import re, hashlib
from typing import Any


PYTHON_RULES: list[tuple[str, str, str, float]] = [
    # --- pickle RCE ---
    ("pickle_rce",
     r'(?i)pickle\.(?:loads?|load)\s*\(\s*(?:request\.(?:data|form|args|json)|input\b)',
     "CRITICAL", 0.98),

    # --- eval/exec ---
    ("eval_user_input",
     r'(?i)eval\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()',
     "CRITICAL", 0.95),
    ("exec_user_input",
     r'(?i)exec\s*\(\s*(?:request\.(?:args|form|json|data)|input\s*\()',
     "CRITICAL", 0.95),

    # --- SSTI (Jinja2) ---
    ("ssti_render_template_string",
     r'(?i)render_template_string\s*\(\s*(?:request\.(?:args|form|json|data)|f["\'])',
     "CRITICAL", 0.90),
    ("ssti_format_string",
     r'(?i)\.format\s*\(.*request\.(?:args|form|json|data)',
     "HIGH", 0.70),

    # --- Command Injection ---
    ("command_injection_os",
     r'(?i)os\.(?:system|popen)\s*\(\s*(?:request\.(?:args|form|json|data)|f["\'])',
     "CRITICAL", 0.95),
    ("command_injection_subprocess",
     r'(?i)subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*(?:request\.|input\s*\()',
     "CRITICAL", 0.95),
    ("command_injection_shell_true",
     r'(?i)subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
     "HIGH", 0.80),

    # --- YAML Deserialization ---
    ("yaml_unsafe_load",
     r'(?i)yaml\.load\s*\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?(?:Safe|Base)Loader)',
     "HIGH", 0.80),
    ("yaml_full_load",
     r'(?i)yaml\.(?:full_load|unsafe_load|load_all)\s*\(',
     "CRITICAL", 0.85),

    # --- Hardcoded Secrets ---
    ("hardcoded_password",
     r'(?i)(?:password|passwd|pass|pwd|secret)\s*[:=]\s*["\'][^"\']{3,}["\']',
     "HIGH", 0.70),
    ("hardcoded_api_key",
     r'(?i)(?:API_KEY|api_key|api_key|SECRET_KEY)\s*=\s*["\'][A-Za-z0-9_-]{16,}["\']',
     "HIGH", 0.70),
    ("hardcoded_token",
     r'(?i)(?:token|auth_token|access_token)\s*=\s*["\'](?:sk-|ghp_|gho_)[A-Za-z0-9]{20,}["\']',
     "CRITICAL", 0.92),

    # --- Path Traversal ---
    ("path_traversal_open",
     r'(?i)(?:open|file)\s*\(\s*(?:os\.path\.join|f["\']).*(?:request\.|input)', "HIGH", 0.80),
    ("path_traversal_join",
     r'(?i)os\.path\.join\s*\([^)]*(?:filename|file_name|file_path|path)\b', "HIGH", 0.70),
    ("path_traversal_send_file",
     r'(?i)send_file\s*\(\s*[a-zA-Z_]\w*\s*\)', "HIGH", 0.65),

    # --- SQL Injection ---
    ("sql_injection_format",
     r'(?i)(?:\.execute|\.executemany)\s*\(\s*f["\'].*(?:request\.|input)', "CRITICAL", 0.90),
    ("sql_injection_percent",
     r'(?i)(?:\.execute|cursor\.execute)\s*\(\s*["\'].*%\s*(?:request\.|input\b)', "CRITICAL", 0.85),

    # --- Insecure Temp ---
    ("insecure_tempfile",
     r'tempfile\.mktemp\s*\(', "MEDIUM", 0.60),

    # --- Debug Mode ---
    ("debug_true",
     r'(?i)(?:DEBUG|debug)\s*=\s*True', "MEDIUM", 0.55),

    # --- XXE ---
    ("xxe_lxml",
     r'(?i)(?:etree\.parse|etree\.fromstring|etree\.XML)\s*\(', "HIGH", 0.60),
    ("xxe_sax",
     r'(?i)feature_external_(?:ges|entities)\s*[,\s]+True', "HIGH", 0.85),

    # --- marshal RCE ---
    ("marshal_rce",
     r'(?i)marshal\.loads?\s*\(\s*(?:request\.|input)', "CRITICAL", 0.91),
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
        "severity": severity, "category": severity, "confidence": confidence,
        "file_path": file_path, "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS037", "pattern_id": rule_id.replace("GS037-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


class GS037PythonDetector:
    rule_id = "GS037"
    name = "Python Vulnerability Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
        if ext != '.py':
            return findings
        hits = 0
        for pattern_id, regex, severity, base_conf in PYTHON_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(f"GS037-{pattern_id}", severity,
                    f"Python security: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))
                hits += 1
        if hits >= 5:
            findings.append(_finding("GS037-high_risk", "CRITICAL",
                f"Python file has {hits} security issues",
                file_path, 1, f"({hits} patterns)", 0.95))
        return findings


RULE_ID = "GS037"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS037: Python Vulnerability Detection — pickle, eval, SSTI, command injection, deserialization"


def detect(ctx) -> list[dict]:
    det = GS037PythonDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file() or fp.suffix != '.py': continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel): continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception: continue
        findings.extend(det.detect(rel, content))
    return findings
