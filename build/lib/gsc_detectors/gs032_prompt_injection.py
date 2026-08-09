#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS032 — Prompt Injection Detector.

Detects malicious prompt injections targeting AI coding agents
(Claude Code, Codex, Gemini CLI) that read code/docs from repos.

Attack vectors (from "Claude Code and Gemini CLI Flaws" — Aug 2026):
  - GitHub issues/PRs with embedded system prompts
  - "Ignore previous instructions" override patterns
  - Simulated agent tool calls in code comments / markdown
  - Credential exfiltration prompts hidden in docs
  - Zero-width / invisible Unicode characters for hidden text
  - HTML/Markdown comments with injected instructions

File targets: .md, .txt, .py, .js, .ts, .yml, .yaml, .json, .html
"""

from __future__ import annotations

import re
import math
from typing import Any

# ── INJECTION PATTERNS ─────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[str, str, str, float, str | None]] = [
    # --- Override / jailbreak ---
    ("override_instruction",
     r'(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)'
     r'\s+(?:instructions?|prompts?|context|messages?|directives?)',
     "CRITICAL", 0.95, None),
    ("role_hijack",
     r'(?i)\byou\s+are\s+(?:now|no\s+longer)\b.{0,80}'
     r'(?:system|assistant|hacker|attacker|evil|malicious)',
     "CRITICAL", 0.90, None),
    ("system_prompt_override",
     r'(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)|'
     r'you\s+are\s+(?:now\s+)?(?:a\s+)?(?:hacker|attacker|evil|malicious|bot)|'
     r'your\s+(?:new\s+)?(?:goal|task|job|purpose)\s+is\s+(?:now\s+)?to|'
     r'from\s+now\s+on\s+you\s+(?:must|will|should|are))',
     "HIGH", 0.75, None),

    # --- Agent tool simulation ---
    ("fake_tool_call_execute",
     r'(?i)(?:execute_command|shell_exec|run_command|subprocess\.run|'
     r'os\.system|bash\s+-c)\s*[\(]\s*["\'].{3,}["\']',
     "HIGH", 0.70, None),
    ("fake_tool_call_file",
     r'(?i)(?:write_file|read_file|patch_file|append_file)\s*\(\s*["\']',
     "MEDIUM", 0.60, None),
    ("fake_tool_call_delegate",
     r'(?i)(?:delegate_task|spawn_agent|create_subagent)\s*\(\s*["\']',
     "HIGH", 0.70, None),
    ("fake_tool_call_terminal",
     r'(?i)(?:terminal|exec)\s*\(\s*(?:command|cmd)\s*=\s*["\']',
     "MEDIUM", 0.55, None),

    # --- Credential exfiltration ---
    ("exfil_curl",
     r'(?i)curl\s+.*(?:https?://|\.(?:com|net|io|dev|xyz|tk|ml|ga|cf)/)'
     r'.{0,100}(?:\$\(|`|&&|;|\|)',
     "CRITICAL", 0.80, None),
    ("exfil_env_send",
     r'(?i)(?:cat|echo|export|printenv|env\s*\|\s*grep)'
     r'\s+.*(?:\.env|secrets?|token|api[_-]?key|credential)'
     r'.{0,60}(?:\||>|curl|wget|nc\s|ncat|socat|telnet)',
     "CRITICAL", 0.85, None),
    ("exfil_git_clone_malicious",
     r'(?i)git\s+clone\s+(?:https?://|git@)'
     r'(?!github\.com/[^/]+/[^/]+\.git\b)',
     "MEDIUM", 0.50, None),
    ("exfil_base64_payload",
     r'(?i)(?:echo|printf)\s+[\'"]?(?:[A-Za-z0-9+/]{40,}={0,2})[\'"]?\s*\|\s*base64\s+-d',
     "HIGH", 0.75, None),

    # --- Hidden text vectors ---
    ("zero_width_chars",
     r'[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\uFEFF]{3,}',
     "MEDIUM", 0.85, None),
    ("hidden_html_comment",
     r'<!--.{20,}(?:(?:ignore|override)\s+(?:previous|all|instructions?|'
     r'prompts?)|(?:execute|run)\s+(?:command|shell)|'
     r'(?:curl|wget)\s+(?:https?://)|'
     r'(?:api[_.-]?key|token|secret|credential)\s*[=:]|'
     r'<system>|</system>).{10,}-->',
     "HIGH", 0.70, None),
    ("markdown_link_injection",
     r'\[.{0,5}\]\((?:javascript:|data:text/html|vbscript:)',
     "HIGH", 0.80, None),
    ("markdown_image_exfil",
     r'!\[.{0,20}\]\(https?://(?!github\.com|img\.shields\.io|'
     r'raw\.githubusercontent\.com)[^/\s]+\.[a-z]{2,}/[^)]+\)',
     "LOW", 0.30, None),

    # --- AI agent specific (code-only: skip in .py/.js — legit API usage) ---
    ("anthropic_system_injection",
     r'(?i)(?:<system>|</system>|<instructions>|</instructions>|'
     r'<anthropic_function_calls>|</anthropic_function_calls>|'
     r'<claude_system>|</claude_system>)',
     "CRITICAL", 0.90, {'.md', '.txt', '.html', '.htm', '.yml', '.yaml'}),
    ("openai_tool_injection",
     r'(?i)(?:"role":\s*"system".{0,30}"content":\s*"(?:ignore|forget|you are now|'
     r'from now on|execute|hack|steal|exfil)|'
     r'"function_call".{0,50}(?:execute|shell|bash|curl|wget))',
     "HIGH", 0.70, {'.md', '.txt', '.html', '.htm'}),
    ("codex_specific",
     r'(?i)(?:codex\s+execute|codex\s+terminal|codex\s+shell|'
     r'codex\s+run\s+command)',
     "HIGH", 0.70, None),
    ("gemini_cli_specific",
     r'(?i)(?:gemini\s+(?:run|exec|shell|bash|terminal)\b)',
     "MEDIUM", 0.60, None),
]

# ── EXCLUDE PATHS ─────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build|'
    r'\.next|\.nuxt|coverage|\.nyc_output|'
    r'graphify-out|openwiki|\.claude/commands)'  # generated + AI config
    r'(?:/|$)', re.IGNORECASE)

EXCLUDE_EXTENSIONS = {
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.webm', '.ogg',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.lock', '.pyc', '.pyo', '.class', '.so', '.dll',
}

TARGET_EXTENSIONS = {
    '.md', '.txt', '.rst', '.adoc',    # documentation
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.rb',  # code
    '.yml', '.yaml',                    # configs (no .json — mostly generated data)
    '.html', '.htm',                    # web
}

# ── ENTROPY CHECK ──────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── DETECTOR ───────────────────────────────────────────────────────────

class GS032PromptInjectionDetector:
    rule_id = "GS032"
    name = "Prompt Injection Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content:
            return findings

        # Skip the detector itself (contains its own patterns in docstrings/regexes)
        if 'gs032_prompt_injection.py' in file_path:
            return findings

        # Skip excluded paths
        if EXCLUDE_PATH_RE.search(file_path):
            return findings

        # Only scan target extensions
        ext = file_path[file_path.rfind('.'):] if '.' in file_path else ''
        if ext.lower() not in TARGET_EXTENSIONS:
            return findings

        # Skip binary-looking content (high null byte ratio or mostly non-printable)
        if self._looks_binary(content):
            return findings

        # Check for "suspicious density" — many injection patterns = higher risk
        pattern_hits = 0

        for entry in INJECTION_PATTERNS:
            if len(entry) == 5:
                pattern_id, regex, severity, base_conf, file_filter = entry
            else:
                pattern_id, regex, severity, base_conf = entry
                file_filter = None

            # Check file extension filter
            if file_filter is not None:
                ext_lower = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''
                if ext_lower not in file_filter:
                    continue

            matches = list(re.finditer(regex, content, re.MULTILINE))
            if not matches:
                continue

            pattern_hits += len(matches)

            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                snippet = self._snippet(content, line_no)
                matched_text = match.group(0)

                # Boost confidence for high-entropy hidden strings
                confidence = base_conf
                if pattern_id == "zero_width_chars":
                    confidence = 0.95
                elif pattern_id in ("exfil_base64_payload",):
                    if _shannon_entropy(matched_text) > 4.5:
                        confidence = min(0.95, base_conf + 0.1)

                findings.append({
                    "rule_id": f"GS032-{pattern_id}",
                    "title": f"Potential prompt injection: {pattern_id}",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "file_path": file_path,
                    "line_number": line_no,
                    "detail": f"Matched pattern '{pattern_id}' at line {line_no}",
                    "snippet": snippet,
                    "language": language,
                    "metadata": {
                        "detector": "GS032",
                        "pattern_id": pattern_id,
                        "matched_text": matched_text[:120],
                        "suspicious_density": pattern_hits >= 3,
                    },
                })

        # Flag entire file if too many patterns (likely an attack doc)
        if pattern_hits >= 5:
            findings.append({
                "rule_id": "GS032-high_density",
                "title": "High density of prompt injection patterns — likely attack document",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "file_path": file_path,
                "line_number": 1,
                "detail": f"File contains {pattern_hits} injection patterns — treat as hostile",
                "snippet": self._snippet(content, 1),
                "language": language,
                "metadata": {
                    "detector": "GS032",
                    "pattern_id": "high_density",
                    "total_pattern_hits": pattern_hits,
                },
            })

        return findings

    def _looks_binary(self, content: str) -> bool:
        """Check if content appears to be binary data."""
        if not content:
            return False
        sample = content[:4096]
        non_printable = sum(1 for ch in sample if ord(ch) < 9 and ch != '\n' and ch != '\r' and ch != '\t')
        return (non_printable / max(len(sample), 1)) > 0.3

    def _snippet(self, content: str, line_no: int, context: int = 2) -> str:
        """Extract a few lines around the match for context."""
        lines = content.splitlines()
        start = max(0, line_no - 1 - context)
        end = min(len(lines), line_no + context)
        return "\n".join(lines[start:end])


# ── Registry bridge ────────────────────────────────────────────────────

RULE_ID = "GS032"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS032: Prompt Injection — detect AI agent hijack via code/docs/issues"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility — uses AuditContext."""
    from pathlib import Path
    det = GS032PromptInjectionDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext not in TARGET_EXTENSIONS:
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings
