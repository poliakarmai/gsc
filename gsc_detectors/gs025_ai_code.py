"""
GS025 — AI-Code Provenance Scanner.

Detects AI-generated code patterns and applies specialized security rules:
- AI code markers (Copilot/GPT/Claude comments)
- AI-specific vulnerability patterns (debug=True, CORS *, eval, hardcoded secrets)
- Overly permissive defaults common in AI training data (md5, pickle, 0.0.0.0)
- Missing error handling (bare except, no try/catch around external calls)

ECHELON: 2 (broader patterns, AI-likelihood scoring)
"""

from __future__ import annotations

import re
from pathlib import Path

from gsc_detectors import AuditContext, Finding

RULE_ID = "GS025"
ECHELON = 2
NOISE_TIER = "normal"
description = "AI-Code Provenance — detect AI-generated code with insecure defaults (Copilot/Cursor/GPT patterns)"

# ── AI markers: comments/patterns typical of AI-generated code ──────────
AI_MARKERS: list[tuple[str, str, float]] = [
    # Explicit AI markers (high confidence)
    (r'#\s*(?:Generated|Created|Written|Produced)\s+by\s+(?:AI|Copilot|GPT|Claude|Cursor|Codex|Qwen)', "Explicit AI-generated code marker", 0.95),
    (r'#\s*(?:copilot|gpt|claude|ai)\s*[:\-]', "AI assistant marker in comment", 0.85),
    # AI-typical TODO patterns
    (r'#\s*TODO:\s*(?:review|verify|check|validate)\s+(?:this|security|auth|input)', "AI-generated TODO requiring review", 0.6),
    # AI integration code
    (r'import\s+(?:openai|anthropic|langchain|llamaindex)', "AI library integration", 0.7),
    (r'client\s*=\s*(?:OpenAI|Anthropic|ChatOpenAI)', "Direct AI client usage — review prompt injection risk", 0.75),
]

# ── AI-specific vulnerability patterns ──────────────────────────────────
AI_VULN_PATTERNS: list[tuple[str, str, str, str]] = [
    # Insecure defaults common in AI training data
    ("permissive_cors", r'CORS\s*\(\s*allow_origins\s*=\s*\[[\"\']\*[\"\']\]|Access-Control-Allow-Origin\s*:\s*\*', "Permissive CORS (*) — typical AI default", "HIGH"),
    ("debug_enabled", r'\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b', "Debug mode enabled — AI-generated default", "HIGH"),
    ("no_rate_limit", r'@(?:app\.route|router\.(?:get|post|put|delete|patch))\s*\(\s*[\"\']/(?!.*\brate_limit\b)', "API route without rate limiting — AI often omits", "MEDIUM"),
    ("eval_exec_usage", r'\beval\s*\(|\bexec\s*\(\s*[^)]', "eval()/exec() — AI often uses for 'simplicity'", "CRITICAL"),
    ("wildcard_bind", r'host\s*=\s*[\"\']0\.0\.0\.0[\"\']', "Binding to 0.0.0.0 — AI training default", "HIGH"),
    ("weak_crypto_default", r'\bhashlib\.md5\b|\bcrypto\.createHash\s*\(\s*[\"\']md5[\"\']|\bMessageDigest\.getInstance\s*\(\s*[\"\']MD5[\"\']', "Weak crypto (MD5) — AI copies from old examples", "CRITICAL"),
    ("unsafe_pickle", r'\bpickle\.(?:loads?|dump)\s*\(', "Unsafe pickle deserialization — AI training data artifact", "CRITICAL"),
    ("unsafe_yaml", r'\byaml\.load\s*\(\s*(?!.*Loader=yaml\.(?:Safe|Base)Loader)', "Unsafe yaml.load() — AI often uses default loader", "CRITICAL"),
    ("no_error_handling", r'(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen)\s*\([^)]*\n(?!\s*(?:except|try))', "HTTP call without error handling — AI often omits try/catch", "MEDIUM"),
    ("bare_except", r'except\s*:', "Bare except — AI-generated code often catches everything", "MEDIUM"),
    ("hardcoded_secret_ai", r'(?:api_key|secret|password|token|key)\s*=\s*[\"\'](?:sk-|ghp_|AKIA|AIza|ya29|eyJ)[^\"]{20,}[\"\']', "Hardcoded credential (API key pattern) — common in AI examples", "CRITICAL"),
    # Insecure defaults for web frameworks
    ("flask_debug_default", r'app\.run\s*\(.*debug\s*=\s*True', "Flask debug mode in production — AI code default", "CRITICAL"),
    ("django_debug", r'DEBUG\s*=\s*True', "Django DEBUG=True — AI often leaves this on", "HIGH"),
    # Prompt injection risk
    ("unsanitized_llm_input", r'(?:completion|chat\.completions)\.create\s*\(\s*.*\{.*(?:user_input|query|prompt|message)', "Unsanitized user input passed to LLM — prompt injection risk", "CRITICAL"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.rb', '.go', '.java'}
EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__', '.venv', 'venv'}
EXCLUDE_PATTERNS = ['test_', 'test/', '.test.', '.spec.', '__test__', 'conftest']


def _collect_files(root: Path) -> list[Path]:
    files = []
    for fp in root.rglob("*"):
        if fp.is_file() and fp.suffix in FILE_EXTENSIONS:
            parts = fp.parts
            if any(d in EXCLUDE_DIRS for d in parts):
                continue
            if any(p in fp.name for p in EXCLUDE_PATTERNS):
                continue
            files.append(fp)
    return files


def _compute_ai_score(content: str) -> tuple[float, list[str]]:
    """Compute AI provenance likelihood score (0.0–1.0)."""
    score = 0.0
    markers_found = []
    for pattern, desc, weight in AI_MARKERS:
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            score = max(score, weight)
            markers_found.append(desc)
    return score, markers_found


def _ai_boost(ai_score: float, base_confidence: float) -> float:
    """Boost confidence for AI-generated code — it's more likely to have issues."""
    if ai_score >= 0.85:
        return min(0.95, base_confidence + 0.15)
    elif ai_score >= 0.6:
        return min(0.90, base_confidence + 0.10)
    return base_confidence


def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []

    for file_path in _collect_files(ctx.path):
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue

        # Check if file has AI markers
        ai_score, ai_markers = _compute_ai_score(content)
        rel_path = str(file_path.relative_to(ctx.path))

        # Check for suppressed lines
        suppressed = set()
        for i, line in enumerate(content.split('\n'), 1):
            if 'gsc:ignore' in line or 'nosec' in line:
                suppressed.add(i)

        # Report AI markers as INFO findings
        for marker in ai_markers:
            findings.append(Finding(
                rule_id=RULE_ID,
                severity="INFO",
                title=f"AI-generated code detected: {marker}",
                file_path=rel_path,
                line=1,
                detail=f"AI provenance score: {ai_score:.0%}",
                noise_tier="normal",
                echelon=ECHELON,
                source=f"multi-lang:python",
                pattern_title=f"{RULE_ID} (ai-marker)",
            ))

        # Scan for AI-specific vulnerability patterns
        for pattern_id, regex, message, severity in AI_VULN_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if line_num in suppressed:
                    continue

                line_content = content.split('\n')[line_num - 1].strip()
                base_confidence = 0.7 if ai_score >= 0.6 else 0.5
                confidence = _ai_boost(ai_score, base_confidence)

                findings.append(Finding(
                    rule_id=f"{RULE_ID}-{pattern_id}",
                    severity=severity,
                    title=f"[AI-Code] {message}",
                    file_path=rel_path,
                    line=line_num,
                    detail=f"{line_content[:120]} | ai_provenance: {ai_score:.0%}",
                    noise_tier="normal",
                    echelon=ECHELON,
                    source="multi-lang:ai-code",
                    pattern_title=f"{RULE_ID} ({pattern_id})",
                ))

    return findings
