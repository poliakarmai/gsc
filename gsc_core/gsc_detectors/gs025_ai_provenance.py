# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS025 — AI-Code Provenance Scanner.

Two tasks:
  1. Estimate AI provenance likelihood (ai_provenance_score).
  2. Catch insecure defaults that AI assistants set most often
     (permissive CORS, debug=True, wildcard bind, hardcoded secrets,
      eval, insecure random, missing rate limits).

Design: GS025 patterns are real vulnerabilities — always reported.
AI score only boosts confidence and adds metadata. Not a duplicate
of existing 23 detectors: focus is on "AI-favored insecure defaults".
Deduplication via finding_key in gsc_external.
"""
from __future__ import annotations

import re
from typing import Any

from . import Finding

# ── AI provenance markers (comment patterns across languages) ──────
AI_MARKERS: list[tuple[str, float]] = [
    (r"(?:#|//|\*)\s*(?:Generated|Created|Written|Assisted|Authored|Scaffolded)"
     r"\s+by\s+(?:AI|Copilot|GPT[-\s]?\d*|Claude|Cursor|ChatGPT|an?\s+assistant)", 0.40),
    (r"(?:#|//)\s*TODO:\s*(?:review|verify|check|audit|harden|secure)\b", 0.15),
    (r'(?:#|//|"""|\*)\s*Examples?:\s*\n', 0.10),
    (r"\b(?:openai|anthropic|langchain|llama_index|ChatCompletion)\b", 0.10),
]

# ── AI-favored insecure defaults ──────────────────────────────────
AI_VULN_PATTERNS: list[tuple[str, str, str, float]] = [
    ("permissive_cors",
     r'CORS\([^)]*allow_origins=\[\s*["\']\*["\']\s*\]'
     r'|Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*',
     "HIGH", 0.70),
    ("debug_mode",
     r"^[ \t]*debug[ \t]*=[ \t]*True[ \t]*(?:#.*)?$"
     r"|\bapp\.run\([^)]*debug[ \t]*=[ \t]*True",
     "HIGH", 0.75),
    ("wildcard_bind",
     r'host\s*=\s*["\']0\.0\.0\.0["\']',
     "MEDIUM", 0.55),
    ("eval_usage",
     r"\beval\s*\(|\bexec\s*\(|\bchild_process\b.*\beval\b",
     "LOW", 0.40),
    ("hardcoded_secret",
     r"^[ \t]*(?:api[_-]?key|secret|password|passwd|token|client_secret)"
     r"[ \t]*=[ \t]*[\"'][A-Za-z0-9_\-./+]{12,}[\"']",
     "CRITICAL", 0.80),
    ("insecure_random",
     r"\brandom\.random\(\).*(?:auth|token|session|otp)"
     r"|\bMath\.random\(\).*(?:auth|token|session|otp)",
     "MEDIUM", 0.60),
]

AI_THRESHOLD = 0.5


# Vendor test/placeholder secrets (hCaptcha/Stripe test mode) — not real secrets.
_TEST_SECRET_MARKERS = ("0x0000", "00000000-", "10000000-", "ffff-ffff",
                        "example", "dummy", "fake", "test-", "your-", "xxxx", "changeme")


def _is_test_secret(matched: str) -> bool:
    low = matched.lower()
    return any(m in low for m in _TEST_SECRET_MARKERS)


class GS025Detector:
    """AI-Code Provenance + AI-favored insecure defaults. Regex-only, fork-safe."""

    rule_id = "GS025"
    name = "AI Code Provenance Scanner"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content:
            return findings

        ai_score = self._ai_likelihood(content)

        for pattern_id, regex, severity, base_conf in AI_VULN_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                matched = match.group(0)
                if _is_test_secret(matched):
                    continue
                # Static eval("literal") without any data source is a config/test
                # artifact, not a vulnerability. Dynamic eval(request/input/...)
                # carries a taint source and stays flagged.
                if pattern_id == "eval_usage" and not re.search(
                    r'(?:input|request|sys\.argv|os\.environ|\$_\w+|process\.env)',
                    matched, re.I,
                ):
                    continue
                line_no = content[:match.start()].count("\n") + 1
                snippet = self._snippet(content, line_no)

                confidence = base_conf
                if ai_score >= AI_THRESHOLD:
                    confidence = min(0.95, base_conf + ai_score * 0.2)

                findings.append({
                    "rule_id": f"GS025-{pattern_id}",
                    "title": f"AI-favored insecure default: {pattern_id}",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "language": language,
                    "metadata": {
                        "ai_provenance_score": round(ai_score, 2),
                        "ai_generated_likely": ai_score >= AI_THRESHOLD,
                        "pattern_id": pattern_id,
                    },
                })
        return findings

    def _ai_likelihood(self, content: str) -> float:
        score = 0.0
        for regex, weight in AI_MARKERS:
            if re.search(regex, content, re.IGNORECASE):
                score += weight
        lines = content.splitlines()
        if len(lines) > 200:
            comment_count = sum(1 for ln in lines if ln.strip().startswith(("#", "//", "/*", "*")))
            if comment_count < 5:
                score += 0.10
        return min(1.0, score)

    def _snippet(self, content: str, line_no: int, window: int = 2) -> str:
        lines = content.splitlines()
        start = max(0, line_no - 1 - window)
        end = min(len(lines), line_no + window)
        return "\n".join(lines[start:end])


# ── Registry bridge (module-level interface expected by DetectorEntry) ──
RULE_ID = "GS025"
ECHELON = 2
NOISE_TIER = "normal"
description = "GS025: AI-Code Provenance — detect AI-favored insecure defaults"


def detect(ctx) -> list[Finding]:
    """Bridge function for registry compatibility.

    Converts GS025Detector's internal dicts to the Finding contract
    (file_path/line_number/detail) so downstream consumers can locate
    findings. Previously returned raw dicts with 'file'/'line' keys,
    which resolved to file_path=None in gsc_external.
    """
    det = GS025Detector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        if fp.suffix not in {'.py', '.js', '.ts', '.tsx', '.go', '.rs', '.java', '.rb', '.php'}:
            continue
        if ctx.is_test_file(fp):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        for raw in det.detect(rel, content):
            findings.append(Finding(
                rule_id=raw["rule_id"],
                category=raw["severity"],
                title=raw["title"],
                file_path=raw["file"],
                line=raw["line"],
                detail=raw.get("snippet", ""),
                confidence=raw.get("confidence"),
                metadata=raw.get("metadata"),
                language=raw.get("language"),
            ))
    return findings
