# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC LLM Verifier — deep analysis of findings using LLM context awareness.

Takes GSC findings, reads surrounding code, asks LLM to verify.
Filters out false positives that regex can't catch.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# ── LLM Client ───────────────────────────────────────────────────────────────

def _get_llm_client():
    """Get LLM client from Hermes environment (DeepSeek or configured provider)."""

    # Load from Hermes .env if not already in os.environ
    env_file = os.path.expanduser("~/.hermes/.env")
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key not in os.environ:
                        os.environ[key] = val

    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    if not api_key:
        # Try OpenRouter fallback
        api_key = os.getenv("OPENROUTER_API_KEY", "")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        model = "deepseek/deepseek-chat"

    if not api_key:
        return None, None, None

    return api_key, base_url, model


def _call_llm(api_key: str, base_url: str, model: str, prompt: str) -> str | None:
    """Call LLM for verification via the unified provider layer."""
    from gsc_llm_providers import llm_chat

    system = (
        "You are a security code reviewer. Analyze the finding and surrounding code. "
        "Reply with JSON only: {\"real_vuln\": true/false, "
        "\"confidence\": 0.0-1.0, \"reason\": \"brief explanation\"}"
    )
    return llm_chat(system, prompt, max_tokens=300, temperature=0.1)


# ── Code Context Extractor ──────────────────────────────────────────────────

def _extract_context(filepath: str, line_number: int, lines_before: int = 20, lines_after: int = 10) -> str:
    """Extract surrounding code context from a file."""
    try:
        with open(filepath, errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return ""

    start = max(0, line_number - lines_before - 1)
    end = min(len(lines), line_number + lines_after)

    result = []
    for i in range(start, end):
        marker = ">>>" if i == line_number - 1 else "   "
        result.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")

    return "\n".join(result)


# ── Main Verifier ────────────────────────────────────────────────────────────

def verify_finding(finding: dict, project_path: str = "") -> dict | None:
    """Verify a finding using LLM context analysis.

    Returns updated finding with llm_verified, llm_confidence, llm_reason fields.
    Returns None if LLM is unavailable.
    """
    api_key, base_url, model = _get_llm_client()
    if not api_key:
        return None

    filepath = finding.get("file_path", "")
    line_no = finding.get("line_number", 0)
    title = finding.get("title", "")
    rule_id = finding.get("rule_id", "")
    detail = finding.get("detail", "")

    # Extract code context — 30 lines before to catch auth callbacks
    code_context = _extract_context(filepath, line_no, lines_before=30, lines_after=10)

    prompt = f"""Analyze this security finding for a potential vulnerability.

Finding: {title} ({rule_id})
File: {Path(filepath).name}:{line_no}
Detail: {detail}

Surrounding code:
```
{code_context}
```

Is this a REAL vulnerability or a FALSE POSITIVE? Consider:
- Are inputs from user/request or internal/trusted?
- Is there authentication/authorization nearby?
- Is this test code, configuration, or production code?
- Are parameters properly escaped/parameterized?

Reply with JSON only: {{"real_vuln": true/false, "confidence": 0.0-1.0, "reason": "..."}}"""

    response = _call_llm(api_key, base_url, model, prompt)
    if not response:
        return None

    # Parse JSON response
    try:
        # Extract JSON from response (may have markdown wrapping)
        json_match = re.search(r'\{[^}]+\}', response)
        if json_match:
            result = json.loads(json_match.group())
            finding["llm_verified"] = result.get("real_vuln", False)
            finding["llm_confidence"] = result.get("confidence", 0.0)
            finding["llm_reason"] = result.get("reason", "")
            return finding
    except Exception:
        pass

    return None


def verify_findings(findings: list[dict], project_path: str = "",
                    min_severity: str = "CRITICAL", max_per_batch: int = 10) -> list[dict]:
    """Verify multiple findings, prioritizing by severity. Limits to max_per_batch for cost control."""
    verified = []
    count = 0

    # Sort: CRITICAL first, then HIGH
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.get("category", "LOW"), 3))

    for f in findings_sorted:
        if count >= max_per_batch:
            break
        sev = f.get("category", "LOW")
        if sev not in ("CRITICAL", "HIGH"):
            continue

        result = verify_finding(f, project_path)
        if result:
            verified.append(result)
            count += 1
        else:
            # LLM unavailable — keep as-is
            verified.append(f)

    # Add remaining non-verified findings as-is
    verified_ids = {id(v) for v in verified}
    for f in findings:
        if id(f) not in verified_ids:
            verified.append(f)

    return verified
