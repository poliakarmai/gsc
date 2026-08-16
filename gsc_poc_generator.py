# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

#!/usr/bin/env python3
"""
GSC PoC Auto-Generator v1.0 — class-based, redaction-audited.

Generates minimal exploits (curl/python/pytest) for confirmed findings.
Requires LLM → auto-disabled in fork-safe (--no-llm) mode.

Key safety: PoC MUST pass redaction audit before being included.
If PoC generation fails for finding with confidence < 0.85 →
confidence is penalized (powerful FP filter).

Usage:
  gsc poc list --report scan.json
  gsc poc show abc123 --report scan.json
  gsc external-scan ./repo --with-poc
"""

import json, re, sys, os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

POC_MIN_CONFIDENCE = 0.80
POC_WINDOW_LINES = 30
POC_FAIL_PENALTY = 0.90

# C1: PoC marker contract — exploited = exit 0 AND marker in stdout
SUCCESS_MARKERS = ("VULNERABLE", "EXPLOITED", "PWNED", "LEAKED", "SUCCESS", "BREACH")

REDACT_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "API key"),
    (r'AKIA[A-Z0-9]{16}', "AWS key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub token"),
    (r'-----BEGIN.*PRIVATE KEY-----', "Private key"),
    (r'password\s*[=:]\s*["\'][^\s"\']{8,}["\']', "Hardcoded credential"),
]

POC_RULES: dict[str, tuple[str, str]] = {
    "GS001": ("sql_injection", "curl"),
    "GS003": ("injection", "curl"),
    "GS007": ("idor", "curl"),
    "GS012": ("info_leak", "python"),
    "GS019": ("auth_bypass", "curl"),
    "GS022": ("ssrf", "curl"),
    "GS024": ("prompt_injection", "python"),
}


def _get_api_key() -> str:
    for p in [Path(os.path.expanduser("~/.hermes/.env")),
              Path(os.path.expanduser("~/.hermes/env"))]:
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def _call_llm(system: str, user: str, max_tokens: int = 800) -> Optional[str]:
    """Unified LLM call via gsc_llm_providers (DeepSeek/OpenRouter/OLLAMA/LM Studio)."""
    from gsc_llm_providers import llm_chat
    try:
        return llm_chat(system, user, max_tokens)
    except Exception as e:
        print(f"[PoC] LLM error: {e}", file=sys.stderr)
        return None


def _redact_audit(text: str) -> bool:
    """Return True if text is CLEAN (no secrets found)."""
    for pattern, label in REDACT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            print(f"[PoC] REDACT BLOCKED: {label}", file=sys.stderr)
            return False
    return True


def _syntax_ok(code: str, fmt: str) -> bool:
    if fmt == "python":
        try:
            compile(code, "<poc>", "exec")
            return True
        except SyntaxError:
            return False
    return bool(re.match(r"^(curl|http|pytest|python)\b", code.strip()))


@dataclass
class PoC:
    code: str
    impact: str
    fmt: str
    validated: bool = False


class PoCGenerator:
    def __init__(self, budget: int = 5):
        self.budget = budget

    def generate(self, finding: dict, source_code: str, feedback: Optional[str] = None) -> Optional[PoC]:
        if self.budget <= 0:
            return None
        if finding.get("confidence", 0) < POC_MIN_CONFIDENCE:
            return None

        rule_id = finding.get("rule_id", finding.get("pattern_title", ""))
        # Match rule_id prefixes (e.g. "GS025-permissive_cors" → check GS025)
        matched_kind = None
        matched_fmt = "curl"
        for prefix, (kind, fmt) in POC_RULES.items():
            if rule_id.startswith(prefix):
                matched_kind = kind
                matched_fmt = fmt
                break
        if not matched_kind:
            return None

        self.budget -= 1
        prompt = self._build_prompt(finding, source_code, matched_kind, matched_fmt, feedback)
        raw = _call_llm(
            "You are a security researcher generating minimal PoC exploits. "
            "Use ONLY placeholder values. Never include real secrets.",
            prompt, max_tokens=800
        )
        if not raw:
            return None

        poc = self._parse(raw, matched_fmt)
        if not poc:
            return None

        # CRITICAL: PoC must pass redaction audit
        if not _redact_audit(poc.code):
            return None

        poc.validated = _syntax_ok(poc.code, poc.fmt)
        return poc

    def _build_prompt(self, f: dict, code: str, kind: str, fmt: str, feedback: Optional[str] = None) -> str:
        line = f.get("line", f.get("line_number", 1))
        lines = code.splitlines()
        start = max(0, line - 1 - POC_WINDOW_LINES // 2)
        ctx = "\n".join(lines[start:start + POC_WINDOW_LINES])
        feedback_block = ""
        if feedback:
            feedback_block = (
                f"\n\nPrevious attempt FAILED in the sandbox. Improve the PoC based on this output:\n"
                f"```\n{feedback[:600]}\n```\n"
                f"Fix the error and keep the SAME EXPLOIT CONTRACT.\n"
            )
        return (
            f"Generate a minimal proof-of-concept exploit.\n\n"
            f"Rule: {f.get('rule_id', '?')} ({kind})\n"
            f"File: {f.get('file_path', '?')}:{line}\n"
            f"Code:\n{ctx}\n\n"
            f"Format: {fmt}\n"
            f"Use placeholder values ONLY. One request/script. No destructive actions.\n"
            f"EXPLOIT CONTRACT (required for Proof-of-Fix verification):\n"
            f"- On SUCCESS, print exactly one marker from: {', '.join(SUCCESS_MARKERS)} to stdout and exit 0.\n"
            f"- On FAILURE, print nothing special and exit non-zero. The marker is the ONLY trusted success signal.\n"
            f'If the target is safe, print "SAFE" and exit 1.\n'
            f'Output JSON: {{"code": "...", "impact": "one sentence"}}'
            + feedback_block
        )

    def _parse(self, raw: str, fmt: str) -> Optional[PoC]:
        try:
            m = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
            if not m:
                return None
            data = json.loads(m.group(0))
            return PoC(code=str(data["code"]), impact=str(data.get("impact", "")), fmt=fmt)
        except (json.JSONDecodeError, KeyError):
            return None


def attach_pocs(findings: list[dict], source_map: dict[str, str], budget: int = 5) -> list[dict]:
    """Generate PoCs for confirmed findings. Mutates findings in-place. Returns findings."""
    # Try deterministic PoCs first (no LLM, instant)
    from gsc_poc_deterministic import attach_deterministic_pocs
    attach_deterministic_pocs(findings)

    # Fall back to LLM for findings without deterministic PoC
    gen = PoCGenerator(budget=budget)
    for f in findings:
        if f.get("metadata", {}).get("poc"):
            continue  # already has deterministic PoC
        if f.get("confidence", 0) < POC_MIN_CONFIDENCE:
            continue
        src = source_map.get(f.get("file_path", f.get("file", "")))
        if not src:
            continue
        poc = gen.generate(f, src)
        if poc and poc.validated:
            f.setdefault("metadata", {})["poc"] = poc.code
            f["metadata"]["poc_impact"] = poc.impact
            f["metadata"]["poc_format"] = poc.fmt
        elif poc is None and f.get("confidence", 0) < 0.85:
            f["confidence"] = round(f["confidence"] * POC_FAIL_PENALTY, 2)

    # Rejudge PoC validation (multi-model consensus on exploit paths)
    try:
        from gsc_rejudge import validate_poc as rejudge_poc
        for f in findings:
            poc_code = f.get("metadata", {}).get("poc", "")
            if not poc_code or len(poc_code) < 20:
                continue
            rej = rejudge_poc(poc_code)
            f["metadata"]["rejudge_verdict"] = rej.get("verdict", "?")
            f["metadata"]["rejudge_confidence"] = rej.get("confidence", 0)
            f["metadata"]["rejudge_models_agree"] = rej.get("models_agree", False)
            
            verdict = rej.get("verdict", "")
            if verdict == "EXPLOITABLE":
                # All models agree: real vulnerability → boost confidence
                boost = 0.10 if rej.get("models_agree") else 0.05
                old_conf = f.get("confidence", 0.7)
                new_conf = min(0.95, old_conf + boost)
                f["confidence"] = round(new_conf, 2)
                f["metadata"]["poc_rejudge_boost"] = boost
            elif verdict == "FALSE_POSITIVE":
                # Models agree it's not exploitable → significant downgrade
                old_conf = f.get("confidence", 0.7)
                f["confidence"] = max(0.3, round(old_conf - 0.3, 2))
                f["metadata"]["poc_rejudge_penalty"] = 0.3
            # else NEEDS_REVIEW → no change, models disagree
    except Exception as e:
        pass  # Rejudge unavailable — proceed without

    # Watermark all PoCs (dual-use mitigation). Must never break scanning.
    try:
        from gsc_poc_watermark import watermark_findings
        watermark_findings(findings)
    except Exception:
        pass

    return findings
