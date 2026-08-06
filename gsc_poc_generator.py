# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

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
    import urllib.request as _req
    key = _get_api_key()
    if not key:
        return None
    body = json.dumps({
        "model": "deepseek-chat",
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    try:
        resp = json.loads(_req.urlopen(_req.Request(
            "https://api.deepseek.com/v1/chat/completions",
            data=body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        ), timeout=30).read())
        return resp["choices"][0]["message"]["content"]
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

    def generate(self, finding: dict, source_code: str) -> Optional[PoC]:
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
        prompt = self._build_prompt(finding, source_code, matched_kind, matched_fmt)
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

    def _build_prompt(self, f: dict, code: str, kind: str, fmt: str) -> str:
        line = f.get("line", f.get("line_number", 1))
        lines = code.splitlines()
        start = max(0, line - 1 - POC_WINDOW_LINES // 2)
        ctx = "\n".join(lines[start:start + POC_WINDOW_LINES])
        return (
            f"Generate a minimal proof-of-concept exploit.\n\n"
            f"Rule: {f.get('rule_id', '?')} ({kind})\n"
            f"File: {f.get('file_path', '?')}:{line}\n"
            f"Code:\n{ctx}\n\n"
            f"Format: {fmt}\n"
            f"Use placeholder values ONLY. One request/script. No destructive actions.\n"
            f'CRITICAL: If the exploit succeeds, print exactly "VULNERABLE" on its own line before exiting with code 0.\n'
            f'If the target is safe, print "SAFE" and exit 1.\n'
            f'Output JSON: {{"code": "...", "impact": "one sentence"}}'
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
    gen = PoCGenerator(budget=budget)
    for f in findings:
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
            f.setdefault("metadata", {})["poc_failed"] = True
    return findings
