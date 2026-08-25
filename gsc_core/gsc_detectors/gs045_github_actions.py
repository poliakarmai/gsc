#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""GS045 — GitHub Actions CI/CD Security Audit (v1.0).

Complements GS033 (CI/CD anti-patterns) with workflow-level checks GS033 misses:
  - Missing ``permissions:`` block (least-privilege — default is write-all)
  - Hardcoded secrets in ``env:`` (literal values, not ``${{ secrets.* }}``)
  - ``pull_request_target`` + checkout of untrusted fork head (RCE via fork)
  - ``workflow_run`` + checkout without ref pinning (runs on default branch)
"""
from __future__ import annotations

import re
import hashlib
from typing import Any

# ── PATTERNS ──────────────────────────────────────────────────────────

GHA_PATTERNS: list[tuple[str, str, str, float]] = [
    # pull_request_target + checkout of attacker-controlled fork head → RCE.
    # Widened window (multi-job workflows), head_ref/head_sha aliases, quoted ref.
    ("pr_target_checkout_head",
     r'pull_request_target[\s\S]{0,1500}?ref:\s*["\']?\s*\${{?\s*github\.(?:head_ref|head_sha|event\.pull_request\.head\.(?:sha|ref))',
     "CRITICAL", 0.92),

    # workflow_run + checkout of the *untrusted trigger* (head) → RCE. Only the
    # dangerous ref matters — a bare checkout of one's own default branch is safe.
    ("workflow_run_untrusted_checkout",
     r'workflow_run[\s\S]{0,1500}?actions/checkout@[\s\S]{0,200}?ref:\s*["\']?\s*\${{?\s*github\.event\.workflow_run\.head_',
     "HIGH", 0.75),

    # hardcoded secret in env — literal value, NOT a ${{ secrets.* }}/${{ env.* }}
    # reference; accepts quoted and unquoted scalars and compound key names.
    ("hardcoded_env_secret",
     r'(?i)^\s{2,}(?:aws_access_key_id|aws_secret_access_key|db_password|github_token|private_key|password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*:\s*(?!\s*["\']?\s*\$)\s*["\']?[^"\'\n\r$]{8,}["\']?\s*$',
     "HIGH", 0.80),

    # unpinned action — uses: owner/repo@vN (or @main/@master) without a 40-char
    # SHA digest. Pin-by-SHA prevents a tag-takeover hijacking the action.
    ("unpinned_action",
     r'uses:\s*[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@(?:v\d+(?:\.\d+)*|main|master)\b',
     "MEDIUM", 0.70),
]

WORKFLOW_RE = re.compile(r'\.github/workflows/.*\.ya?ml$', re.IGNORECASE)
# Workflow-level only: `permissions:` must sit at column 0 (job-level blocks are indented).
PERMISSIONS_RE = re.compile(r'^permissions\s*:', re.MULTILINE)


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "language": "yaml",
        "metadata": {"detector": "GS045", "pattern_id": rule_id.replace("GS045-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS045GitHubActionsDetector:
    rule_id = "GS045"
    name = "GitHub Actions CI/CD Security"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content or not WORKFLOW_RE.search(file_path):
            return findings

        # 1) least-privilege: workflow-level permissions block absent →
        #    every job defaults to write-all (GITHUB_TOKEN = full scope)
        if not PERMISSIONS_RE.search(content):
            findings.append(_finding(
                "GS045-missing_permissions", "HIGH",
                "GitHub Actions workflow without permissions block (least-privilege)",
                file_path, 1, _snippet(content, 1), 0.75))

        # 2) pattern-based checks
        for pattern_id, regex, severity, base_conf in GHA_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.DOTALL):
                line_no = content[:match.start()].count("\n") + 1
                findings.append(_finding(
                    f"GS045-{pattern_id}", severity,
                    f"GitHub Actions: {pattern_id}",
                    file_path, line_no, _snippet(content, line_no), base_conf))

        return findings


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS045"
ECHELON = 2
NOISE_TIER = "sensitive"
description = "GS045: GitHub Actions CI/CD Security Audit — least-privilege permissions, env secrets, PR-target RCE"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS045GitHubActionsDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if not WORKFLOW_RE.search(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings
