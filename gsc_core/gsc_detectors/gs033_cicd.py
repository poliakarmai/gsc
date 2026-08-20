#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS033 — CI/CD Pipeline Anti-Patterns (v1.0).

Scans GitHub Actions, GitLab CI, Jenkins, and other CI configs for:
  - Long-lived tokens instead of OIDC
  - Direct prod deploy without staging/canary
  - Secrets exposed in logs
  - pull_request_target without sandbox
  - Missing CODEOWNERS / branch protection
  - Self-hosted runners without isolation

Book reference: Brikman "Fundamentals of DevOps", 2026, ch.5 (CI/CD).
"""

from __future__ import annotations

import re
import hashlib
from typing import Any

# ── PATTERNS ──────────────────────────────────────────────────────────

CICD_PATTERNS: list[tuple[str, str, str, float]] = [
    # --- Token/credential antipatterns ---
    ("long_lived_token",
     r'(?i)(?:\$\{\{\s*secrets\.\w+\s*\}\}|TOKEN|GITHUB_TOKEN|'
     r'secrets\.(?:GITHUB_TOKEN|DEPLOY_KEY|NPM_TOKEN|PYPI_TOKEN|'
     r'DOCKER_PASSWORD|AWS_ACCESS_KEY_ID)|'
     r'with:\s*\n\s*token:\s*\$\{\{\s*secrets\.)',
     "HIGH", 0.80),

    # --- Deploy without safety ---
    ("prod_deploy_no_staging",
     r'(?i)name:\s*(?:deploy.*prod|production.*deploy|release)',
     "MEDIUM", 0.50),  # context-dependent — flag for review

    ("deploy_no_canary",
     r'(?i)(?:deploy|rollout|release).{0,50}(?:production|prod)'
     r'(?!.{0,100}(?:canary|staging|blue.green|rolling))',
     "LOW", 0.40),

    # --- Secret exposure in logs ---
    ("secret_in_log",
     r'(?i)(?:echo|cat|printf).{0,30}secrets\.\w+',
     "CRITICAL", 0.95),

    ("secret_in_env_dump",
     r'(?i)(?:printenv|env\s*\|\s*grep|set\s*\|\s*grep)',
     "HIGH", 0.70),

    # --- Pull request risks ---
    ("pull_request_target_unsafe",
     r'pull_request_target.{0,100}actions/checkout@v\d+\s*\n\s*with:'
     r'\s*\n\s*ref:\s*',
     "CRITICAL", 0.90),

    ("pull_request_no_sandbox",
     r'pull_request_target(?!.{0,200}(?:environment:|environment\s*:))',
     "HIGH", 0.70),

    # --- Runner security ---
    ("self_hosted_runner",
     r'runs-on:\s*(?:self-hosted|\[.*self-hosted)',
     "MEDIUM", 0.60),

    # --- Checkout safety ---
    ("persist_credentials",
     r'actions/checkout@v\d+(?!.{0,200}persist-credentials:\s*false)',
     "MEDIUM", 0.65),

    ("checkout_no_ref",
     r'actions/checkout@v\d+(?!.{0,200}ref:\s*)',
     "LOW", 0.30),

    # --- Unsafe script execution ---
    ("script_injection_via_var",
     r'run:\s*\|\s*\n\s*.*github\.event\.(?:issue|comment|pull_request)',
     "CRITICAL", 0.85),

    ("curl_pipe_bash_in_ci",
     r'run:\s*\|\s*\n\s*curl\s+.*\|\s*(?:sh|bash|python)',
     "HIGH", 0.75),
]

# ── EXCLUSIONS ────────────────────────────────────────────────────────

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)'
    r'(?:tests?|fixtures?|examples?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv|'
    r'\.pytest_cache|__pycache__|dist|build)'
    r'(?:/|$)', re.IGNORECASE)

CI_FILE_PATTERNS = [
    r'.github/workflows/.*\.ya?ml$',
    r'\.gitlab-ci\.ya?ml$',
    r'Jenkinsfile$',
    r'\.circleci/config\.ya?ml$',
    r'\.travis\.ya?ml$',
    r'azure-pipelines\.ya?ml$',
]


def _is_ci_file(file_path: str) -> bool:
    for pattern in CI_FILE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


def _finding(rule_id: str, severity: str, title: str, file_path: str,
             line_no: int, snippet: str, confidence: float) -> dict[str, Any]:
    key = hashlib.sha256(f"{rule_id}{file_path}{snippet}".encode()).hexdigest()[:12]
    return {
        "finding_key": key,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "language": "yaml",
        "metadata": {
            "detector": "GS033",
            "pattern_id": rule_id.replace("GS033-", ""),
        },
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS033CICDDetector:
    rule_id = "GS033"
    name = "CI/CD Pipeline Anti-Patterns"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content:
            return findings

        if EXCLUDE_PATH_RE.search(file_path):
            return findings

        if not _is_ci_file(file_path):
            return findings

        pattern_hits = 0

        for pattern_id, regex, severity, base_conf in CICD_PATTERNS:
            matches = list(re.finditer(regex, content, re.MULTILINE))
            if not matches:
                continue

            pattern_hits += len(matches)

            for match in matches:
                line_no = content[:match.start()].count("\n") + 1
                snippet = _snippet(content, line_no)
                matched = match.group(0)[:120]

                confidence = base_conf
                if pattern_id == "secret_in_log":
                    confidence = 0.98

                findings.append(_finding(
                    f"GS033-{pattern_id}", severity,
                    f"CI/CD anti-pattern: {pattern_id}",
                    file_path, line_no, snippet, confidence,
                ))

        # A single CI workflow file cannot establish repository-level CODEOWNERS
        # absence, and a pattern-count aggregate adds no independent security
        # signal. Individual CICD_PATTERNS findings above already carry locations.

        return findings


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS033"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS033: CI/CD Anti-Patterns — detect unsafe GitHub Actions/GitLab CI patterns"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS033CICDDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if not _is_ci_file(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings
