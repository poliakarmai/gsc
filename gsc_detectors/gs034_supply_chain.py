#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""
GS034 — npm Supply Chain Attack Detector.

Detects patterns from ChainDrop (Aug 2026) and similar npm supply chain worms:
  - Suspicious preinstall/postinstall scripts in package.json
  - Downloader stagers (setup.mjs, loader.js)
  - Infostealer payloads (Math_Symbol.js, obfuscated JS)
  - Bun runtime download (evasion — not a typical npm dep)
  - C2/exfiltration domains (npm-cache[.]com, etc.)
  - npm token validation before exfil (registry.npmjs.org/-/whoami)

Attack chain (ChainDrop):
  1. Compromised maintainer → malicious commit
  2. package.json: "preinstall": "node setup.mjs"
  3. setup.mjs downloads Bun → runs infostealer → exfils tokens
  4. Stolen tokens → infect more repos → worm spreads
  5. GitHub Actions provenance = valid → bypasses trust checks
"""

from __future__ import annotations

import json
import re
import hashlib
from pathlib import Path
from typing import Any


# ── PACKAGE.JSON PATTERNS ─────────────────────────────────────────────

PACKAGE_JSON_RULES: list[tuple[str, str, str, float]] = [
    # --- Suspicious lifecycle scripts ---
    ("preinstall_script",
     r'"preinstall"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "CRITICAL", 0.90),
    ("postinstall_script",
     r'"postinstall"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "HIGH", 0.75),
    ("install_script",
     r'"install"\s*:\s*"(?:node|npm|python|bash|sh|cmd)\s+',
     "HIGH", 0.70),

    # --- Known ChainDrop stagers ---
    ("setup_mjs_stager",
     r'setup\.mjs|loader\.mjs|init\.mjs|bootstrap\.mjs',
     "CRITICAL", 0.95),
    ("infostealer_payload",
     r'Math_Symbol\.js|math_init\.js|crypto_utils\.js|random_bytes\.js',
     "CRITICAL", 0.90),

    # --- Bun download evasion ---
    ("bun_runtime_download",
     r'(?i)(?:bun-sh/bun|bun\.sh|oven-sh/bun).{0,100}(?:releases/download|install)',
     "HIGH", 0.85),

    # --- Token/credential theft ---
    ("token_theft_npm",
     r'registry\.npmjs\.(?:org|com)/-/whoami',
     "CRITICAL", 0.95),
    ("token_theft_github",
     r'(?i)(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}',
     "CRITICAL", 0.85),
    ("aws_key_theft",
     r'(?i)(?:AKIA|ASIA)[A-Z0-9]{16}',
     "CRITICAL", 0.90),

    # --- Exfiltration ---
    ("exfil_domain",
     r'(?i)(?:npm-cache\.com|npm-cdn\.com|npm-registry\.xyz|'
     r'npm-mirror\.net|package-cache\.org)',
     "CRITICAL", 0.95),
    ("exfil_github_repo",
     r'(?i)github\.com/[^/]+/(?:Shai-Hulud|chaindrop|token-dump|'
     r'secret-exfil|cred-collector)',
     "CRITICAL", 0.90),

    # --- Obfuscation markers ---
    ("obfuscated_js",
     r'(?i)(?:atob|btoa)\s*\(\s*[\'"`][A-Za-z0-9+/=]{100,}[\'"`]\s*\)',
     "HIGH", 0.80),
    ("eval_obfuscation",
     r'eval\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode)',
     "HIGH", 0.85),

    # --- Dependency confusion / typo-squatting ---
    ("typo_squatting",
     r'"(?:@?\w+[-_](?:utils|helper|core|lib|common|config|tools|'
     r'auth|api|client|server|proxy|cache|logger|parser)[-_.]\w+)"\s*:\s*"[~^]',
     "LOW", 0.30),
]


# ── JS/MJS FILE PATTERNS ──────────────────────────────────────────────

JS_MALWARE_RULES: list[tuple[str, str, str, float]] = [
    ("bun_downloader",
     r'(?i)(?:fetch|https?://).{0,100}(?:github\.com/oven-sh/bun|'
     r'bun\.sh)/releases/download',
     "CRITICAL", 0.95),
    ("token_collector",
     r'(?i)process\.env(?!\.CI|\.NODE_ENV|\.PATH|\.HOME|\.USER)',
     "HIGH", 0.70),
    ("env_dump_all",
     r'(?i)(?:Object\.(?:entries|keys|values)|for\s*\(.*in)\s*\(?\s*process\.env',
     "CRITICAL", 0.85),
    ("file_exfiltrator",
     r'(?i)readFile(?:Sync)?\s*\(.{0,100}(?:npmrc|gitconfig|credentials|'
     r'id_rsa|\.env|config\.json)',
     "CRITICAL", 0.90),
    ("github_exfil_api",
     r'(?i)fetch\s*\(.{0,50}api\.github\.com.{0,50}'
     r'(?:contents|PUT|Authorization)',
     "CRITICAL", 0.90),
    ("encoded_payload",
     r'(?:atob|Buffer\.from)\s*\(\s*[\'"`][A-Za-z0-9+/=]{200,}[\'"`]\s*\)',
     "CRITICAL", 0.90),
]


# ── EXCLUSIONS ────────────────────────────────────────────────────────

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
        "finding_key": key,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line_number": line_no,
        "detail": f"{title} at line {line_no}",
        "snippet": snippet,
        "metadata": {"detector": "GS034", "pattern_id": rule_id.replace("GS034-", "")},
    }


def _snippet(content: str, line_no: int, window: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - window)
    end = min(len(lines), line_no + window)
    return "\n".join(lines[start:end])


# ── DETECTOR ──────────────────────────────────────────────────────────

class GS034SupplyChainDetector:
    rule_id = "GS034"
    name = "npm Supply Chain Attack Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not content or EXCLUDE_PATH_RE.search(file_path):
            return findings

        fname = file_path.split("/")[-1].lower()
        ext = file_path[file_path.rfind('.'):].lower() if '.' in file_path else ''

        # Scan package.json
        if fname == "package.json":
            findings.extend(self._scan_package_json(file_path, content))

        # Scan JS/MJS files for malware patterns
        if ext in ('.js', '.mjs', '.cjs', '.ts'):
            findings.extend(self._scan_js_file(file_path, content))

        return findings

    def _scan_package_json(self, file_path: str, content: str) -> list[dict[str, Any]]:
        findings = []
        pattern_hits = 0

        for pattern_id, regex, severity, base_conf in PACKAGE_JSON_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = _snippet(content, line_no)
                findings.append(_finding(
                    f"GS034-{pattern_id}", severity,
                    f"Supply chain risk in package.json: {pattern_id}",
                    file_path, line_no, snippet, base_conf,
                ))
                pattern_hits += 1

        if pattern_hits >= 3:
            findings.append(_finding(
                "GS034-package_json_critical", "CRITICAL",
                f"package.json has {pattern_hits} supply chain red flags — likely compromised",
                file_path, 1, f"({pattern_hits} patterns matched)", 0.95,
            ))

        return findings

    def _scan_js_file(self, file_path: str, content: str) -> list[dict[str, Any]]:
        findings = []
        fname = file_path.split("/")[-1].lower()

        # Only flag uncommon filenames (not typical app code)
        suspicious_names = {'setup', 'loader', 'init', 'bootstrap', 'runtime',
                            'helper', 'utils', 'math_symbol', 'math_init',
                            'random_bytes', 'crypto_utils'}
        is_suspicious_name = any(n in fname.replace('.js', '').replace('.mjs', '')
                                 for n in suspicious_names)

        for pattern_id, regex, severity, base_conf in JS_MALWARE_RULES:
            for match in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:match.start()].count("\n") + 1
                # Boost confidence for files with suspicious names
                conf = min(0.98, base_conf + 0.1) if is_suspicious_name else base_conf
                snippet = _snippet(content, line_no)
                findings.append(_finding(
                    f"GS034-{pattern_id}", severity,
                    f"Supply chain malware pattern in JS: {pattern_id}",
                    file_path, line_no, snippet, conf,
                ))

        return findings


# ── Registry bridge ───────────────────────────────────────────────────

RULE_ID = "GS034"
ECHELON = 1
NOISE_TIER = "sensitive"
description = "GS034: npm Malware Patterns — detect ChainDrop worms, dependency confusion, typosquatting in package.json"


def detect(ctx) -> list[dict]:
    """Bridge function for registry compatibility."""
    det = GS034SupplyChainDetector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        fname = fp.name.lower()
        ext = fp.suffix.lower()
        if fname != "package.json" and ext not in ('.js', '.mjs', '.cjs', '.ts'):
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        if EXCLUDE_PATH_RE.search(rel):
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        findings.extend(det.detect(rel, content))
    return findings
