#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS029 — Secrets Detection (v0.29).

Standalone SAST detector in main pipeline. Reuses narrowed patterns
from cross-repo secrets (v0.27) with entropy filter + redaction.

No value is stored or displayed — only fact of detection.
"""

from __future__ import annotations

import math, re
from typing import Dict, List

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                   'aws_access_key',  None, "CRITICAL"),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY', 'private_key',    None, "CRITICAL"),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'jwt_token', 0, "HIGH"),
    (r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*'
     r'[\'"]?([A-Za-z0-9+/=_.\-!@#$%^&*]{12,})',                 'config_secret',   1, "HIGH"),
    (r'(?i)(?:mongodb|mysql|postgresql|redis|amqp)://[^\s\'"]{10,}', 'db_url',  None, "HIGH"),
]

EXCLUDE_PATH_RE = re.compile(
    r'(?:^|/)(?:tests?|fixtures?|examples?|samples?|tutorials?|devscripts?|mock|__mocks__|'
    r'node_modules|vendor|\.git|venv|\.venv)(?:/|$)', re.IGNORECASE)

EXCLUDE_FILE_RE = re.compile(
    r'(?:^test_|_test\.|conftest\.|setup\.|conf\.py$)', re.IGNORECASE)

MIN_ENTROPY = 3.0

def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class GS029SecretsDetector:
    rule_id = "GS029"
    name = "Secrets Detection"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> List[Dict]:
        if EXCLUDE_PATH_RE.search(file_path):
            return []
        fname = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
        if EXCLUDE_FILE_RE.search(fname):
            return []
        findings = []
        for pattern, secret_type, capture_idx, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                if capture_idx is not None:
                    value = m.group(capture_idx)
                    if _shannon_entropy(value) < MIN_ENTROPY:
                        continue
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule_id": f"GS029-{secret_type}",
                    "title": f"Potential {secret_type} exposed",
                    "severity": severity,
                    "confidence": 0.85,
                    "file_path": file_path,
                    "line_number": line_no,
                    "detail": f"<redacted:{secret_type}> at line {line_no}",
                    "metadata": {"secrets": {"type": secret_type}},
                })
        return findings
