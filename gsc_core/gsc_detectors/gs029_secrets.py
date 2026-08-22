#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GS029 — Secrets Detection (v0.29).

Standalone SAST detector in main pipeline. Reuses narrowed patterns
from cross-repo secrets (v0.27) with entropy filter + redaction.

No value is stored or displayed — only fact of detection.
"""

from __future__ import annotations

import math, os, re
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

# Placeholder / demo / example secret values — skipped when the captured value
# begins with an unambiguous placeholder marker (no real secret starts with these).
# Anchored at start via .match(); `(?![a-z])` prevents prefix collisions with
# real English words (e.g. "democratic", "testing", "examplesecret").
PLACEHOLDER_VALUE_RE = re.compile(
    r'(?i)^(?:'
    r'your[_\- ]?(?:api[_\- ]?key|token|secret|password|passwd|key|value|here)'  # your_api_key_here
    r'|(?:change|replace)[_\- ]?me'                                              # changeme / replace_me
    r'|dummy|fake|placeholder|redacted'
    r'|(?:sample|example|demo|test)(?![a-z])'                                    # example_… / test-… / test123
    r'|x{4,}'                                                                    # xxxx
    r'|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}'                                        # <KEY> ${KEY} {{KEY}}
    r'|[а-яё]+[_\- ]?(?:ключ|пароль|секрет|токен|api[_\- ]?key)'                 # ваш-ключ-здесь
    r')'
)

# Canonical AWS documentation example access key — appears in countless READMEs/
# tutorials. Non-functional by definition; never a real credential.
AWS_EXAMPLE_KEYS = {"AKIAIOSFODNN7EXAMPLE"}

# Loopback DB connection strings (localhost / 127.0.0.1 / ::1, with optional
# userinfo and port) are dev/default examples, not leaked production credentials.
DB_URL_LOOPBACK_RE = re.compile(
    r'(?i)^(?:mongodb|mysql|postgresql|redis|amqp)://'
    r'(?:[^/@\s]+@)?'
    r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)(?::\d+)?(?:/|$)'
)


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

    def detect(self, file_path: str, content: str, language: str = "auto",
               verify_live=None) -> List[Dict]:
        # Фаза 8: live-verify выключается по умолчанию (как DAST), включается
        # флагом env GSC_VERIFY_SECRETS=1 или явным verify_live=True.
        if verify_live is None:
            verify_live = os.environ.get("GSC_VERIFY_SECRETS") == "1"
        if EXCLUDE_PATH_RE.search(file_path):
            return []
        fname = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
        if EXCLUDE_FILE_RE.search(fname):
            return []
        findings = []
        for pattern, secret_type, capture_idx, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                value = m.group(capture_idx) if capture_idx is not None else m.group(0)
                if capture_idx is not None:
                    if _shannon_entropy(value) < MIN_ENTROPY:
                        continue
                    if PLACEHOLDER_VALUE_RE.match(value):
                        continue
                if secret_type == "aws_access_key" and m.group(0) in AWS_EXAMPLE_KEYS:
                    continue
                if secret_type == "db_url" and DB_URL_LOOPBACK_RE.match(m.group(0)):
                    continue
                line_no = content[:m.start()].count("\n") + 1
                finding = {
                    "rule_id": f"GS029-{secret_type}",
                    "title": f"Potential {secret_type} exposed",
                    "severity": severity,
                    "confidence": 0.85,
                    "file_path": file_path,
                    "line_number": line_no,
                    "detail": f"<redacted:{secret_type}> at line {line_no}",
                    "metadata": {"secrets": {"type": secret_type}},
                }
                if verify_live:
                    self._live_verify(finding, value)
                findings.append(finding)
        return findings

    def _live_verify(self, finding: Dict, value: str) -> None:
        """Фаза 8: live-проверка секрета (опционально, off by default как DAST).

        dead → deboost confidence ×0.3 + metadata. Значение не сохраняется и не
        логируется. Ленивый import — verifier живёт в gsc_cli (сеть), core не
        зависит от cli статически.
        """
        try:
            from gsc_secrets_verifier import verify_secret
        except Exception:
            return
        try:
            r = verify_secret(value)
        except Exception:
            return
        if r.get("status") == "dead":
            finding["confidence"] = round(finding.get("confidence", 0.85) * 0.3, 2)
            finding["metadata"]["secrets"]["status"] = "dead"
            finding["metadata"]["secrets"]["provider"] = r.get("provider")
            finding["detail"] += " [dead — live-verified]"
