# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

"""
GS023 — Race Conditions / TOCTOU.

Real-World Bug Hunting + Web Hacking 101:
- Time-of-check to time-of-use (TOCTOU)
- Parallel request races (double-spend, double-redeem)
- Async race conditions in JS/Python
- File system races (symlink, tmpfile)

ECHELON: 3 (semantic, needs code flow analysis)
"""

from __future__ import annotations

import re
from pathlib import Path

from gsc_detectors import AuditContext, Detector, Finding

RULE_ID = "GS023"
ECHELON = 3
NOISE_TIER = "noisy"
description = "Race Conditions / TOCTOU — double-spend, async races, fs races (Bug Hunting)"

RACE_PATTERNS: list[tuple[str, str, str]] = [
    # TOCTOU — file system
    (r'os\.path\.exists\s*\(.*\).*\n.*open\s*\(', "TOCTOU: exists() then open() — file may change between calls", "HIGH"),
    (r'os\.access\s*\(.*\).*\n.*open\s*\(', "TOCTOU: os.access() then open() — race window", "HIGH"),
    (r'Path\(.*\)\.exists\s*\(\).*\n.*open\s*\(', "TOCTOU: Path.exists() then open()", "MEDIUM"),
    (r'tempfile\.(?:mktemp|mkstemp|mkdtemp)', "TOCTOU: tempfile without secure flags", "MEDIUM"),
    (r'os\.symlink\s*\(', "Potential TOCTOU: symlink creation — verify target validation", "INFO"),

    # Double-spend / payment races
    (r'\.save\s*\(\).*\n.*\.save\s*\(\)', "Potential race: two saves without SELECT FOR UPDATE", "HIGH"),
    (r'select_for_update|SELECT.*FOR UPDATE', "Race protection: SELECT FOR UPDATE (verify coverage)", "INFO"),
    (r'\.objects\.(?:get|filter)\s*\(.*\).*\n.*\.save\s*\(', "Potential race: Django get-then-save without locking", "HIGH"),
    (r'UPDATE.*WHERE.*\n.*SELECT', "Potential race: UPDATE then SELECT — lost update problem", "HIGH"),
    (r'transaction\.atomic|@transaction\.atomic', "Transaction present — verify isolation level", "INFO"),

    # Async races
    (r'await\s+.*\n.*await\s+.*(?:same_resource|balance|stock)', "Potential async race: parallel awaits on shared state", "MEDIUM"),
    (r'Promise\.all\s*\(', "Potential JS race: Promise.all on mutable state", "MEDIUM"),
    (r'async\s+def.*\n.*(?:global|self\.)', "Potential async race: async function with shared state", "MEDIUM"),
    (r'threading\.(?:Lock|RLock|Semaphore)', "Race protection: threading lock (verify scope)", "INFO"),

    # Coupon/promo races
    (r'(?:coupon|promo|voucher|discount).*\.(?:get|filter).*\n.*\.(?:delete|update|save)',
     "Potential coupon race: get-then-use without locking", "HIGH"),
    (r'(?:redeem|claim|apply).*coupon', "Coupon redemption — verify idempotency and locking", "MEDIUM"),

    # Idempotency
    (r'idempotency_key|idempotent|Idempotency-Key', "Idempotency: key present (verify correctness)", "INFO"),
    (r'stripe\.(?:charge|payment|customer).*create', "Stripe API — verify idempotency key", "INFO"),
]

FILE_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.rb', '.go', '.java', '.php'}

EXCLUDE_DIRS = {'node_modules', 'vendor', 'dist', '.git', '__pycache__', 'migrations'}

EXCLUDE_PATTERNS = ['test_', 'test/', '.test.', '.spec.', '__test__', 'migration']


def detect(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    files = _collect_files(ctx.path)

    for file_path in files:
        try:
            content = file_path.read_text(errors='replace')
        except (OSError, UnicodeDecodeError):
            continue

        rel_path = str(file_path.relative_to(ctx.path))
        if _is_skip_path(rel_path):
            continue

        for pattern, message, severity in RACE_PATTERNS:
            # Multi-line patterns need DOTALL
            flags = re.IGNORECASE | (re.DOTALL if '\\n' in pattern else 0)
            for match in re.finditer(pattern, content, flags):
                line_no = content[:match.start()].count('\\n') + 1
                snippet = _extract_line(content, line_no)
                if _is_false_positive(snippet, content):
                    continue
                if _is_noise_pattern(pattern, content):
                    continue
                findings.append(Finding(
                    rule_id=RULE_ID, severity=severity, category="race_condition",
                    file=rel_path, line=line_no, snippet=snippet.strip()[:200],
                    message=message, cwe="CWE-362",
                    cvss={"HIGH":"7.0","MEDIUM":"5.3","INFO":"0.0"}.get(severity,"5.0"),
                ))

    return findings


def _collect_files(root: Path) -> list[Path]:
    files = []
    for ext in FILE_EXTENSIONS:
        for f in root.rglob(f'*{ext}'):
            if any(d in f.parts for d in EXCLUDE_DIRS):
                continue
            if any(p in f.name for p in EXCLUDE_PATTERNS):
                continue
            files.append(f)
    return files


def _extract_line(content: str, line_no: int) -> str:
    lines = content.split('\n')
    return lines[line_no - 1] if 0 < line_no <= len(lines) else ''


def _is_false_positive(snippet: str, full_context: str = "") -> bool:
    s = snippet.strip()
    if s.startswith('//') or s.startswith('#') or s.startswith('/*') or s.startswith('*'):
        return True
    if s.startswith('<!--'):
        return True
    # os.path.exists → open is OK if wrapped in try/with
    if 'os.path.exists' in s or 'Path(' in s:
        if re.search(r'(with|try)\s*:', full_context):
            return True
    return False


def _is_skip_path(rel_path: str) -> bool:
    """Skip demo/test/sample/migration directories."""
    return bool(re.search(
        r'(?:/|\A)(?:tests?|fixtures?|examples?|samples?|demo|docs?|migrations?)/',
        rel_path, re.IGNORECASE
    ))


def _is_noise_pattern(pattern: str, full_context: str) -> bool:
    """Additional context checks to reduce noise."""
    # save()+save() is fine if it's different fields
    if re.search(r'\.save\s*\(\)', pattern) and re.search(r'select_for_update|\.objects\.select_for_update|transaction\.atomic', full_context):
        return True
    # async def + global is fine if it's a single-threaded context
    if 'async' in pattern and 'global' in pattern:
        if not re.search(r'(?:balance|stock|inventory|counter|ledger)', full_context, re.IGNORECASE):
            return True
    return False
