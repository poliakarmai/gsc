# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS020 — LLM-based SQL Injection Detector (Pilot).
Replaces 87 regex patterns with a single LLM call per candidate file.
Faster, more accurate, fewer false positives.

Strategy:
1. Quick grep pre-filter: find files with SQL keywords (execute, cursor, raw, query)
2. For each candidate: send 20 lines of context to DeepSeek
3. LLM returns: {vulnerable: bool, confidence: 0-1, reason: str}
4. Only report high-confidence findings

Cost: ~$0.001/file. On 100 candidates = $0.10/day.
Precision target: >50% (vs <5% for regex approach).
"""

import os
import re
from pathlib import Path

RULE_ID = "GS024"
ECHELON = 2
CATEGORY = "CRITICAL"
DESCRIPTION = "LLM-based SQL/NoSQL injection detection — replaces 87 regex patterns with one smart call"


# Quick pre-filter: files that contain SQL-like patterns
PRE_FILTER_PATTERNS = [
    r'(?:execute|cursor|cursor\(\)|raw|query|text)\s*\(',
    r'(?:\.execute|\.raw|\.query|\.exec)\s*\(',
    r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:FROM|INTO|SET|TABLE)',
    r'(?:find_by_sql|find_by_sql\s*\()',
    r'(?:\$where|\$regex)',
]


def _get_api_key() -> str | None:
    """Get DeepSeek API key from env or .env file."""
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        # Try .env file (Hermes stores keys here, not in config.yaml)
        for env_path in [
            os.path.expanduser("~/.hermes/.env"),
            os.path.expanduser("~/.hermes/env"),
            ".env",
        ]:
            if os.path.exists(env_path):
                try:
                    with open(env_path) as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("DEEPSEEK_API_KEY="):
                                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                                if api_key:
                                    return api_key
                except Exception:
                    pass
    return api_key or None


def _quick_grep_filter(file_path: Path) -> bool:
    """Quick check: does this file contain SQL-like patterns?"""
    try:
        content = file_path.read_text(errors="replace")
        for pattern in PRE_FILTER_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    except Exception:
        pass
    return False


def _extract_candidates(file_path: Path, max_per_file: int = 5) -> list[dict]:
    """Extract candidate lines for LLM analysis."""
    try:
        lines = file_path.read_text(errors="replace").split("\n")
    except Exception:
        return []

    candidates = []
    for i, line in enumerate(lines):
        if len(candidates) >= max_per_file:
            break
        # Only lines that contain execute/query/raw + string formatting
        if re.search(r'(?:execute|query|raw|cursor)\s*\(\s*(?:f["\']|["\'].*%.*["\'])', line, re.IGNORECASE):
            start = max(0, i - 10)
            end = min(len(lines), i + 10)
            snippet = "\n".join(f"{j+1}: {l}" for j, l in enumerate(lines[start:end], start))
            candidates.append({
                "line_number": i + 1,
                "line": line.strip(),
                "snippet": snippet,
            })
    return candidates


def _call_llm(snippet: str, file_path: str) -> dict:
    """Unified LLM classify via gsc_llm_providers."""
    from gsc_llm_providers import defang, guard_system, llm_chat

    prompt = f"""You are a security code auditor. Analyze this code for SQL injection vulnerabilities.

CODE:
{defang(snippet[:2500])}

Determine if this is a REAL SQL injection vulnerability or a SAFE pattern.

SAFE patterns (NOT vulnerabilities):
- Parameterized queries: cursor.execute("SELECT ...", (param,))
- SQLAlchemy ORM: session.query(User).filter(...)
- Django ORM: Model.objects.filter(...)
- Static SQL strings (no user input interpolation)
- f-strings with trusted/internal variables only
- Test fixtures, documentation examples

REAL vulnerabilities:
- f-string with user-controlled input: cursor.execute(f"SELECT ... WHERE id={{request.GET['id']}}")
- String formatting with external data: cursor.execute("SELECT ..." % user_input)
- Raw SQL concatenation with request params

Reply with JSON only:
{{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "one sentence"}}"""

    content = llm_chat(
        guard_system("You are a security auditor. Reply with JSON only."),
        prompt, max_tokens=200, temperature=0.1,
    )
    if not content:
        return {"vulnerable": False, "confidence": 0, "reason": "No LLM provider configured"}

    try:
        import json
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            result = json.loads(content[start:end])
            return {
                "vulnerable": result.get("vulnerable", False),
                "confidence": result.get("confidence", 0.5),
                "reason": result.get("reason", ""),
            }
    except Exception as e:
        return {"vulnerable": False, "confidence": 0, "reason": f"LLM error: {str(e)[:100]}"}

    return {"vulnerable": False, "confidence": 0, "reason": "Failed to parse response"}


def detect(ctx) -> list:
    """
    LLM-based SQL injection detection.
    ctx: AuditContext with get_source_files(), project_path, etc.
    """
    findings = []

    # Check if we have an API key
    api_key = _get_api_key()
    if not api_key:
        return findings

    source_files = ctx.get_source_files(extensions=(".py", ".go", ".ts", ".js", ".java", ".rb", ".php"))
    if not source_files:
        return findings

    # Phase 1: Quick grep pre-filter → extract candidates per file
    file_candidates: list[tuple[Path, list[dict]]] = []
    total_candidates = 0
    for fp in source_files:
        if total_candidates >= 30:
            break
        if _quick_grep_filter(fp):
            cands = _extract_candidates(fp, max_per_file=3)
            if cands:
                file_candidates.append((fp, cands))
                total_candidates += len(cands)

    if not file_candidates:
        return findings

    # Phase 2: LLM analysis (limited to 30 candidates per scan for cost control)
    for fp, cands in file_candidates:
        for c in cands:
            result = _call_llm(c["snippet"], str(fp))
            if result.get("vulnerable") and result.get("confidence", 0) >= 0.7:
                findings.append({
                    "rule_id": RULE_ID,
                    "title": "LLM: SQL injection detected",
                    "category": "CRITICAL",
                    "echelon": ECHELON,
                    "file_path": str(fp),
                    "line_number": c["line_number"],
                    "detail": f"LLM confidence: {result['confidence']:.0%}. {result['reason']}",
                    "noise_tier": "precise",
                })

    return findings


# Standalone test
if __name__ == "__main__":
    # Test with a sample
    test_code = '''
def vulnerable(request):
    user_id = request.GET.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def safe(param):
    cursor.execute("SELECT * FROM users WHERE id = ?", (param,))
'''
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_path = f.name

    print(f"Testing LLM detector on: {test_path}")
    # Mock AuditContext
    class MockCtx:
        def get_source_files(self, extensions=None):
            return [Path(test_path)]
        project_path = Path(test_path).parent
        skipped_detectors = set()

    findings = detect(MockCtx())
    for f in findings:
        print(f"  [{f['category']}] {f['title']}: {f['detail']}")

    os.unlink(test_path)
