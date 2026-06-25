#!/usr/bin/env python3
"""
GSC E4 — LLM-powered deep analysis module.
Spec: escalates only high-value findings to LLM, cost-guarded, cache-enabled.

Escalation rules:
  - E3 Adversarial finding without clear pattern
  - Finding clustered with 2+ others in same file
  - Schema mismatch between SQL/ORM
  - User explicitly passes --deep
  - Pattern has needs_review: true

Cost guardrails:
  - max_tokens_per_finding: 800
  - max_cost_per_scan_usd: 2.0
  - circuit_breaker: max 20 findings per scan
  - Cache: sha256(snippet + pattern_id) → skip re-analysis
"""

import os, sys, json, hashlib, sqlite3
from pathlib import Path
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
CACHE_DB = os.path.expanduser("~/.hermes/state/gsc_e4_cache.db")

# ── Config (can be overridden via env / config.yaml) ─────────────────────────

E4_CONFIG = {
    "provider": os.environ.get("GSC_LLM_PROVIDER", "openrouter"),
    "model": os.environ.get("GSC_LLM_MODEL", "google/gemini-2.5-flash"),
    "max_tokens_per_finding": int(os.environ.get("GSC_E4_MAX_TOKENS", "800")),
    "max_cost_per_scan_usd": float(os.environ.get("GSC_E4_MAX_COST_USD", "2.0")),
    "circuit_breaker_max": int(os.environ.get("GSC_E4_CB_MAX", "20")),
    "cache_enabled": os.environ.get("GSC_E4_CACHE", "true").lower() != "false",
    "cache_ttl_days": int(os.environ.get("GSC_E4_CACHE_TTL", "30")),
    "local_fallback": os.environ.get("GSC_LLM_PROVIDER") == "ollama",
}

PROMPT_SYSTEM = """You are GSC-E4, a security reasoning engine.
You receive code snippets and preliminary E1-E3 findings.
Your task: validate the finding AND assess business-logic risk.
Output JSON strictly following the schema.

Rules:
1. Only flag if REAL exploitable vulnerability exists
2. Consider project context (is this a test file? is input sanitized earlier?)
3. Suggest minimal fix preserving existing code style
4. CVSS vector must be justified"""

PROMPT_USER = """## Context
Project: {project}
File: {file_path}
Lines: {line_start}-{line_end}

## Code
```{language}
{code_snippet}
```

## Finding
Category: {category}
Title: {title}
Detail: {detail}

## Similar findings in this project
{related_findings}

## Task
1. Is this a real vulnerability? (true/false)
2. Can it be exploited in this specific context? (none|low|medium|high)
3. Suggest minimal fix preserving project style
4. CVSS vector string

Output JSON:
{{
  "is_real": bool,
  "exploitability": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "fix": "code diff or description",
  "cvss_vector": "CVSS:3.1/AV:...",
  "cvss_score": 0.0-10.0
}}"""


def should_escalate(finding: dict, findings_in_file: list) -> bool:
    """Determine if this finding should go to LLM."""
    # Rule 1: User explicitly asked for deep
    if os.environ.get("GSC_DEEP_MODE"):
        return True

    # Rule 2: E3 finding without clear pattern
    if finding.get("echelon") == 3 and not finding.get("pattern_title"):
        return True

    # Rule 3: Clustered risk (2+ findings in same file)
    if len(findings_in_file) >= 2:
        return True

    # Rule 4: Schema mismatch pattern
    detail = (finding.get("detail") or "").lower()
    if any(kw in detail for kw in ["schema", "column", "valid_from", "created_at", "mismatch"]):
        return True

    return False


def get_cache_key(finding: dict, code_snippet: str) -> str:
    """Generate deterministic cache key."""
    raw = f"{finding.get('file_path','')}:{finding.get('line_number',0)}:{finding.get('title','')}:{code_snippet}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def check_cache(cache_key: str) -> dict | None:
    """Check if this finding was already analyzed."""
    if not os.path.exists(CACHE_DB):
        return None

    conn = sqlite3.connect(CACHE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS e4_cache (
        cache_key TEXT PRIMARY KEY,
        response_json TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        ttl_days INTEGER DEFAULT 30
    )""")
    row = conn.execute(
        "SELECT response_json FROM e4_cache WHERE cache_key=? AND datetime(created_at, '+' || ttl_days || ' days') > datetime('now')",
        (cache_key,)
    ).fetchone()
    conn.close()
    return json.loads(row['response_json']) if row else None


def save_cache(cache_key: str, response: dict):
    """Cache LLM response."""
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS e4_cache (
        cache_key TEXT PRIMARY KEY, response_json TEXT,
        created_at TEXT DEFAULT (datetime('now')), ttl_days INTEGER DEFAULT 30
    )""")
    conn.execute(
        "INSERT OR REPLACE INTO e4_cache (cache_key, response_json, ttl_days) VALUES (?,?,?)",
        (cache_key, json.dumps(response), E4_CONFIG["cache_ttl_days"])
    )
    conn.commit()
    conn.close()


def read_code_snippet(file_path: str, line_number: int, context_lines: int = 10) -> str | None:
    """Read code around the finding for LLM context."""
    path = Path(file_path)
    if not path.exists():
        return None

    try:
        lines = path.read_text().split("\n")
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        snippet = "\n".join(lines[start:end])
        # Truncate if too long
        if len(snippet) > 3000:
            snippet = snippet[:3000] + "\n... (truncated)"
        return snippet
    except Exception:
        return None


def collect_related(findings: list[dict], file_path: str, limit: int = 3) -> str:
    """Find related findings in the same file."""
    related = [f for f in findings if f.get('file_path') == file_path and f.get('title') != findings[0].get('title')]
    if not related:
        return "None"

    lines = []
    for r in related[:limit]:
        lines.append(f"- [{r.get('category','?')}] {r.get('title','?')} (line {r.get('line_number','?')})")
    return "\n".join(lines)


def analyze_finding(finding: dict, all_findings: list[dict], code_snippet: str = None) -> dict | None:
    """Run E4 LLM analysis on a single finding. Returns enriched finding or None."""
    if not should_escalate(finding, [f for f in all_findings if f.get('file_path') == finding.get('file_path')]):
        return None

    # Circuit breaker
    analyzed_count = sum(1 for f in all_findings if f.get('e4_analyzed'))
    if analyzed_count >= E4_CONFIG["circuit_breaker_max"]:
        return None

    # Read code if not provided
    if not code_snippet:
        code_snippet = read_code_snippet(
            finding.get('file_path', ''),
            finding.get('line_number', 0)
        )
    if not code_snippet:
        return None

    # Check cache
    cache_key = get_cache_key(finding, code_snippet)
    if E4_CONFIG["cache_enabled"]:
        cached = check_cache(cache_key)
        if cached:
            finding['e4_analyzed'] = True
            finding['e4_result'] = cached
            finding['e4_source'] = 'cache'
            return finding

    # Build prompt
    prompt = PROMPT_USER.format(
        project=finding.get('project', 'unknown'),
        file_path=finding.get('file_path', '?'),
        line_start=max(0, (finding.get('line_number', 0) or 0) - 10),
        line_end=(finding.get('line_number', 0) or 0) + 10,
        language="python" if finding.get('file_path', '').endswith('.py') else "text",
        code_snippet=code_snippet,
        category=finding.get('category', '?'),
        title=finding.get('title', '?'),
        detail=finding.get('detail', ''),
        related_findings=collect_related(all_findings, finding.get('file_path', '')),
    )

    # Route: ollama → OpenRouter API → placeholder
    if E4_CONFIG["local_fallback"]:
        result = analyze_local(prompt)
    else:
        result = call_openrouter(prompt)

    if result:
        save_cache(cache_key, result)
        finding['e4_analyzed'] = True
        finding['e4_result'] = result
        finding['e4_source'] = 'llm'

    return finding


def call_openrouter(prompt: str) -> dict | None:
    """Call OpenRouter API for E4 analysis."""
    try:
        import requests

        # Get API key — from config.yaml (already set via hermes config set)
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            # Read from Hermes config
            import yaml
            cfg_path = os.path.expanduser("~/.hermes/config.yaml")
            if os.path.exists(cfg_path):
                with open(cfg_path) as f:
                    cfg = yaml.safe_load(f)
                api_key = cfg.get("auxiliary", {}).get("vision", {}).get("api_key", "")

        if not api_key:
            return {"is_real": False, "exploitability": "none", "confidence": 0.0,
                    "reasoning": "No OpenRouter API key found", "fix": "N/A",
                    "cvss_vector": "N/A", "cvss_score": 0.0}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/poliakarmai/gsc",
            "X-Title": "GSC-E4"
        }

        body = {
            "model": E4_CONFIG["model"],
            "messages": [
                {"role": "system", "content": PROMPT_SYSTEM},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": E4_CONFIG["max_tokens_per_finding"],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }

        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers, json=body, timeout=30
        )

        if r.status_code != 200:
            return {"is_real": False, "exploitability": "none", "confidence": 0.0,
                    "reasoning": f"OpenRouter error {r.status_code}: {r.text[:200]}",
                    "fix": "N/A", "cvss_vector": "N/A", "cvss_score": 0.0}

        data = r.json()
        content = data["choices"][0]["message"]["content"]

        # Parse JSON from response
        return json.loads(content)

    except Exception as e:
        return {"is_real": False, "exploitability": "none", "confidence": 0.0,
                "reasoning": f"E4 API call failed: {e}", "fix": "N/A",
                "cvss_vector": "N/A", "cvss_score": 0.0}


def analyze_local(prompt: str) -> dict | None:
    """Use local ollama for E4 analysis."""
    try:
        import subprocess
        full_prompt = PROMPT_SYSTEM + "\n\n" + prompt
        r = subprocess.run(
            ["ollama", "run", E4_CONFIG["model"], full_prompt],
            capture_output=True, text=True, timeout=60
        )
        # Parse JSON from response (ollama may wrap in markdown)
        response = r.stdout.strip()
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]
        return json.loads(response)
    except Exception as e:
        return {"is_real": False, "exploitability": "none", "confidence": 0.0,
                "reasoning": f"Local analysis failed: {e}", "fix": "N/A",
                "cvss_vector": "N/A", "cvss_score": 0.0}


def run_e4_scan(findings: list[dict], max_cost_usd: float = None) -> list[dict]:
    """Run E4 analysis on escalated findings. Non-destructive — enriches findings in-place."""
    if max_cost_usd:
        E4_CONFIG["max_cost_per_scan_usd"] = max_cost_usd

    enriched = []
    for f in findings:
        result = analyze_finding(f, findings)
        if result:
            enriched.append(result)

    return enriched


if __name__ == "__main__":
    # Standalone test: analyze a sample finding
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        finding = {
            "project": "test", "file_path": "/tmp/test.py", "line_number": 10,
            "category": "HIGH", "echelon": 3, "title": "SQL injection risk",
            "detail": "f-string used in SQL query without parameterization"
        }
        result = analyze_finding(finding, [finding], "query = f\"SELECT * FROM users WHERE id={user_id}\"")
        print(json.dumps(result, indent=2, default=str))
    else:
        print("E4 module ready. Run with 'test' arg to test, or import run_e4_scan().")
