#!/usr/bin/env python3
"""
GSC PoC Auto-Generator v1.0.

Generates proof-of-concept exploits for confirmed findings.
- If PoC generation succeeds → confidence boost + PoC included in reports
- If PoC generation fails → confidence reduction (finding likely FP)
- Formats: curl, Python, pytest

Usage:
  python3 gsc_poc_generator.py <finding_id>              # single finding
  python3 gsc_poc_generator.py --project gsc --min-sev HIGH  # batch
"""

import os, sys, json, sqlite3, textwrap
from pathlib import Path
from typing import Optional

GSC_HOME = Path(__file__).resolve().parent
DB_PATH = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"


def _get_api_key() -> str:
    if API_KEY:
        return API_KEY
    env_paths = [
        Path(os.path.expanduser("~/.hermes/.env")),
        Path(os.path.expanduser("~/.hermes/env")),
    ]
    for p in env_paths:
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"\'')
    return ""


def _call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 800) -> Optional[str]:
    """Call DeepSeek API for PoC generation."""
    import urllib.request as _req

    key = _get_api_key()
    if not key:
        return None

    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode()

    r = _req.Request(API_URL, data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    })

    try:
        resp = json.loads(_req.urlopen(r, timeout=30).read())
        return resp["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[PoC Gen] LLM call failed: {e}", file=sys.stderr)
        return None


def _read_context(file_path: str, line: int, window: int = 30) -> str:
    """Read ±window lines around the finding, with line numbers."""
    p = Path(file_path)
    if not p.is_absolute():
        # Try relative to GSC home and cwd
        for base in [GSC_HOME, Path.cwd()]:
            candidate = base / file_path
            if candidate.exists():
                p = candidate
                break

    if not p.exists():
        return f"// [file not found: {file_path}]"

    try:
        lines = p.read_text(errors='replace').splitlines()
    except Exception:
        return f"// [cannot read: {file_path}]"

    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    result = []
    for i in range(start, end):
        marker = ">>>" if i == line - 1 else "   "
        result.append(f"{marker} {i+1:4d}| {lines[i]}")
    return "\n".join(result)


def generate_poc(finding: dict, project_dir: str = ".") -> Optional[dict]:
    """
    Generate PoC for a single finding.
    Returns None if generation fails (→ reduce confidence).
    """
    file_path = finding.get("file_path", "")
    line = finding.get("line", finding.get("line_number", 0))
    rule_id = finding.get("pattern_title", finding.get("rule_id", "?"))
    title = finding.get("title", "")
    detail = finding.get("detail", "")

    context = _read_context(file_path, line)

    system = textwrap.dedent("""\
    You are a security researcher generating minimal proof-of-concept exploits.
    Your PoCs must be:
    - SYNTAX-VALID (compilable/runnable code)
    - MINIMAL (shortest possible demo of the vulnerability)
    - SAFE (demonstrate impact without causing real harm)
    - FORMATTED as a single fenced code block

    If the finding is a FALSE POSITIVE (not actually exploitable), respond with:
    ```
    FALSE_POSITIVE: <reason>
    ```

    If exploitable, respond with:
    ```
    PoC:
    <exploit code>
    
    Impact: <what happens>
    Severity: <CRITICAL|HIGH|MEDIUM|LOW>
    ```""")

    user = f"""Finding: {rule_id} — {title}
File: {file_path}, line {line}
Detail: {detail}

Code context:
```
{context}
```

Generate a minimal PoC. If this is a false positive, say so."""

    result = _call_llm(system, user, max_tokens=600)
    if not result:
        return None

    # Parse result
    is_fp = "FALSE_POSITIVE" in result.upper()
    if is_fp:
        return {"poc": None, "is_false_positive": True, "reason": result}

    # Extract code block if present
    code = result
    if "```" in result:
        blocks = result.split("```")
        if len(blocks) >= 2:
            code = blocks[1]
            # Strip language tag
            if "\n" in code:
                first_line, rest = code.split("\n", 1)
                if first_line.strip().lower() in ("python", "bash", "curl", "sh", "pytest"):
                    code = rest

    return {
        "poc": code.strip(),
        "is_false_positive": False,
        "full_response": result,
    }


def generate_batch(project: str, min_severity: str = "HIGH", limit: int = 10) -> list[dict]:
    """Generate PoCs for top findings in a project."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    min_idx = sev_order.get(min_severity, 1)

    rows = conn.execute("""
        SELECT * FROM findings
        WHERE project = ? AND revalidation_verdict IS NULL
        ORDER BY CASE category
            WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END
        LIMIT ?
    """, (project, limit)).fetchall()
    conn.close()

    results = []
    for r in rows:
        finding = dict(r)
        poc = generate_poc(finding)
        finding["poc"] = poc
        results.append(finding)
        rule = finding.get("pattern_title", finding.get("rule_id", "?"))[:30]
        if poc and not poc.get("is_false_positive"):
            print(f"✅ {rule} — PoC generated")
        elif poc and poc.get("is_false_positive"):
            print(f"🔴 {rule} — FALSE POSITIVE: {poc.get('reason','')[:80]}")
        else:
            print(f"⚠️ {rule} — PoC generation failed")

    return results


def poc_confidence_adjust(finding: dict, poc_result: Optional[dict]) -> float:
    """
    Adjust confidence based on PoC generation result.
    - PoC generated → +0.10 boost (max 0.95)
    - False positive → -0.30 penalty (min 0.05)
    - Generation failed → -0.10 penalty (uncertainty)
    """
    base = finding.get("confidence", 0.5)

    if poc_result is None:
        return max(0.05, base - 0.10)
    if poc_result.get("is_false_positive"):
        return max(0.05, base - 0.30)
    if poc_result.get("poc"):
        return min(0.95, base + 0.10)
    return base


# ── CLI ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="GSC PoC Auto-Generator")
    p.add_argument("finding_id", nargs="?", help="Finding ID from DB")
    p.add_argument("--project", help="Project name for batch generation")
    p.add_argument("--min-sev", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM"])
    p.add_argument("--limit", type=int, default=10)
    args = p.parse_args()

    if args.project:
        results = generate_batch(args.project, args.min_sev, args.limit)
        generated = sum(1 for r in results if r.get("poc") and r["poc"].get("poc"))
        fp = sum(1 for r in results if r.get("poc") and r["poc"].get("is_false_positive"))
        failed = sum(1 for r in results if r.get("poc") is None)
        print(f"\n📊 {len(results)} findings: {generated} PoCs, {fp} FP, {failed} failed")
    elif args.finding_id:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        r = conn.execute("SELECT * FROM findings WHERE id=?", (args.finding_id,)).fetchone()
        conn.close()
        if not r:
            print(f"Finding {args.finding_id} not found")
            sys.exit(1)
        poc = generate_poc(dict(r))
        if poc:
            print(json.dumps(poc, indent=2))
    else:
        p.print_help()
