#!/usr/bin/env python3
"""
GSC Exploit Chain Composer v1.0.

Composes individual findings into attack chains.
A chain of 3 LOW findings can be more dangerous than 1 HIGH.
Chain severity may exceed max(individual severities).

Key insight: scanners evaluate findings in isolation.
Real attackers chain them. GSC bridges that gap.

Usage:
  python3 gsc_chain_composer.py scan.json            # analyze scan results
  python3 gsc_chain_composer.py --project gsc         # from DB
"""

import json, hashlib, sys, os, sqlite3
from itertools import combinations
from pathlib import Path
from typing import Optional

GSC_HOME = Path(__file__).resolve().parent
DB_PATH = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_NAMES = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}

CHAIN_BUDGETS = {
    "developer-review": 5,
    "pr-gate": 3,
    "audit": 10,
    "candidate-review": 3,
}


def _get_api_key() -> str:
    if API_KEY:
        return API_KEY
    for p in [Path(os.path.expanduser("~/.hermes/.env")),
              Path(os.path.expanduser("~/.hermes/env"))]:
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    return ""


def _call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 600) -> Optional[str]:
    import urllib.request as _req
    key = _get_api_key()
    if not key:
        return None
    body = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode()
    r = _req.Request("https://api.deepseek.com/v1/chat/completions", data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    })
    try:
        resp = json.loads(_req.urlopen(r, timeout=30).read())
        return resp["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[Chain] LLM call failed: {e}", file=sys.stderr)
        return None


def _read_file(file_path: str, project_dir: str = ".") -> str:
    """Read source file, try multiple base paths."""
    p = Path(file_path)
    if p.is_absolute() and p.exists():
        return p.read_text(errors='replace')
    for base in [Path(project_dir), GSC_HOME, Path.cwd()]:
        candidate = base / file_path
        if candidate.exists():
            return candidate.read_text(errors='replace')
    return "// [file not found]"


def _chain_key(findings: list[dict]) -> str:
    """Stable key: sha256(sorted finding keys)[:12]."""
    keys = sorted(
        f.get("finding_key", f.get("id", "")) for f in findings
    )
    return hashlib.sha256("+".join(str(k) for k in keys).encode()).hexdigest()[:12]


def _max_severity(findings: list[dict]) -> int:
    """Max severity value across findings."""
    return max(
        SEVERITY_ORDER.get(f.get("category", f.get("severity", "LOW")), 0)
        for f in findings
    )


def _file_context(findings: list[dict], project_dir: str = ".", window: int = 15) -> str:
    """Build combined context from source files."""
    seen = set()
    parts = []
    for f in findings:
        fp = f.get("file_path", "")
        if fp in seen:
            continue
        seen.add(fp)
        content = _read_file(fp, project_dir)
        if not content.startswith("//"):
            lines = content.splitlines()
            ln = f.get("line", f.get("line_number", 1)) - 1
            start = max(0, ln - window)
            end = min(len(lines), ln + window + 1)
            parts.append(f"── {fp}:{ln+1} ──\n")
            for i in range(start, end):
                marker = ">>>" if i == ln else "   "
                parts.append(f"{marker} {i+1:4d}| {lines[i]}")
            parts.append("")
    return "\n".join(parts)


def _find_chain_candidates(findings: list[dict], max_chains: int = 20) -> list[list[dict]]:
    """Group findings by file, generate pairs/triplets within same file."""
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file_path", f.get("file", ""))
        by_file.setdefault(fp, []).append(f)

    candidates = []
    for file_finds in by_file.values():
        if len(file_finds) >= 2:
            for pair in combinations(file_finds, 2):
                candidates.append(list(pair))
        if len(file_finds) >= 3:
            for triple in combinations(file_finds, 3):
                candidates.append(list(triple))

    # Sort by max severity desc, then by count desc
    candidates.sort(key=lambda c: (-_max_severity(c), -len(c)))
    return candidates[:max_chains]


def compose_chains(
    findings: list[dict],
    project_dir: str = ".",
    budget: int = 5,
) -> list[dict]:
    """
    Analyze findings for exploitable chains.
    Returns list of chain dicts with: steps, composed_severity, confidence, narrative, chain_key.
    """
    if len(findings) < 2:
        return []

    candidates = _find_chain_candidates(findings)

    system = """You are a security researcher analyzing whether multiple
code-level weaknesses can be chained into a single exploit.

For each chain candidate, determine:
1. Can the weaknesses be composed? (A's output feeds B's input?)
2. What is the combined severity? (may exceed max individual)
3. What is the step-by-step attack narrative?

Respond with JSON:
{"exploitable": true/false, "severity": "LOW|MEDIUM|HIGH|CRITICAL",
 "confidence": 0.0-1.0, "narrative": "step-by-step"}"""

    chains = []
    used_budget = 0

    for cand in candidates:
        if used_budget >= budget:
            break
        used_budget += 1

        # Skip candidates where all findings are INFO or LOW
        if _max_severity(cand) < SEVERITY_ORDER["MEDIUM"]:
            continue

        findings_desc = "\n".join(
            f"[{f.get('category', f.get('severity', '?'))}] "
            f"{f.get('title', f.get('pattern_title', '?'))} "
            f"({f.get('file_path','')}:{f.get('line', f.get('line_number', '?'))})"
            for f in cand
        )
        context = _file_context(cand, project_dir)

        prompt = f"""Can these findings be chained into a single exploit?

Findings:
{findings_desc}

Code context:
```
{context}
```

Respond with the JSON verdict."""

        result = _call_llm(system, prompt)
        if not result:
            continue

        try:
            # Extract JSON from response
            import re
            m = re.search(r'\{[^{}]*"exploitable"[^{}]*\}', result, re.DOTALL)
            if not m:
                continue
            verdict = json.loads(m.group(0))
        except (json.JSONDecodeError, KeyError):
            continue

        if verdict.get("exploitable"):
            composed_sev = verdict.get("severity", "HIGH")
            max_individual = SEVERITY_NAMES.get(_max_severity(cand), "LOW")

            # Chain severity can be higher than max individual
            if SEVERITY_ORDER.get(composed_sev, 0) <= SEVERITY_ORDER.get(max_individual, 0):
                composed_sev = SEVERITY_NAMES.get(
                    min(4, SEVERITY_ORDER.get(max_individual, 0) + 1), "HIGH"
                )

            chains.append({
                "chain_key": _chain_key(cand),
                "steps": [
                    {
                        "finding_key": f.get("finding_key",
                            hashlib.sha256(
                                f"{f.get('file_path','')}+{f.get('line',0)}+{f.get('title','')[:40]}".encode()
                            ).hexdigest()[:12]
                        ),
                        "rule_id": f.get("pattern_title", f.get("rule_id", "?")),
                        "severity": f.get("category", f.get("severity", "LOW")),
                        "file": f.get("file_path", ""),
                        "line": f.get("line", f.get("line_number", 0)),
                    }
                    for f in cand
                ],
                "composed_severity": composed_sev,
                "max_individual_severity": max_individual,
                "confidence": verdict.get("confidence", 0.7),
                "narrative": verdict.get("narrative", ""),
            })

    return chains


# ── CLI ───────────────────────────────────────────────────

def _load_from_db(project: str, limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM findings
        WHERE project = ?
        ORDER BY CASE category
            WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
            WHEN 'MEDIUM' THEN 2 ELSE 3 END
        LIMIT ?
    """, (project, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GSC Exploit Chain Composer")
    p.add_argument("input", nargs="?", help="scan.json or project name (with --project)")
    p.add_argument("--project", help="Load findings from DB instead of JSON")
    p.add_argument("--budget", type=int, default=5, help="Max LLM calls (default: 5)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    if args.project:
        findings = _load_from_db(args.project, limit=50)
        print(f"Loaded {len(findings)} findings for '{args.project}'")
        project_dir = str(GSC_HOME)
    elif args.input:
        with open(args.input) as f:
            data = json.load(f)
        findings = data.get("findings", data) if isinstance(data, dict) else data
        project_dir = str(Path(args.input).parent)
        print(f"Loaded {len(findings)} findings from {args.input}")
    else:
        p.print_help()
        sys.exit(0)

    if len(findings) < 2:
        print("Need at least 2 findings for chain analysis.")
        sys.exit(0)

    chains = compose_chains(findings, project_dir, budget=args.budget)

    if args.json:
        print(json.dumps(chains, indent=2))
    else:
        if not chains:
            print("No exploitable chains found.")
        for c in chains:
            print(f"\n🔗 Chain {c['chain_key']} — {c['composed_severity']} "
                  f"(max individual: {c['max_individual_severity']}, "
                  f"confidence: {c['confidence']:.0%})")
            for s in c["steps"]:
                print(f"  [{s['severity']}] {s['rule_id']} — {s['file']}:{s['line']}")
            print(f"  ╰ {c['narrative'][:120]}")
        print(f"\n📊 {len(chains)} chains found (budget: {args.budget} LLM calls)")
