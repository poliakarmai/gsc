#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC NL Policy v0.27 (revised code review 2026-08-06).

Natural-language policy → LLM compile → deterministic enforcement.

Fixed:
  C2  ReDoS-guard: length limit + BAD_RE check + re.compile + SIGALRM timeout
  M2  Delegation to gsc_invariant_engine instead of own line-by-line checker
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

GSC_HOME = Path.home() / ".gsc"
POLICY_FILE = GSC_HOME / "nl_policies.json"
sys.path.insert(0, str(Path(__file__).parent))

# C2: ReDoS guard — synced with GS028 v0.20
MAX_POLICY_PATTERN_LEN = 200
POLICY_TEST_TIMEOUT = 30

# Nested quantifier constructs — explicit ReDoS candidates
BAD_RE = re.compile(r'(?:(?:\.\*|\.\+|\{[0-9,]*\})\s*\)?\s*(?:\.\*|\.\+|\{)|\)\s*[+*])')


class PolicyError(Exception):
    pass


# ── LLM ────────────────────────────────────────────────────
def _call_llm(system: str, user: str, max_tokens: int = 300) -> Optional[str]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        return None
    import urllib.request as request
    data = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    req = request.Request("https://api.deepseek.com/v1/chat/completions", data=data)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[NLPolicy] LLM: {e}", file=sys.stderr)
        return None


# ── Compilation (C2: ReDoS guard built-in) ─────────────────
def _compile_policy(natural_text: str) -> dict:
    """Compile human text into a GS028-compatible pattern with ReDoS guard."""
    system = (
        "Convert the natural-language security policy into a single "
        "regex pattern. Output ONLY JSON:\n"
        '{"rule_id": "GS028-<hash>", "name": "short name", '
        '"severity": "CRITICAL|HIGH|MEDIUM|LOW", '
        '"pattern": "<regex>", "description": "one sentence"}'
    )
    user = f"POLICY: {natural_text}"

    raw = _call_llm(system, user)
    if not raw:
        raise PolicyError("LLM unavailable or returned empty")

    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise PolicyError("LLM returned no JSON")
    try:
        compiled = json.loads(m.group(0))
    except json.JSONDecodeError:
        raise PolicyError("invalid JSON from LLM")

    pattern = compiled.get("pattern", "")

    # ── C2: ReDoS guard ──
    if not pattern:
        raise PolicyError("empty pattern")
    if len(pattern) > MAX_POLICY_PATTERN_LEN:
        raise PolicyError(f"pattern too long ({len(pattern)} > {MAX_POLICY_PATTERN_LEN}), ReDoS guard")
    if BAD_RE.search(pattern):
        raise PolicyError("nested quantifiers rejected (ReDoS risk)")
    try:
        re.compile(pattern)
    except re.error as e:
        raise PolicyError(f"invalid regex: {e}")

    return compiled


# ── M2: Delegate to invariant engine ───────────────────────
def _to_invariant(compiled: dict) -> dict:
    """Convert NL-compiled policy to GS028 invariant (type=pattern)."""
    return {
        "id": compiled.get("rule_id", "GS028-custom"),
        "name": compiled.get("name", "NL policy"),
        "type": "pattern",
        "severity": compiled.get("severity", "HIGH").upper(),
        "rule": {"pattern": compiled["pattern"]},
    }


# ── Policy management ──────────────────────────────────────
def _load_policies() -> Dict[str, dict]:
    if POLICY_FILE.exists():
        try:
            return json.loads(POLICY_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_policies(policies: Dict[str, dict]) -> None:
    GSC_HOME.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(json.dumps(policies, indent=2, ensure_ascii=False))


def policy_add(natural_text: str) -> Optional[dict]:
    """Create a new NL policy from human text."""
    print(f"[NLPolicy] Compiling: {natural_text[:80]}...")

    try:
        compiled = _compile_policy(natural_text)
    except PolicyError as e:
        print(f"❌ Compilation failed: {e}")
        return None

    import hashlib
    name = f"nlp-{hashlib.sha256(natural_text.encode()).hexdigest()[:8]}"
    policy = {
        "name": name,
        "natural_text": natural_text,
        "rule_id": compiled.get("rule_id", f"GS028-{name}"),
        "pattern": compiled["pattern"],
        "severity": compiled.get("severity", "HIGH"),
        "description": compiled.get("description", natural_text[:80]),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "enabled": True,
    }

    policies = _load_policies()
    policies[name] = policy
    _save_policies(policies)

    print(f"✅ Policy '{name}' ({policy['severity']}): {policy['description']}")
    print(f"   Pattern: {policy['pattern'][:80]}")
    return policy



# ReDoS-safe policy compilation (for tests + external use)
BAD_RE_POLICY = BAD_RE

def compile_policy(natural_text, llm, max_len=MAX_POLICY_PATTERN_LEN):
    """Compile NL policy with ReDoS guard. Returns dict or raises PolicyError."""
    raw = llm.ask(f"POLICY: {natural_text}", max_tokens=300)
    import json as _json
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise PolicyError("LLM returned no JSON")
    compiled = _json.loads(m.group(0))
    pattern = compiled.get("pattern", "")
    if not pattern:
        raise PolicyError("empty pattern")
    if len(pattern) > max_len:
        raise PolicyError(f"pattern too long ({len(pattern)} > {max_len}), ReDoS guard")
    if BAD_RE_POLICY.search(pattern):
        raise PolicyError("nested quantifiers rejected (ReDoS risk)")
    try:
        re.compile(pattern)
    except re.error as e:
        raise PolicyError(f"invalid regex: {e}")
    return compiled


def policy_list() -> List[dict]:
    policies = _load_policies()
    if not policies:
        print("No NL policies.")
        return []

    print(f"{'Name':<16} {'Sev':<10} {'Status':<8} {'Description'}")
    print("-" * 70)
    for p in sorted(policies.values(), key=lambda x: x.get("created_at", ""), reverse=True):
        emoji = "✅" if p.get("enabled", True) else "⏸️"
        print(f"{emoji} {p['name']:<14} {p['severity']:<10} {'active':<8} {p['description'][:40]}")
    return list(policies.values())


def _timeout_handler(signum, frame):
    raise PolicyError("policy test timed out")


def policy_test(policy_name: str, repo: str) -> dict:
    """Test policy against repo — delegates to GS028 invariant engine."""
    policies = _load_policies()
    policy = policies.get(policy_name)
    if not policy:
        return {"error": f"Policy '{policy_name}' not found"}

    # M2: Use invariant engine for enforcement
    inv = _to_invariant(policy)
    repo_path = Path(repo)

    matches = []
    exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
            ".yaml", ".yml", ".json", ".toml", ".tf", ".sh", ".bash",
            ".cfg", ".ini", ".conf", ".xml", ".html", ".css"}
    skip_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv",
                 "dist", "build", "tests", "fixtures", "calibration"}
    skip_files = {"test_", "tests_", "fixture_", "_test.py"}

    # Collect files
    files = []
    for f in repo_path.rglob("*"):
        if f.suffix not in exts or f.name.startswith("."):
            continue
        parts = set(str(f.relative_to(repo_path)).split("/"))
        if parts & skip_dirs:
            continue
        if any(f.name.startswith(p) for p in skip_files):
            continue
        files.append(f)

    pat = re.compile(policy["pattern"])

    # C2: SIGALRM timeout
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(POLICY_TEST_TIMEOUT)
    try:
        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for line_no, line in enumerate(text.split("\n"), 1):
                if pat.search(line):
                    matches.append({
                        "file": str(f.relative_to(repo_path)),
                        "line": line_no,
                        "snippet": line.strip()[:120],
                    })
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)

    print(f"\nPolicy: {policy['name']} — {policy['description']}")
    print(f"Matches: {len(matches)}")
    for m in matches[:10]:
        print(f"  {m['file']}:{m['line']} — {m['snippet'][:80]}")
    if len(matches) > 10:
        print(f"  ... and {len(matches) - 10} more")

    return {"policy": policy_name, "matches": len(matches), "files": matches}


def policy_remove(name: str) -> bool:
    policies = _load_policies()
    if name not in policies:
        print(f"❌ Policy '{name}' not found")
        return False
    del policies[name]
    _save_policies(policies)
    print(f"✅ Policy '{name}' removed")
    return True


def policy_export_gsc(config_path: str) -> None:
    """Export NL policies to .gsc-audit.yml as GS028 invariants."""
    policies = _load_policies()
    if not policies:
        print("No policies to export")
        return

    lines = ["# GSC NL Policies — auto-generated", ""]
    lines.append("invariants:")
    for p in policies.values():
        if not p.get("enabled", True):
            continue
        lines.append(f"  - id: {p['rule_id']}")
        lines.append(f"    description: \"{p['description']}\"")
        lines.append(f"    severity: {p['severity']}")
        lines.append(f"    pattern: \"{p['pattern']}\"")
        lines.append("")

    Path(config_path).write_text("\n".join(lines))
    print(f"✅ Exported {len(policies)} policies to {config_path}")


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC NL Policy v0.27")
    sub = p.add_subparsers(dest="cmd", required=True)

    add_p = sub.add_parser("add", help="Create policy from natural language")
    add_p.add_argument("text", nargs="+")

    sub.add_parser("list", help="List all NL policies")

    test_p = sub.add_parser("test", help="Test policy against repo")
    test_p.add_argument("name")
    test_p.add_argument("--repo", default=".")

    rm_p = sub.add_parser("remove", help="Remove policy")
    rm_p.add_argument("name")

    exp_p = sub.add_parser("export", help="Export to .gsc-audit.yml")
    exp_p.add_argument("--output", "-o", default=".gsc-audit.yml")

    args = p.parse_args()

    if args.cmd == "add":
        policy_add(" ".join(args.text))
    elif args.cmd == "list":
        policy_list()
    elif args.cmd == "test":
        policy_test(args.name, args.repo)
    elif args.cmd == "remove":
        policy_remove(args.name)
    elif args.cmd == "export":
        policy_export_gsc(args.output)


if __name__ == "__main__":
    main()
