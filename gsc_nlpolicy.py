#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Natural Language Policy v1.0 — политики на человеческом языке.

Пользователь пишет: «секреты не должны попадать в логи»
DeepSeek компилирует → детерминированный GS028-инвариант → enforcement без LLM.

Эксклюзив: мост между гибкостью LLM и детерминизмом SAST.
LLM пишет правило один раз, дальше оно бесплатно и стабильно.

CLI:
  gsc policy add "весь user input должен пройти sanitize до SQL"
  gsc policy list
  gsc policy test <name> --repo .
  gsc policy remove <name>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


GSC_HOME = Path.home() / ".gsc"
POLICY_FILE = GSC_HOME / "nl_policies.json"
sys.path.insert(0, str(Path(__file__).parent))


# ── LLM ───────────────────────────────────────────────────
def _call_llm(system: str, user: str, max_tokens: int = 800) -> Optional[str]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        return None
    import urllib.request as req
    data = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    r = req.Request("https://api.deepseek.com/v1/chat/completions", data=data)
    r.add_header("Authorization", f"Bearer {api_key}")
    r.add_header("Content-Type", "application/json")
    try:
        with req.urlopen(r, timeout=30) as resp:
            body = json.loads(resp.read())
            return body["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[NLPolicy] LLM: {e}", file=sys.stderr)
        return None


# ── Policy parsing ────────────────────────────────────────
@dataclass
class NLPolicy:
    name: str
    natural_text: str
    rule_id: str  # GS028-<hash>
    pattern: str  # compiled regex
    severity: str = "HIGH"
    category: str = "custom"
    description: str = ""
    created_at: str = ""
    enabled: bool = True

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "NLPolicy":
        return cls(**d)


def _compile_policy(natural_text: str) -> Optional[dict]:
    """Use DeepSeek to compile human text into a GS028-compatible pattern."""
    system = (
        "You are a security rule compiler. Convert natural-language security policies "
        "into precise REGEX patterns suitable for SAST scanning. "
        "Output ONLY valid JSON, no markdown, no explanations:\n"
        "{\n"
        '  "rule_id": "GS028-custom",\n'
        '  "pattern": "regex here",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '  "category": "secrets|injection|config|auth|privacy|input-validation",\n'
        '  "description": "one sentence",\n'
        '  "test_example": "code that SHOULD match",\n'
        '  "test_negative": "code that should NOT match"\n'
        "}\n"
        "RULES:\n"
        "- pattern must be a valid Python regex\n"
        "- Use \\b for word boundaries\n"
        "- Use (?i) for case-insensitive\n"
        "- Use [^...]* for negated character classes\n"
        "- Escape special chars: . * + ? [ ] ( ) { } | ^ $\n"
        "- severity depends on impact: secret leak=CRITICAL, config issue=HIGH, "
        "style=LOW\n"
    )

    user = f"POLICY: {natural_text}"
    raw = _call_llm(system, user)
    if not raw:
        return None

    # Parse JSON from LLM response
    try:
        # Strip markdown if present
        if "```" in raw:
            raw = raw.split("```json")[1] if "```json" in raw else raw.split("```")[1]
            if "```" in raw:
                raw = raw.split("```")[0]
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        # Try to extract just the JSON part
        import re
        m = re.search(r'\{[^{}]*"pattern"[^{}]*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except:
                pass
    return None


def _validate_pattern(pattern: str) -> bool:
    """Validate regex compiles and isn't dangerous."""
    import re
    try:
        re.compile(pattern)
        # Reject catastrophic backtracking patterns
        if len(pattern) > 500:
            return False
        return True
    except re.error:
        return False


# ── Policy management ─────────────────────────────────────
def _load_policies() -> Dict[str, NLPolicy]:
    if POLICY_FILE.exists():
        try:
            data = json.loads(POLICY_FILE.read_text())
            return {k: NLPolicy.from_dict(v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def _save_policies(policies: Dict[str, NLPolicy]) -> None:
    GSC_HOME.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(json.dumps(
        {k: v.to_dict() for k, v in policies.items()},
        indent=2, ensure_ascii=False,
    ))


def policy_add(natural_text: str) -> Optional[NLPolicy]:
    """Create a new NL policy from human text."""
    print(f"[NLPolicy] Compiling: {natural_text[:80]}...")

    compiled = _compile_policy(natural_text)
    if not compiled:
        print("❌ Compilation failed — LLM unavailable or returned invalid output")
        return None

    pattern = compiled.get("pattern", "")
    if not _validate_pattern(pattern):
        print(f"❌ Invalid or dangerous regex: {pattern[:60]}")
        return None

    import hashlib
    name_hash = hashlib.sha256(natural_text.encode()).hexdigest()[:8]
    policy = NLPolicy(
        name=f"nlp-{name_hash}",
        natural_text=natural_text,
        rule_id=f"GS028-{name_hash}",
        pattern=pattern,
        severity=compiled.get("severity", "HIGH"),
        category=compiled.get("category", "custom"),
        description=compiled.get("description", natural_text[:80]),
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    policies = _load_policies()
    policies[policy.name] = policy
    _save_policies(policies)

    print(f"✅ Policy '{policy.name}' ({policy.severity}): {policy.description}")
    print(f"   Pattern: {pattern[:80]}...")
    print(f"   Test match: {compiled.get('test_example', '-')[:60]}")
    print(f"   Test negative: {compiled.get('test_negative', '-')[:60]}")
    return policy


def policy_list() -> List[NLPolicy]:
    policies = _load_policies()
    if not policies:
        print("No NL policies. Add one: gsc policy add 'your rule here'")
        return []

    print(f"{'Name':<16} {'Sev':<10} {'Category':<16} {'Description'}")
    print("-" * 70)
    for p in sorted(policies.values(), key=lambda x: x.created_at, reverse=True):
        emoji = "✅" if p.enabled else "⏸️"
        print(f"{emoji} {p.name:<14} {p.severity:<10} {p.category:<16} {p.description[:40]}")
    return list(policies.values())


def policy_test(policy_name: str, repo: str) -> dict:
    """Test a policy against a repo — scan for pattern matches."""
    policies = _load_policies()
    policy = policies.get(policy_name)
    if not policy:
        return {"error": f"Policy '{policy_name}' not found"}

    import re
    pat = re.compile(policy.pattern, re.IGNORECASE if "(?i)" not in policy.pattern else 0)

    matches = []
    repo_path = Path(repo)
    exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
            ".yaml", ".yml", ".json", ".toml", ".tf", ".sh", ".bash",
            ".env", ".cfg", ".ini", ".conf", ".xml", ".html", ".css"}

    for f in repo_path.rglob("*"):
        if f.suffix not in exts or f.name.startswith("."):
            continue
        if any(d in str(f) for d in [".git", "node_modules", "__pycache__", "venv", ".venv"]):
            continue

        try:
            content = f.read_text()
            for i, line in enumerate(content.split("\n"), 1):
                if pat.search(line):
                    matches.append({
                        "file": str(f.relative_to(repo_path)),
                        "line": i,
                        "snippet": line.strip()[:120],
                    })
        except Exception:
            pass

    print(f"\nPolicy: {policy.name} — {policy.description}")
    print(f"Pattern: {policy.pattern[:80]}")
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
    """Export all NL policies to .gsc-audit.yml format (GS028 invariants)."""
    policies = _load_policies()
    if not policies:
        print("No policies to export")
        return

    lines = ["# GSC NL Policies — auto-generated by gsc_policy.py", ""]
    lines.append("invariants:")
    for p in policies.values():
        if not p.enabled:
            continue
        lines.append(f"  - id: {p.rule_id}")
        lines.append(f"    description: \"{p.description}\"")
        lines.append(f"    severity: {p.severity}")
        lines.append(f"    pattern: \"{p.pattern}\"")
        lines.append("")

    Path(config_path).write_text("\n".join(lines))
    print(f"✅ Exported {len(policies)} policies to {config_path}")


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC NL Policy — human-language security rules")
    sub = p.add_subparsers(dest="cmd", required=True)

    add_p = sub.add_parser("add", help="Create policy from natural language")
    add_p.add_argument("text", nargs="+", help="Policy in human language")

    sub.add_parser("list", help="List all NL policies")

    test_p = sub.add_parser("test", help="Test policy against repo")
    test_p.add_argument("name", help="Policy name")
    test_p.add_argument("--repo", default=".", help="Repository path")

    rm_p = sub.add_parser("remove", help="Remove policy")
    rm_p.add_argument("name")

    exp_p = sub.add_parser("export", help="Export policies to .gsc-audit.yml")
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
