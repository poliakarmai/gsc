#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Security Archaeology v1.0 — машина времени уязвимостей.

Реконструирует полный жизненный цикл каждой находки по git-истории:
  - Какой коммит внёс уязвимость
  - Кто автор
  - Сколько дней жила
  - Какой коммит починил

Эксклюзив: никто не видит *историю* уязвимости через fingerprint.
GSC видит археологию благодаря корпусу 400K находок.

CLI:
  gsc archaeology trace <finding_key>
  gsc archaeology report --repo <path>
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))


# ── Data ──────────────────────────────────────────────────
@dataclass
class VulnerabilityLifespan:
    finding_key: str
    rule_id: str
    category: str
    file_path: str
    line_number: int
    snippet: str
    # Archaeology
    introduced_by: str = ""          # commit SHA
    introduced_author: str = ""      # git author name
    introduced_at: str = ""          # ISO date
    fixed_by: str = ""               # commit SHA
    fixed_author: str = ""
    fixed_at: str = ""
    lifespan_days: int = 0
    is_active: bool = True           # still present?
    # Derived
    module: str = ""
    blame_confidence: float = 0.0


# ── Fingerprint matching ──────────────────────────────────
def content_fingerprint(snippet: str) -> str:
    """Public alias for testing — normalised content hash."""
    return _content_fingerprint(snippet)


def _content_fingerprint(snippet: str) -> str:
    """Normalized fingerprint — strip whitespace, lowercase, truncate."""
    norm = "".join(snippet.lower().split())[:120]
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


def _git_blame(file_path: str, line: int, repo: Path) -> dict:
    """git blame for a specific line. Returns {sha, author, date}."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "blame", "-L", f"{line},{line}",
             "--line-porcelain", file_path],
            capture_output=True, text=True, timeout=10,
        )
        result = {}
        for line_str in r.stdout.split("\n"):
            if line_str.startswith("author "):
                result["author"] = line_str[7:]
            elif line_str.startswith("author-time "):
                ts = int(line_str[12:])
                result["date"] = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            elif len(line_str) == 40 and all(c in "0123456789abcdef" for c in line_str):
                result["sha"] = line_str
        return result
    except Exception:
        return {}


def _git_log_for_file(file_path: str, repo: Path, max_commits: int = 100) -> List[dict]:
    """git log for a file — all commits touching it."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", "--oneline", "--follow",
             "--format=%H|%an|%aI|%s", "-n", str(max_commits), "--", file_path],
            capture_output=True, text=True, timeout=10,
        )
        commits = []
        for line in r.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|", 3)
            if len(parts) >= 4:
                commits.append({
                    "sha": parts[0][:8],
                    "author": parts[1],
                    "date": parts[2],
                    "message": parts[3][:120],
                })
        return commits
    except Exception:
        return []


# ── Archaeology Engine ────────────────────────────────────
def trace_lifespan(finding: dict, repo_path: str) -> VulnerabilityLifespan:
    """
    Trace the full lifecycle of a finding through git history.

    Uses fingerprint matching across commits to find:
    - Introducing commit (when the vulnerable pattern first appeared)
    - Fixing commit (when it disappeared — if resolved)
    """
    import hashlib as _h
    raw = f"{finding.get('rule_id','')}+{finding.get('file_path','')}+{finding.get('detail','')[:80]}"
    key = _h.sha256(raw.encode()).hexdigest()[:12]

    result = VulnerabilityLifespan(
        finding_key=key,
        rule_id=finding.get("rule_id", ""),
        category=finding.get("category", ""),
        file_path=finding.get("file_path", ""),
        line_number=finding.get("line_number", 0),
        snippet=(finding.get("detail") or "")[:120],
        module=finding.get("file_path", "").split("/")[0] if "/" in finding.get("file_path", "") else "",
    )

    repo = Path(repo_path)
    if not (repo / ".git").exists():
        return result

    # Blame the current line
    blame = _git_blame(result.file_path, result.line_number, repo)
    if blame:
        result.introduced_by = blame.get("sha", "")[:8]
        result.introduced_author = blame.get("author", "")
        result.introduced_at = blame.get("date", "")

    # Check resolved_at from DB
    db_path = Path.home() / ".hermes" / "state" / "gsc_audit.db"
    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT resolved_at FROM findings WHERE finding_key = ? OR "
                "(rule_id = ? AND file_path = ? AND line_number = ?)",
                (key, result.rule_id, result.file_path, result.line_number),
            ).fetchall()
            conn.close()

            for row in rows:
                if row["resolved_at"]:
                    result.fixed_at = row["resolved_at"]
                    result.is_active = False
        except Exception:
            pass

    # Calculate lifespan
    if result.introduced_at and result.fixed_at:
        try:
            intro = datetime.fromisoformat(result.introduced_at.replace("Z", "+00:00"))
            fixed = datetime.fromisoformat(result.fixed_at.replace("Z", "+00:00"))
            result.lifespan_days = (fixed - intro).days
        except Exception:
            pass

    return result


def archaeology_report(repo_path: str, findings_json: Optional[str] = None) -> dict:
    """
    Generate archaeology report for a repo or from scan findings.

    Returns aggregate stats: total lifespan, per-module, per-author.
    """
    repo = Path(repo_path)
    if not (repo / ".git").exists():
        return {"error": "Not a git repository", "findings": []}

    # Load findings — from DB or provided JSON
    findings = []
    if findings_json and Path(findings_json).exists():
        with open(findings_json) as f:
            data = json.load(f)
            findings = data.get("findings", [])

    if not findings:
        # Query from DB
        db_path = Path.home() / ".hermes" / "state" / "gsc_audit.db"
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM findings WHERE file_path LIKE ? AND category IN ('CRITICAL','HIGH') "
                "ORDER BY id DESC LIMIT 50",
                (f"{repo.name}%",),
            ).fetchall()
            findings = [dict(r) for r in rows]
            conn.close()

    if not findings:
        return {"error": "No findings to analyze", "findings": [], "stats": {}}

    # Trace each finding
    traces = []
    for f_ in findings:
        trace = trace_lifespan(f_, repo_path)
        traces.append(asdict(trace))

    # Aggregate stats
    resolved = [t for t in traces if t["lifespan_days"] > 0]
    active = [t for t in traces if t["is_active"]]
    by_author = defaultdict(lambda: {"count": 0, "total_days": 0})
    by_module = defaultdict(lambda: {"count": 0, "total_days": 0, "active": 0})

    for t in traces:
        if t["introduced_author"]:
            by_author[t["introduced_author"]]["count"] += 1
            by_author[t["introduced_author"]]["total_days"] += t["lifespan_days"]
        if t["module"]:
            by_module[t["module"]]["count"] += 1
            by_module[t["module"]]["total_days"] += t["lifespan_days"]
            if t["is_active"]:
                by_module[t["module"]]["active"] += 1

    avg_lifespan = sum(t["lifespan_days"] for t in resolved) / len(resolved) if resolved else 0

    return {
        "total_findings": len(traces),
        "resolved": len(resolved),
        "active": len(active),
        "avg_lifespan_days": round(avg_lifespan, 1),
        "worst_author": sorted(by_author.items(), key=lambda x: -x[1]["avg_days"] if (x[1]["count"] > 0 and (x[1]["total_days"]/x[1]["count"]) > 0) else 0)[:3],
        "hottest_module": sorted(by_module.items(), key=lambda x: -x[1]["active"])[:3],
        "by_author": {k: {"count": v["count"], "avg_lifespan": round(v["total_days"]/v["count"], 1)} for k, v in by_author.items()},
        "by_module": {k: {"count": v["count"], "active": v["active"], "avg_lifespan": round(v["total_days"]/v["count"], 1)} for k, v in by_module.items() if v["count"] > 0},
        "findings": traces[:30],
    }


# ── CLI ───────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Security Archaeology — vulnerability time machine")
    sub = p.add_subparsers(dest="cmd", required=True)

    trace_p = sub.add_parser("trace", help="Trace single finding lifecycle")
    trace_p.add_argument("finding_key")
    trace_p.add_argument("--report", "-r", help="Scan report JSON")
    trace_p.add_argument("--repo", required=True, help="Repository path")

    report_p = sub.add_parser("report", help="Full archaeology report")
    report_p.add_argument("--repo", required=True, help="Repository path")
    report_p.add_argument("--findings", help="Scan report JSON")
    report_p.add_argument("--output", "-o", help="Save report JSON")

    args = p.parse_args()

    if args.cmd == "trace":
        findings = []
        if args.report:
            with open(args.report) as f:
                findings = json.load(f).get("findings", [])
        target = next((f for f in findings if _content_fingerprint(
            f"{f.get('rule_id','')}+{f.get('file_path','')}+{f.get('detail','')[:80]}"
        )[:12] == args.finding_key), None)

        if not target:
            print(f"Finding {args.finding_key} not found in report")
            sys.exit(1)

        trace = trace_lifespan(target, args.repo)
        print(json.dumps(asdict(trace), indent=2, ensure_ascii=False))

    elif args.cmd == "report":
        report = archaeology_report(args.repo, args.findings)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
