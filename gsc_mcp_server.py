#!/usr/bin/env python3
"""GSC MCP server — read-only security tools for AI coding agents.

Exposes GSC to Claude / Cursor / Copilot-style agents over Model Context Protocol.
Destructive actions (auto-patch, PR) are intentionally NOT exposed here — they stay
in the human/CLI loop with explicit confirmation (sale-audit P0: read-only MCP).

Tools:
  scan_repo      — run a GSC scan on a local repo, return findings summary + top items.
  list_findings  — quick read of recent findings from the GSC database.
  verify_finding — re-run a finding's PoC in the sandbox, report exploit status.

Run:  python3 gsc_mcp_server.py     (stdio transport)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastmcp import FastMCP

mcp = FastMCP("gsc")


def _severity(f: dict) -> str:
    return (f.get("severity") or f.get("category") or f.get("level") or "unknown")


def _finding_key(f: dict) -> str:
    return f.get("finding_key") or f.get("key") or ""


@mcp.tool()
def scan_repo(repo_path: str, profile: str = "audit", scan_mode: str = "standard") -> dict:
    """Run a GSC security scan on a local repository path and return a summary.

    Args:
        repo_path: absolute or relative path to the repository to scan.
        profile: scan profile (audit, developer-review, ci).
        scan_mode: quick (regex-only) | standard (LLM revalidate) | deep (chains).
    """
    from gsc_external import run_external_scan

    res = run_external_scan(repo_path, profile_name=profile, scan_mode=scan_mode)
    findings = list(getattr(res, "findings", []) or [])

    by_sev: dict[str, int] = {}
    for f in findings:
        s = _severity(f)
        by_sev[s] = by_sev.get(s, 0) + 1

    return {
        "repo": repo_path,
        "profile": profile,
        "scan_mode": scan_mode,
        "total_findings": len(findings),
        "by_severity": by_sev,
        "top": [
            {
                "finding_key": _finding_key(f),
                "rule_id": f.get("rule_id"),
                "severity": _severity(f),
                "file": f.get("file_path") or f.get("file"),
                "line": f.get("line_number") or f.get("line"),
                "title": f.get("title"),
                "has_poc": bool((f.get("metadata") or {}).get("poc")),
            }
            for f in findings[:20]
        ],
    }


@mcp.tool()
def list_findings(limit: int = 20, project: str = "") -> list[dict]:
    """List recent findings from the GSC database (fast, no scan).

    Args:
        limit: max number of findings (default 20, max 100).
        project: optional project name filter.
    """
    from gsc_db import GSCDatabase

    limit = max(1, min(int(limit), 100))
    db = GSCDatabase()
    db.__enter__()
    try:
        if project:
            rows = db.query(
                "SELECT finding_key, rule_id, category, title, file_path, line_number, "
                "status, confidence_score FROM findings WHERE project=? "
                "ORDER BY id DESC LIMIT ?",
                (project, limit),
            )
        else:
            rows = db.query(
                "SELECT finding_key, rule_id, category, title, file_path, line_number, "
                "status, confidence_score FROM findings ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in rows]
    finally:
        db.__exit__(None, None, None)


@mcp.tool()
def verify_finding(repo_path: str, finding_key: str) -> dict:
    """Re-run a finding's PoC in the sandbox and report whether the exploit still works.

    Scans the repo (to reconstruct the finding), locates the PoC, executes it in the
    isolated sandbox and returns the result. Read-only w.r.t. the host system.
    """
    from gsc_external import run_external_scan
    from gsc_pof_sandbox import PoFSandbox

    res = run_external_scan(repo_path, profile_name="audit", scan_mode="standard")
    findings = list(getattr(res, "findings", []) or [])

    target = None
    for f in findings:
        if _finding_key(f) == finding_key:
            target = f
            break
    if target is None:
        return {"error": f"finding not found: {finding_key}", "repo": repo_path}

    meta = target.get("metadata") or {}
    poc = meta.get("poc")
    if not poc:
        return {"error": "no PoC attached to this finding", "finding_key": finding_key}

    fmt = meta.get("poc_format", "python")
    src = target.get("snippet") or target.get("detail") or ""
    r = PoFSandbox()._execute(poc, src, fmt=fmt)

    return {
        "finding_key": finding_key,
        "rule_id": target.get("rule_id"),
        "severity": _severity(target),
        "file": target.get("file_path") or target.get("file"),
        "exploit_success": r.success,
        "exit_code": r.exit_code,
        "stdout": r.stdout[:2000],
        "stderr": r.stderr[:500],
    }


if __name__ == "__main__":
    mcp.run()
