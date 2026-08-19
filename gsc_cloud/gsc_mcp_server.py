#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC MCP server — read-only security tools for AI coding agents.

Exposes GSC to Claude / Cursor / Copilot-style agents over Model Context Protocol.
Destructive actions (auto-patch, PR) are intentionally NOT exposed here — they stay
in the human/CLI loop with explicit confirmation (sale-audit P0: read-only MCP).

Tools:
  scan_repo      — run a GSC scan on a local repo, return findings summary + top items.
  list_findings  — quick read of recent findings from the GSC database.
  verify_finding — re-run a finding's PoC in the sandbox, report exploit status.

Security (ADR-0001 trigger activated):
  - Auth: ``GSCMCPAuth`` (Bearer token) on HTTP/SSE transport — ``GSC_MCP_TOKEN``
    (on-prem) or a ``gsk_`` key via ``GSC_DATABASE_URL`` (cloud). Fail-closed.
  - Path scoping: ``resolve_repo_path`` rejects paths outside ``GSC_ALLOWED_ROOTS``.

Run:
  python3 gsc_mcp_server.py                       # stdio (local, trusted)
  GSC_MCP_TOKEN=... python3 gsc_mcp_server.py --transport http --host 0.0.0.0 --port 8001
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token, get_context

from gsc_cloud.gsc_mcp_auth import GSCMCPAuth, auth_configured, resolve_repo_path

mcp = FastMCP("gsc", auth=GSCMCPAuth())


def _severity(f: dict) -> str:
    return (f.get("severity") or f.get("category") or f.get("level") or "unknown")


def _finding_key(f: dict) -> str:
    return f.get("finding_key") or f.get("key") or ""


def _caller() -> dict:
    """Best-effort: tenant_id from token + client_id of the agent (for audit)."""
    info: dict = {"tenant_id": None, "client_id": None}
    try:
        tok = get_access_token()
        if tok is not None:
            claims = getattr(tok, "claims", None) or {}
            info["tenant_id"] = claims.get("tenant_id")
    except Exception:
        pass
    try:
        ctx = get_context()
        cid = getattr(ctx, "client_id", None)
        if cid:
            info["client_id"] = cid
    except Exception:
        pass
    return info


@mcp.tool()
def scan_repo(repo_path: str, profile: str = "audit", scan_mode: str = "standard") -> dict:
    """Run a GSC security scan on a local repository path and return a summary.

    Args:
        repo_path: absolute or relative path to the repository to scan.
        profile: scan profile (audit, developer-review, ci).
        scan_mode: quick (regex-only) | standard (LLM revalidate) | deep (chains).
    """
    resolved, err = resolve_repo_path(repo_path)
    if err:
        return {"error": err, "repo_path": repo_path}

    from gsc_external import run_external_scan

    res = run_external_scan(str(resolved), profile_name=profile, scan_mode=scan_mode)
    findings = list(getattr(res, "findings", []) or [])

    by_sev: dict[str, int] = {}
    for f in findings:
        s = _severity(f)
        by_sev[s] = by_sev.get(s, 0) + 1

    return {
        "repo": str(resolved),
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
        "_audit": _caller(),
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
    resolved, err = resolve_repo_path(repo_path)
    if err:
        return {"error": err, "repo_path": repo_path, "finding_key": finding_key}

    from gsc_external import run_external_scan
    from gsc_pof_sandbox import PoFSandbox

    res = run_external_scan(str(resolved), profile_name="audit", scan_mode="standard")
    findings = list(getattr(res, "findings", []) or [])

    target = None
    for f in findings:
        if _finding_key(f) == finding_key:
            target = f
            break
    if target is None:
        return {"error": f"finding not found: {finding_key}", "repo": str(resolved)}

    meta = target.get("metadata") or {}
    poc = meta.get("poc")
    if not poc:
        return {"error": "no PoC attached to this finding", "finding_key": finding_key}

    fmt = meta.get("poc_format", "python")

    # C-01 (audit): PoC must run against the REAL source file/project, not a
    # stripped snippet/detail — a SAFE on a snippet means "snippet didn't run",
    # not "vuln not exploitable". Resolve file_path against the repo root and
    # pass project_dir so curl PoCs get a live multi-module server.
    project_root = os.path.abspath(str(resolved))
    file_path = target.get("file_path") or target.get("file") or ""
    src = ""
    src_from_file = False
    if file_path:
        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path(project_root) / fp
        try:
            src = fp.read_text(errors="replace")
            src_from_file = True
        except OSError:
            src = ""
    if not src:
        src = target.get("snippet") or target.get("detail") or ""

    try:
        r = PoFSandbox()._execute(poc, src, fmt=fmt, project_dir=project_root)
    except Exception as e:  # sandbox/runner failure — do not report as SAFE
        return {
            "finding_key": finding_key,
            "rule_id": target.get("rule_id"),
            "severity": _severity(target),
            "file": target.get("file_path") or target.get("file"),
            "status": "execution_error",
            "error": str(e),
            "_audit": _caller(),
        }

    status = "verified" if r.success else "not_reproducible"

    return {
        "finding_key": finding_key,
        "rule_id": target.get("rule_id"),
        "severity": _severity(target),
        "file": target.get("file_path") or target.get("file"),
        "status": status,
        "source": "file" if src_from_file else "snippet-fallback",
        "exploit_success": r.success,
        "exit_code": r.exit_code,
        "stdout": r.stdout[:2000],
        "stderr": r.stderr[:500],
        "_audit": _caller(),
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="GSC MCP server (read-only security tools)")
    ap.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        default="stdio",
        help="stdio (default, local trusted) | http (streamable) | sse",
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    args = ap.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        if not auth_configured():
            raise SystemExit(
                f"{args.transport.upper()} transport requires auth "
                "(GSC_MCP_TOKEN or GSC_DATABASE_URL) — fail-closed (ADR-0001)."
            )
        mcp.run(transport=args.transport, host=args.host, port=args.port)
