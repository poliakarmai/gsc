#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Workspace — multi-repo project management (Sn1per-inspired).

Workspace = engagement with multiple repos.
Tracks scan history, generates aggregate reports.

CLI:
  gsc workspace create <name>
  gsc workspace add <name> <repo-url|path>
  gsc workspace scan <name> [--scan-mode quick|standard|deep]
  gsc workspace report <name> [--format json|markdown|pdf]
  gsc workspace list
  gsc workspace delete <name>
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GSC_HOME = Path.home() / ".gsc"
WORKSPACE_DB = GSC_HOME / "workspaces.db"


def _connect() -> sqlite3.Connection:
    GSC_HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(WORKSPACE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspace_repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_name TEXT NOT NULL,
            repo_url TEXT NOT NULL,
            alias TEXT,
            added_at TEXT NOT NULL,
            FOREIGN KEY (workspace_name) REFERENCES workspaces(name) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS workspace_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_name TEXT NOT NULL,
            repo_url TEXT NOT NULL,
            scan_mode TEXT DEFAULT 'standard',
            findings_critical INTEGER DEFAULT 0,
            findings_high INTEGER DEFAULT 0,
            findings_medium INTEGER DEFAULT 0,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT DEFAULT 'running',
            report_path TEXT,
            FOREIGN KEY (workspace_name) REFERENCES workspaces(name) ON DELETE CASCADE
        );
    """)
    return conn


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
def workspace_create(name: str, description: str = "") -> bool:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO workspaces (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (name, description, _utcnow(), _utcnow()),
        )
        conn.commit()
        print(f"✅ Workspace '{name}' created")
        return True
    except sqlite3.IntegrityError:
        print(f"❌ Workspace '{name}' already exists")
        return False
    finally:
        conn.close()


def workspace_add(workspace: str, repo: str, alias: str = "") -> bool:
    conn = _connect()
    try:
        ws = conn.execute("SELECT name FROM workspaces WHERE name = ?", (workspace,)).fetchone()
        if not ws:
            print(f"❌ Workspace '{workspace}' not found")
            return False

        conn.execute(
            "INSERT INTO workspace_repos (workspace_name, repo_url, alias, added_at) VALUES (?, ?, ?, ?)",
            (workspace, repo, alias or repo, _utcnow()),
        )
        conn.commit()
        print(f"✅ Added '{alias or repo}' to workspace '{workspace}'")
        return True
    finally:
        conn.close()


def workspace_list() -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute("""
        SELECT w.name, w.description, w.created_at,
               COUNT(r.id) as repo_count,
               COUNT(s.id) as scan_count
        FROM workspaces w
        LEFT JOIN workspace_repos r ON w.name = r.workspace_name
        LEFT JOIN workspace_scans s ON w.name = s.workspace_name
        GROUP BY w.name
        ORDER BY w.updated_at DESC
    """).fetchall()
    conn.close()

    if not rows:
        print("No workspaces. Create one: gsc workspace create <name>")
        return []

    print(f"{'Workspace':<20} {'Repos':>5} {'Scans':>5} {'Description'}")
    print("-" * 60)
    for r in rows:
        print(f"{r['name']:<20} {r['repo_count']:>5} {r['scan_count']:>5} {r['description'] or ''}")
    return [dict(r) for r in rows]


def workspace_scan(workspace: str, scan_mode: str = "standard",
                   profile: str = "developer-review") -> List[Dict[str, Any]]:
    conn = _connect()
    repos = conn.execute(
        "SELECT repo_url, alias FROM workspace_repos WHERE workspace_name = ?",
        (workspace,),
    ).fetchall()

    if not repos:
        print(f"❌ No repos in workspace '{workspace}'. Add with: gsc workspace add {workspace} <url>")
        conn.close()
        return []

    script = Path(__file__).parent / "gsc_external.py"
    results = []

    for repo_row in repos:
        repo = repo_row["repo_url"]
        alias = repo_row["alias"] or repo
        scan_id = conn.execute(
            "INSERT INTO workspace_scans (workspace_name, repo_url, scan_mode, started_at, status) VALUES (?, ?, ?, ?, 'running')",
            (workspace, repo, scan_mode, _utcnow()),
        ).lastrowid
        conn.commit()

        print(f"\n🔍 Scanning {alias} ({scan_mode} mode)...")
        try:
            proc = subprocess.run(
                [sys.executable, str(script), "scan", repo,
                 "--scan-mode", scan_mode, "--profile", profile,
                 "--format", "json", "--output", str(GSC_HOME / "workspace_output")],
                capture_output=True, text=True, timeout=600,
            )
            status = "completed" if proc.returncode == 0 else "failed"

            # Count findings from output
            findings = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
            for line in proc.stdout.splitlines() + proc.stderr.splitlines():
                for sev in findings:
                    if sev in line:
                        findings[sev] += 1

            conn.execute(
                "UPDATE workspace_scans SET status=?, finished_at=?, findings_critical=?, findings_high=?, findings_medium=? WHERE id=?",
                (status, _utcnow(), findings["CRITICAL"], findings["HIGH"], findings["MEDIUM"], scan_id),
            )
            conn.commit()

            icon = "✅" if status == "completed" else "❌"
            print(f"  {icon} {alias}: {findings['CRITICAL']}C {findings['HIGH']}H {findings['MEDIUM']}M")
            results.append({"repo": alias, "status": status, **findings})
        except subprocess.TimeoutExpired:
            conn.execute("UPDATE workspace_scans SET status='timeout', finished_at=? WHERE id=?", (_utcnow(), scan_id))
            conn.commit()
            print(f"  ⏰ {alias}: timeout")
            results.append({"repo": alias, "status": "timeout"})
        except Exception as e:
            conn.execute("UPDATE workspace_scans SET status='error', finished_at=? WHERE id=?", (_utcnow(), scan_id))
            conn.commit()
            print(f"  ❌ {alias}: {e}")
            results.append({"repo": alias, "status": "error"})

    conn.close()
    return results


def workspace_report(workspace: str, fmt: str = "markdown") -> str:
    conn = _connect()
    scans = conn.execute(
        "SELECT * FROM workspace_scans WHERE workspace_name = ? ORDER BY started_at DESC",
        (workspace,),
    ).fetchall()
    conn.close()

    if not scans:
        return f"No scans for workspace '{workspace}'"

    if fmt == "json":
        return json.dumps([dict(s) for s in scans], ensure_ascii=False, indent=2)

    # Markdown report
    total_c = sum(s["findings_critical"] for s in scans)
    total_h = sum(s["findings_high"] for s in scans)
    total_m = sum(s["findings_medium"] for s in scans)

    lines = [
        f"# GSC Workspace Report: {workspace}",
        f"Generated: {_utcnow()}",
        "",
        f"## Summary",
        f"- Scans: {len(scans)}",
        f"- CRITICAL: {total_c}",
        f"- HIGH: {total_h}",
        f"- MEDIUM: {total_m}",
        "",
        "## Scans",
        "| Repo | Mode | Status | C | H | M | Started |",
        "|------|------|--------|---|---|---|---------|",
    ]
    for s in scans:
        started = s["started_at"][:16] if s["started_at"] else "-"
        lines.append(
            f"| {s['repo_url'][:40]} | {s['scan_mode']} | {s['status']} | "
            f"{s['findings_critical']} | {s['findings_high']} | {s['findings_medium']} | {started} |"
        )

    return "\n".join(lines)


def workspace_delete(name: str) -> bool:
    conn = _connect()
    conn.execute("DELETE FROM workspace_scans WHERE workspace_name = ?", (name,))
    conn.execute("DELETE FROM workspace_repos WHERE workspace_name = ?", (name,))
    conn.execute("DELETE FROM workspaces WHERE name = ?", (name,))
    deleted = conn.total_changes > 0
    conn.commit()
    conn.close()
    if deleted:
        print(f"✅ Workspace '{name}' deleted")
    else:
        print(f"❌ Workspace '{name}' not found")
    return deleted


# ---------------------------------------------------------------------------
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Workspace Manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    cr = sub.add_parser("create", help="Create workspace")
    cr.add_argument("name")
    cr.add_argument("--description", default="")

    ad = sub.add_parser("add", help="Add repo to workspace")
    ad.add_argument("workspace")
    ad.add_argument("repo")
    ad.add_argument("--alias", default="")

    sc = sub.add_parser("scan", help="Scan all repos in workspace")
    sc.add_argument("workspace")
    sc.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="standard")
    sc.add_argument("--profile", default="developer-review")

    rep = sub.add_parser("report", help="Generate workspace report")
    rep.add_argument("workspace")
    rep.add_argument("--format", choices=["json", "markdown"], default="markdown")

    sub.add_parser("list", help="List workspaces")

    dl = sub.add_parser("delete", help="Delete workspace")
    dl.add_argument("name")

    args = p.parse_args()

    if args.cmd == "create":
        workspace_create(args.name, args.description)
    elif args.cmd == "add":
        workspace_add(args.workspace, args.repo, args.alias)
    elif args.cmd == "scan":
        workspace_scan(args.workspace, args.scan_mode, args.profile)
    elif args.cmd == "report":
        print(workspace_report(args.workspace, args.format))
    elif args.cmd == "list":
        workspace_list()
    elif args.cmd == "delete":
        workspace_delete(args.name)


if __name__ == "__main__":
    main()
