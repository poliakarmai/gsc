#!/usr/bin/env python3
"""GSC Inline PR Comments — post findings as GitHub PR review comments."""
import os, sys, json, sqlite3
from pathlib import Path

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")


def get_pr_findings(project: str, limit: int = 10) -> list[dict]:
    """Get top CRITICAL+HIGH findings for PR comment."""
    if not Path(DB).exists():
        return []
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT * FROM findings
        WHERE project = ? AND status = 'open'
          AND category IN ('CRITICAL', 'HIGH')
        ORDER BY CASE category WHEN 'CRITICAL' THEN 0 ELSE 1 END
        LIMIT ?
    """, (project, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def format_pr_comment(findings: list[dict]) -> str:
    """Format findings as a GitHub PR review comment."""
    if not findings:
        return "## 🔒 GSC Audit\n\n✅ No critical or high findings."

    crit = [f for f in findings if f['category'] == 'CRITICAL']
    high = [f for f in findings if f['category'] == 'HIGH']

    lines = [
        f"## 🔒 GSC Audit — {len(findings)} findings",
        "",
    ]

    if crit:
        lines.append(f"### 🔴 Critical ({len(crit)})")
        for f in crit:
            fp = f.get('file_path', '?')
            ln = f.get('line_number', 0)
            lines.append(f"- **{f['title']}** — `{fp}:{ln}`")
            if f.get('detail'):
                lines.append(f"  {f['detail'][:120]}")
        lines.append("")

    if high:
        lines.append(f"### 🟠 High ({len(high)})")
        for f in high[:5]:
            fp = f.get('file_path', '?')
            ln = f.get('line_number', 0)
            lines.append(f"- **{f['title']}** — `{fp}:{ln}`")
        lines.append("")

    lines.extend([
        "---",
        f"*GSC v0.4 — [poliakarmai/gsc](https://github.com/poliakarmai/gsc)*",
    ])
    return "\n".join(lines)


def post_pr_comment(project: str, github_token: str = None):
    """Post findings as a PR comment via GitHub API."""
    token = github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("No GitHub token available — skipping PR comment")
        return

    # Detect PR context
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    pr_number = None
    repo = os.environ.get("GITHUB_REPOSITORY", "")

    if event_path and Path(event_path).exists():
        event = json.loads(Path(event_path).read_text())
        pr_number = event.get("pull_request", {}).get("number") or event.get("number")

    if not pr_number or not repo:
        # Not in a PR context — skip
        return

    findings = get_pr_findings(project)
    body = format_pr_comment(findings)

    import requests
    r = requests.post(
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=15
    )

    if r.status_code == 201:
        print(f"✅ Posted PR comment to {repo}#{pr_number}")
    else:
        print(f"❌ Failed to post PR comment: {r.status_code} {r.text[:100]}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="GSC PR Comments")
    p.add_argument("project", help="Project name")
    p.add_argument("--token", help="GitHub token (or use GITHUB_TOKEN env)")
    args = p.parse_args()
    post_pr_comment(args.project, args.token)
