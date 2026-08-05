#!/usr/bin/env python3
"""
GSC PR Comment Scanner — сканирует PR и постит CRITICAL/HIGH находки как комментарии.

Usage:
    python3 gsc_pr_scanner.py --pr <PR_NUMBER> [--repo owner/repo]

Env vars:
    GITHUB_TOKEN — for GitHub API
    GITHUB_REPOSITORY — owner/repo (auto-detected in Actions)
    GITHUB_REF — PR ref (auto-detected in Actions)
"""

import os, sys, json, subprocess, tempfile
from pathlib import Path

GSC = os.path.expanduser("~/gsc/gsc.py")


def get_pr_info() -> dict:
    """Auto-detect PR context from GitHub Actions environment."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        event = json.loads(Path(event_path).read_text())
        if "pull_request" in event:
            pr = event["pull_request"]
            return {
                "number": event.get("number") or pr.get("number"),
                "repo": os.environ.get("GITHUB_REPOSITORY", ""),
                "base_sha": pr.get("base", {}).get("sha", "HEAD~1"),
                "head_sha": pr.get("head", {}).get("sha", "HEAD"),
            }

    # Fallback: try gh CLI
    return {
        "number": os.environ.get("PR_NUMBER", ""),
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "base_sha": "HEAD~1",
        "head_sha": "HEAD",
    }


def run_gsc_scan(repo_path: str = ".") -> list[dict]:
    """Run GSC scan on changed files, return CRITICAL/HIGH findings."""
    try:
        r = subprocess.run(
            [sys.executable, GSC, "scan", repo_path, "--diff", "--json", "--ci"],
            capture_output=True, text=True, timeout=120,
            cwd=repo_path
        )
        if r.returncode == 0 and r.stdout.strip():
            output = r.stdout.strip()
            start = output.find("[")
            if start >= 0:
                end = output.rfind("]") + 1
                if end > start:
                    all_findings = json.loads(output[start:end])
                    return [f for f in all_findings
                            if f.get("category") in ("CRITICAL", "HIGH")]
    except Exception as e:
        print(f"GSC scan error: {e}", file=sys.stderr)
    return []


def format_comment(findings: list[dict]) -> str:
    """Format findings as a GitHub-compatible Markdown comment."""
    if not findings:
        return ""

    critical = [f for f in findings if f.get("category") == "CRITICAL"]
    high = [f for f in findings if f.get("category") == "HIGH"]

    lines = [
        "## 🔒 GSC Security Scan",
        "",
        f"**{len(critical)} CRITICAL** · **{len(high)} HIGH** findings in this PR.",
        "",
    ]

    if critical:
        lines.append("### 🚨 CRITICAL")
        for f in critical:
            fp = f.get("file_path", "?")
            ln = f.get("line_number", "?")
            title = f.get("title", "?")
            detail = (f.get("detail") or "")[:200]
            lines.append(f"- **`{fp}:{ln}`** — {title}")
            if detail:
                lines.append(f"  > {detail}")
        lines.append("")

    if high:
        lines.append("### ⚠️ HIGH")
        for f in high[:5]:  # Limit to top 5 HIGH
            fp = f.get("file_path", "?")
            ln = f.get("line_number", "?")
            title = f.get("title", "?")
            lines.append(f"- **`{fp}:{ln}`** — {title}")
        if len(high) > 5:
            lines.append(f"- ... and {len(high) - 5} more")
        lines.append("")

    lines.extend([
        "---",
        f"*Scanned by [GSC](https://github.com/poliakarmai/gsc) · "
        f"{len(findings)} findings in changed files*",
    ])
    return "\n".join(lines)


def post_pr_comment(pr_number: str, repo: str, body: str) -> bool:
    """Post a comment on the PR using gh CLI."""
    if not body:
        return False

    try:
        r = subprocess.run(
            ["gh", "pr", "comment", str(pr_number), "--repo", repo,
             "--body", body],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception as e:
        print(f"Failed to post comment: {e}", file=sys.stderr)
        return False


def main():
    pr_info = get_pr_info()
    print(f"PR: #{pr_info['number']} in {pr_info['repo']}")

    findings = run_gsc_scan(".")
    if not findings:
        print("✅ No CRITICAL/HIGH findings in changed files")
        return

    comment = format_comment(findings)
    print(comment)

    if pr_info["number"]:
        ok = post_pr_comment(pr_info["number"], pr_info["repo"], comment)
        print(f"Comment posted: {ok}")
    else:
        print("No PR number — comment not posted")


if __name__ == "__main__":
    main()
