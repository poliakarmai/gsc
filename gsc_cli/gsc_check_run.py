#!/usr/bin/env python3
"""GSC GitHub Check Runs — CI integration.

Posts scan results as GitHub Check Runs on PRs.
Green check = pass, Red X = blocking findings, Yellow = warnings.

Usage:
    python3 gsc_check_run.py --repo owner/repo --sha HEAD --scan-file scan.json
    python3 gsc_check_run.py --pr-url https://github.com/owner/repo/pull/123

Integrated with pr_feedback for self-learning loop.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GSC_GITHUB_TOKEN")
    if token:
        return token
    try:
        import subprocess
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    print("No GitHub token found. Set GITHUB_TOKEN or login with gh.", file=sys.stderr)
    sys.exit(1)


def gh_api(method: str, path: str, token: str, data: dict = None) -> dict:
    url = f"https://api.github.com{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read().decode()) if e.fp else {"message": str(e)}
        raise RuntimeError(f"GitHub API {e.code}: {err.get('message', str(e))}") from e


def findings_to_check_run(findings: list, conclusion: str = None) -> dict:
    """Convert GSC findings to GitHub Check Run output."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 0), reverse=True)

    critical = [f for f in sorted_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in sorted_findings if f.get("severity") == "HIGH"]
    med = [f for f in sorted_findings if f.get("severity") == "MEDIUM"]
    low = [f for f in sorted_findings if f.get("severity") == "LOW"]

    # Determine conclusion
    if conclusion is None:
        if critical:
            conclusion = "failure"
        elif high:
            conclusion = "failure"
        elif med:
            conclusion = "neutral"
        else:
            conclusion = "success"

    # Build summary
    summary = "## 🔒 GSC Security Scan\n\n"
    summary += "| Severity | Count |\n|----------|-------|\n"
    summary += f"| 🔴 Critical | {len(critical)} |\n"
    summary += f"| 🟠 High | {len(high)} |\n"
    summary += f"| 🟡 Medium | {len(med)} |\n"
    summary += f"| 🟢 Low | {len(low)} |\n"

    if critical:
        summary += f"\n### 🔴 Critical ({len(critical)})\n"
        for f in critical[:10]:
            summary += f"- **{f.get('rule_id', '?')}**: {f.get('title', '')[:100]}\n"
            summary += f"  `{f.get('file_path', f.get('file', '?'))}:{f.get('line_number', f.get('line', '?'))}`\n"

    if high:
        summary += f"\n### 🟠 High ({len(high)})\n"
        for f in high[:5]:
            summary += f"- **{f.get('rule_id', '?')}**: {f.get('title', '')[:100]}\n"

    # Annotations for inline display
    annotations = []
    for f in critical[:50] + high[:30]:
        annotations.append({
            "path": f.get("file_path", f.get("file", "")),
            "start_line": int(f.get("line_number", f.get("line", 1))),
            "end_line": int(f.get("line_number", f.get("line", 1))),
            "annotation_level": "failure" if f.get("severity") in ("CRITICAL", "HIGH") else "warning",
            "message": f"{f.get('rule_id', '?')}: {f.get('title', '')[:120]}",
            "title": f.get('rule_id', 'Security finding'),
        })

    return {
        "name": "GSC Security Scan",
        "head_sha": "",  # filled by caller
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "output": {
            "title": f"GSC: {len(critical)} critical, {len(high)} high, {len(med)} medium",
            "summary": summary[:65535],  # GitHub limit
            "annotations": annotations[:50],  # GitHub limit: 50 per run
            "text": "Scanned with [GSC](https://github.com/poliakarmai/gsc) v1.4.0",
        },
    }


def create_check_run(repo: str, sha: str, findings: list, token: str, conclusion: str = None) -> dict:
    """Create a Check Run on GitHub."""
    data = findings_to_check_run(findings, conclusion)
    data["head_sha"] = sha

    result = gh_api("POST", f"/repos/{repo}/check-runs", token, data)
    return result


def create_from_pr(pr_url: str, scan_file: str = None, token: str = None):
    """Create Check Run from PR URL and scan results."""
    if token is None:
        token = get_token()

    # Parse PR URL
    import re
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)", pr_url)
    if not m:
        raise ValueError(f"Invalid PR URL: {pr_url}")

    repo = m.group(1)
    pr_num = int(m.group(2))

    # Get PR head SHA
    pr = gh_api("GET", f"/repos/{repo}/pulls/{pr_num}", token)
    sha = pr["head"]["sha"]
    print(f"PR #{pr_num}: head={sha[:8]} branch={pr['head']['ref']}")

    # Load findings
    if scan_file:
        with open(scan_file) as f:
            data = json.load(f)
        findings = data if isinstance(data, list) else data.get("findings", [])
    else:
        findings = []
        print("No scan file — creating empty Check Run (no issues)")

    return create_check_run(repo, sha, findings, token)


def create_conclusion_only(repo: str, sha: str, conclusion: str, token: str = None):
    """Create a simple Check Run with just a conclusion (no findings)."""
    if token is None:
        token = get_token()
    return create_check_run(repo, sha, [], token, conclusion)


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="GSC GitHub Check Runs")
    ap.add_argument("--repo", help="owner/repo")
    ap.add_argument("--sha", help="Commit SHA")
    ap.add_argument("--pr-url", help="GitHub PR URL")
    ap.add_argument("--scan-file", help="Path to scan.json")
    ap.add_argument("--conclusion", choices=["success", "failure", "neutral", "skipped"],
                    help="Force conclusion")
    ap.add_argument("--token", help="GitHub token (or set GITHUB_TOKEN)")

    args = ap.parse_args()

    token = get_token()

    if args.pr_url:
        result = create_from_pr(args.pr_url, args.scan_file, token)
    elif args.repo and args.sha:
        findings = []
        if args.scan_file:
            with open(args.scan_file) as f:
                data = json.load(f)
            findings = data if isinstance(data, list) else data.get("findings", [])
        result = create_check_run(args.repo, args.sha, findings, token, args.conclusion)
    else:
        ap.print_help()
        sys.exit(1)

    print(f"✅ Check Run: {result.get('html_url') or result.get('url')}")
    print(f"   Status: {result.get('status')}, Conclusion: {result.get('conclusion')}")
