#!/usr/bin/env python3
"""
GSC GitHub Adapter — PR comment, check runs, SARIF upload.
v0.14

Usage:
  gsc-github scan <pr-url> --profile pr-gate [--dry-run] [--post-comment]
  gsc-github scan . --github-context event.json --profile pr-gate
"""

import os, sys, json, re, subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field

GSC_EXTERNAL = Path(__file__).resolve().parent / "gsc_external.py"

COMMENT_MARKER = "<!-- gsc:pr-scan:v1 -->"


# ═══════════════════════════════════════════════════════════════════════════════
# GitHub Context
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GitHubPRContext:
    owner: str = ""
    repo: str = ""
    pr_number: int = 0
    base_ref: str = "main"
    head_ref: str = "HEAD"
    base_sha: str = ""
    head_sha: str = ""
    clone_url: str = ""
    api_url: str = ""
    token: str = ""


def parse_pr_url(url: str) -> Optional[GitHubPRContext]:
    """Parse GitHub PR URL: https://github.com/owner/repo/pull/123"""
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)', url)
    if not m:
        return None
    owner, repo, pr_num = m.group(1), m.group(2), int(m.group(3))
    ctx = GitHubPRContext(
        owner=owner, repo=repo, pr_number=pr_num,
        api_url=f"https://api.github.com/repos/{owner}/{repo}",
        clone_url=f"https://github.com/{owner}/{repo}.git",
    )
    # Resolve via GitHub API if token available
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PAT", "")
    ctx.token = token
    if token:
        try:
            import requests
            resp = requests.get(
                f"{ctx.api_url}/pulls/{pr_num}",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                ctx.base_ref = data.get("base", {}).get("ref", "main")
                ctx.head_ref = data.get("head", {}).get("ref", "HEAD")
                ctx.base_sha = data.get("base", {}).get("sha", "")
                ctx.head_sha = data.get("head", {}).get("sha", "")
                ctx.clone_url = data.get("head", {}).get("repo", {}).get("clone_url", ctx.clone_url)
        except Exception:
            pass
    return ctx


def parse_github_event(event_path: str) -> Optional[GitHubPRContext]:
    """Parse GitHub Actions event JSON."""
    try:
        data = json.loads(Path(event_path).read_text())
    except Exception:
        return None

    pr_data = data.get("pull_request", {})
    repo_data = data.get("repository", {})
    owner = repo_data.get("owner", {}).get("login", os.environ.get("GITHUB_REPOSITORY_OWNER", ""))
    repo = repo_data.get("name", os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1] if "/" in os.environ.get("GITHUB_REPOSITORY", "") else "")
    pr_num = pr_data.get("number", 0)

    if not pr_num:
        return None

    return GitHubPRContext(
        owner=owner, repo=repo, pr_number=pr_num,
        base_ref=pr_data.get("base", {}).get("ref", os.environ.get("GITHUB_BASE_REF", "main")),
        head_ref=pr_data.get("head", {}).get("ref", os.environ.get("GITHUB_HEAD_REF", "HEAD")),
        base_sha=pr_data.get("base", {}).get("sha", ""),
        head_sha=pr_data.get("head", {}).get("sha", ""),
        clone_url=pr_data.get("head", {}).get("repo", {}).get("clone_url", ""),
        api_url=f"https://api.github.com/repos/{owner}/{repo}",
        token=os.environ.get("GITHUB_TOKEN", ""),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GitHub API
# ═══════════════════════════════════════════════════════════════════════════════

def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def find_existing_comment(ctx: GitHubPRContext) -> Optional[int]:
    """Find existing GSC comment by marker. Returns comment_id or None."""
    if not ctx.token:
        return None
    try:
        import requests
        resp = requests.get(
            f"{ctx.api_url}/issues/{ctx.pr_number}/comments?per_page=100&sort=created&direction=desc",
            headers=_gh_headers(ctx.token), timeout=15
        )
        if resp.status_code == 200:
            for comment in resp.json():
                if COMMENT_MARKER in (comment.get("body") or ""):
                    return comment["id"]
    except Exception:
        pass
    return None


def upsert_comment(ctx: GitHubPRContext, body: str, dry_run: bool = False) -> Optional[int]:
    """Create or update PR comment. Returns comment_id or None."""
    full_body = f"{COMMENT_MARKER}\n{body}"
    if dry_run:
        print(f"\n📝 [DRY-RUN] Would post comment to PR #{ctx.pr_number}")
        return None

    if not ctx.token:
        print("⚠️ No GITHUB_TOKEN — skipping comment")
        return None

    try:
        import requests
        existing = find_existing_comment(ctx)
        if existing:
            resp = requests.patch(
                f"{ctx.api_url}/issues/comments/{existing}",
                headers=_gh_headers(ctx.token),
                json={"body": full_body}, timeout=15
            )
            if resp.status_code == 200:
                print(f"📝 Updated comment #{existing} on PR #{ctx.pr_number}")
                return existing
        else:
            resp = requests.post(
                f"{ctx.api_url}/issues/{ctx.pr_number}/comments",
                headers=_gh_headers(ctx.token),
                json={"body": full_body}, timeout=15
            )
            if resp.status_code == 201:
                cid = resp.json()["id"]
                print(f"📝 Created comment #{cid} on PR #{ctx.pr_number}")
                return cid
        print(f"⚠️ Comment failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"⚠️ Comment error: {e}")
    return None


def create_check_run(ctx: GitHubPRContext, conclusion: str, summary: str,
                     title: str = "GSC Security Scan",
                     annotations: list = None,
                     dry_run: bool = False) -> Optional[int]:
    """Create GitHub Check Run. Returns check_run_id or None."""
    if dry_run:
        print(f"\n✅ [DRY-RUN] Would create check run: {conclusion}")
        return None

    if not ctx.token or not ctx.head_sha:
        print("⚠️ No GITHUB_TOKEN or head_sha — skipping check run")
        return None

    try:
        import requests
        payload = {
            "name": "GSC Security Scan",
            "head_sha": ctx.head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "output": {
                "title": title,
                "summary": summary,
            }
        }
        if annotations:
            payload["output"]["annotations"] = annotations[:50]

        resp = requests.post(
            f"{ctx.api_url}/check-runs",
            headers=_gh_headers(ctx.token),
            json=payload, timeout=15
        )
        if resp.status_code == 201:
            cid = resp.json()["id"]
            print(f"✅ Check run #{cid}: {conclusion}")
            return cid
        print(f"⚠️ Check run failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"⚠️ Check run error: {e}")
    return None


def conclusion_from_result(blocking: int, errored: bool = False) -> str:
    if errored:
        return "action_required"
    return "failure" if blocking > 0 else "success"


# ═══════════════════════════════════════════════════════════════════════════════
# Full PR adapter pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def run_pr_adapter(ctx: GitHubPRContext, profile: str = "pr-gate",
                   dry_run: bool = False, post_comment: bool = False,
                   fail_on_blocking: bool = False) -> int:
    """
    Full PR pipeline:
    1. Clone repo (or use local)
    2. Run diff scan
    3. Build comment
    4. Upsert comment (if post_comment)
    5. Create check run
    6. Return exit code
    """
    print(f"🔍 GSC PR Gate — {ctx.owner}/{ctx.repo}#{ctx.pr_number}")
    print(f"   Base: {ctx.base_ref} → Head: {ctx.head_ref}")

    # Resolve repo path
    token_flag = ["-c", f"http.extraHeader=Authorization: Bearer {ctx.token}"] if ctx.token and ctx.clone_url else []

    if ctx.clone_url:
        repo_path = Path(f"/tmp/gsc-pr-{ctx.owner}-{ctx.repo}-{ctx.pr_number}")
        if repo_path.exists():
            subprocess.run(["rm", "-rf", str(repo_path)], timeout=10)
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ctx.head_ref,
             "--filter=blob:none", ctx.clone_url, str(repo_path)] + token_flag,
            timeout=120
        )
        if not repo_path.exists():
            print("❌ Clone failed")
            return 2
    else:
        repo_path = Path.cwd()

    # Run external scan in diff mode
    cmd = [
        sys.executable, str(GSC_EXTERNAL), "scan", str(repo_path),
        "--profile", profile,
        "--mode", "diff",
        "--base", ctx.base_ref,
        "--head", "HEAD",
        "--format", "markdown",
    ]
    if fail_on_blocking:
        cmd.append("--fail-on-blocking")

    r = subprocess.run(cmd, timeout=600)
    exit_code = r.returncode

    # Find generated report files
    from gsc_external import EXTERNAL_DIR
    reports = sorted(Path(EXTERNAL_DIR).rglob("*-diff"), key=lambda p: p.stat().st_mtime, reverse=True)
    out_dir = reports[0] if reports else None

    # Build PR comment
    comment_body = _build_comment(out_dir, ctx)

    # Post comment
    if post_comment:
        upsert_comment(ctx, comment_body.strip(), dry_run)

    # Check run
    blocking = int("blocking" in str(exit_code) or exit_code == 1)
    concl = conclusion_from_result(blocking)
    summary = f"Blocking: {blocking} | Profile: {profile} | Base: {ctx.base_ref} → {ctx.head_ref}"
    create_check_run(ctx, concl, summary, dry_run=dry_run)

    # SARIF — print path for GitHub Actions
    if out_dir:
        sarif = out_dir / "report.sarif.json"
        if sarif.exists():
            print(f"📎 SARIF: {sarif}")

    # Cleanup
    if ctx.clone_url:
        subprocess.run(["rm", "-rf", str(repo_path)], timeout=10)

    return exit_code


def _build_comment(out_dir: Optional[Path], ctx: GitHubPRContext) -> str:
    """Build PR comment from scan results."""
    if not out_dir:
        return f"## 🔒 GSC Security Scan\n\n⚠️ Scan failed for {ctx.owner}/{ctx.repo}#{ctx.pr_number}"

    summary_path = out_dir / "summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text())
            findings = summary.get("findings", {})
            risk = summary.get("overall_risk", "UNKNOWN")
            lines = [
                f"## 🔒 GSC Security Scan",
                "",
                f"**Profile:** `{summary.get('profile', 'pr-gate')}`  ",
                f"**Base:** `{ctx.base_ref}` → **Head:** `{ctx.head_ref}`  ",
                f"**Overall risk:** {risk}  ",
                f"**Blocking:** {findings.get('blocking', 0)} · "
                f"**Confirmed:** {findings.get('confirmed', 0)} · "
                f"**Likely:** {findings.get('likely', 0)}",
                "",
            ]
            return "\n".join(lines)
        except Exception:
            pass

    # Fallback: read PR comment from scan output
    comment_path = out_dir / "pr_comment.md"
    if comment_path.exists():
        return comment_path.read_text()

    return f"## 🔒 GSC Security Scan\n\nScan completed for {ctx.owner}/{ctx.repo}#{ctx.pr_number}"


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC GitHub Adapter v0.14")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run PR scan with GitHub integration")
    scan.add_argument("target", help="GitHub PR URL (https://github.com/org/repo/pull/123) or '.' for local")
    scan.add_argument("--profile", default="pr-gate")
    scan.add_argument("--github-context", help="Path to GITHUB_EVENT_PATH JSON")
    scan.add_argument("--dry-run", action="store_true", help="Don't post to GitHub")
    scan.add_argument("--post-comment", action="store_true", help="Post comment to PR")
    scan.add_argument("--fail-on-blocking", action="store_true", help="Exit 1 if blocking")

    args = p.parse_args()

    if args.command == "scan":
        ctx = None

        if args.github_context:
            ctx = parse_github_event(args.github_context)
        elif args.target.startswith("http"):
            ctx = parse_pr_url(args.target)

        if not ctx:
            # Local scan only — no GitHub PR context
            print("⚠️ No GitHub PR context — running local diff scan only")
            cmd = [sys.executable, str(GSC_EXTERNAL), "scan", args.target,
                   "--profile", args.profile, "--mode", "diff", "--format", "markdown"]
            if args.fail_on_blocking:
                cmd.append("--fail-on-blocking")
            sys.exit(subprocess.run(cmd).returncode)

        exit_code = run_pr_adapter(ctx, args.profile, args.dry_run, args.post_comment, args.fail_on_blocking)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
