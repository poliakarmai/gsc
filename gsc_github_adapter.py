# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
"""
GSC GitHub Adapter v0.15 — Real GitHub Operations & Safe Fork Mode

Features:
- GitHubAPIClient with rate limiting, retries, pagination
- Idempotent comment upsert via marker
- Check run with proper conclusions
- Fork safe mode (no LLM, no blocking, no secrets)
- gsc doctor --github diagnostics
- Redaction audit before publishing
- Comment size / annotation limits
- Source tracking for feedback loop

Usage:
  gsc github-scan <pr-url> --post-comment --create-check --fail-on-blocking
  gsc github-scan . --github-context "$GITHUB_EVENT_PATH" --safe-mode
  gsc doctor --github
"""

import os, sys, json, re, time, subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field

GSC_EXTERNAL = Path(__file__).resolve().parent / "gsc_external.py"
COMMENT_MARKER = "<!-- gsc:pr-scan:v1 -->"
MAX_COMMENT_BYTES = 60000
MAX_ANNOTATIONS = 50
MAX_COMMENTS_PAGES = 3  # 3 × 100 = 300 comments


# ═══════════════════════════════════════════════════════════════════════════════
# GitHub API Client with rate limiting & retries
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RateLimit:
    remaining: int = 5000
    reset: int = 0
    limit: int = 5000

class GitHubAPIClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com"):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.rate = RateLimit()
        self._session = None

    @property
    def session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "GSC/0.15",
            })
        return self._session

    def _update_rate_limit(self, resp):
        self.rate.remaining = int(resp.headers.get("X-RateLimit-Remaining", self.rate.remaining))
        self.rate.reset = int(resp.headers.get("X-RateLimit-Reset", self.rate.reset))
        self.rate.limit = int(resp.headers.get("X-RateLimit-Limit", self.rate.limit))

    def _wait_for_rate_limit(self):
        if self.rate.remaining < 20:
            wait = max(self.rate.reset - int(time.time()), 1) + 2
            print(f"⏳ Rate limit low ({self.rate.remaining}), waiting {wait}s...")
            time.sleep(min(wait, 30))

    def _request(self, method: str, path: str, json_data: dict = None,
                 params: dict = None, retries: int = 2) -> "requests.Response":
        import requests
        url = f"{self.api_url}{path}"
        for attempt in range(retries + 1):
            self._wait_for_rate_limit()
            try:
                if method == "GET":
                    resp = self.session.get(url, params=params, timeout=20)
                elif method == "POST":
                    resp = self.session.post(url, json=json_data, timeout=20)
                elif method == "PATCH":
                    resp = self.session.patch(url, json=json_data, timeout=20)
                else:
                    raise ValueError(f"Unknown method: {method}")
                self._update_rate_limit(resp)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 5))
                    print(f"⚠️ Rate limited, retry in {retry_after}s (attempt {attempt+1})")
                    time.sleep(retry_after + 2)
                    continue
                if resp.status_code >= 500 and attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                return resp
            except requests.RequestException as e:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                raise
        return resp  # Last attempt result

    def get(self, path: str, params: dict = None):
        return self._request("GET", path, params=params)

    def post(self, path: str, json_data: dict):
        return self._request("POST", path, json_data=json_data)

    def patch(self, path: str, json_data: dict):
        return self._request("PATCH", path, json_data=json_data)


# ═══════════════════════════════════════════════════════════════════════════════
# GitHub PR Context
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
    is_fork: bool = False
    head_repo_full: str = ""


def parse_pr_url(url: str) -> Optional[GitHubPRContext]:
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)', url)
    if not m:
        return None
    owner, repo, pr_num = m.group(1), m.group(2), int(m.group(3))
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PAT", "")
    ctx = GitHubPRContext(
        owner=owner, repo=repo, pr_number=pr_num,
        api_url=f"https://api.github.com/repos/{owner}/{repo}",
        clone_url=f"https://github.com/{owner}/{repo}.git",
        token=token,
    )
    if token:
        _fetch_pr_details(ctx)
    return ctx


def parse_github_event(event_path: str) -> Optional[GitHubPRContext]:
    try:
        data = json.loads(Path(event_path).read_text())
    except Exception:
        return None

    pr_data = data.get("pull_request", {})
    repo_data = data.get("repository", {})
    owner = repo_data.get("owner", {}).get("login",
              os.environ.get("GITHUB_REPOSITORY_OWNER", ""))
    repo = repo_data.get("name",
           os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1]
           if "/" in os.environ.get("GITHUB_REPOSITORY", "") else "")
    pr_num = pr_data.get("number", 0)
    if not pr_num:
        return None

    base_repo = pr_data.get("base", {}).get("repo", {})
    head_repo = pr_data.get("head", {}).get("repo", {})
    base_full = base_repo.get("full_name", "")
    head_full = head_repo.get("full_name", "")
    is_fork = bool(base_full and head_full and base_full != head_full)

    return GitHubPRContext(
        owner=owner, repo=repo, pr_number=pr_num,
        base_ref=pr_data.get("base", {}).get("ref", os.environ.get("GITHUB_BASE_REF", "main")),
        head_ref=pr_data.get("head", {}).get("ref", os.environ.get("GITHUB_HEAD_REF", "HEAD")),
        base_sha=pr_data.get("base", {}).get("sha", ""),
        head_sha=pr_data.get("head", {}).get("sha", ""),
        clone_url=head_repo.get("clone_url", ""),
        api_url=f"https://api.github.com/repos/{owner}/{repo}",
        token=os.environ.get("GITHUB_TOKEN", ""),
        is_fork=is_fork,
        head_repo_full=head_full,
    )


def _fetch_pr_details(ctx: GitHubPRContext):
    try:
        client = GitHubAPIClient(ctx.token, "https://api.github.com")
        resp = client.get(f"/repos/{ctx.owner}/{ctx.repo}/pulls/{ctx.pr_number}")
        if resp.status_code == 200:
            data = resp.json()
            ctx.base_ref = data.get("base", {}).get("ref", ctx.base_ref)
            ctx.head_ref = data.get("head", {}).get("ref", ctx.head_ref)
            ctx.base_sha = data.get("base", {}).get("sha", "")
            ctx.head_sha = data.get("head", {}).get("sha", "")
            ctx.clone_url = data.get("head", {}).get("repo", {}).get("clone_url", ctx.clone_url)
            base_full = data.get("base", {}).get("repo", {}).get("full_name", "")
            head_full = data.get("head", {}).get("repo", {}).get("full_name", "")
            ctx.is_fork = bool(base_full and head_full and base_full != head_full)
            ctx.head_repo_full = head_full
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Comment ops
# ═══════════════════════════════════════════════════════════════════════════════

def find_existing_comment(client: GitHubAPIClient, ctx: GitHubPRContext) -> Optional[int]:
    """Find existing GSC comment by marker with pagination."""
    for page in range(1, MAX_COMMENTS_PAGES + 1):
        resp = client.get(
            f"/repos/{ctx.owner}/{ctx.repo}/issues/{ctx.pr_number}/comments",
            params={"per_page": 100, "page": page, "sort": "created", "direction": "desc"}
        )
        if resp.status_code != 200:
            break
        for comment in resp.json():
            if COMMENT_MARKER in (comment.get("body") or ""):
                return comment["id"]
        if len(resp.json()) < 100:
            break
    return None


def upsert_comment(client: GitHubAPIClient, ctx: GitHubPRContext,
                   body: str, dry_run: bool = False) -> Optional[int]:
    """Create or update PR comment. Returns comment_id or None."""
    full_body = f"{COMMENT_MARKER}\n{body}"

    # Truncate if needed
    if len(full_body.encode()) > MAX_COMMENT_BYTES:
        trunc_note = "\n\n---\n*Some findings omitted — see full report artifact.*"
        while len((full_body + trunc_note).encode()) > MAX_COMMENT_BYTES:
            # Remove last section
            parts = full_body.rsplit("\n### ", 1)
            if len(parts) > 1:
                full_body = parts[0]
            else:
                full_body = full_body[:MAX_COMMENT_BYTES - 500]
                break
        full_body += trunc_note

    if dry_run:
        print(f"\n📝 [DRY-RUN] Comment ({len(full_body.encode())} bytes)")
        print(full_body[:500])
        return None

    try:
        existing = find_existing_comment(client, ctx)
        if existing:
            resp = client.patch(
                f"/repos/{ctx.owner}/{ctx.repo}/issues/comments/{existing}",
                {"body": full_body}
            )
            if resp.status_code == 200:
                print(f"📝 Updated comment #{existing}")
                return existing
        else:
            resp = client.post(
                f"/repos/{ctx.owner}/{ctx.repo}/issues/{ctx.pr_number}/comments",
                {"body": full_body}
            )
            if resp.status_code == 201:
                cid = resp.json()["id"]
                print(f"📝 Created comment #{cid}")
                return cid
        print(f"⚠️ Comment failed: HTTP {resp.status_code} — {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️ Comment error: {e}")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Check run ops
# ═══════════════════════════════════════════════════════════════════════════════

def conclusion_from_result(blocking: int, warnings: int, safe_mode: bool = False,
                           errored: bool = False, phase: str = "warn-only") -> str:
    if errored:
        return "action_required"
    if safe_mode:
        return "neutral"
    # Phase 2: warn-only never blocks (neutral = attention, not failure)
    if phase == "warn-only":
        return "neutral" if (blocking > 0 or warnings > 0) else "success"
    # Phase 4+: blocking means failure
    if blocking > 0:
        return "failure"
    return "success"


def create_check_run(client: GitHubAPIClient, ctx: GitHubPRContext,
                     conclusion: str, summary: str, title: str = "GSC Security Scan",
                     dry_run: bool = False) -> Optional[int]:
    if dry_run:
        print(f"\n✅ [DRY-RUN] Check run: {conclusion}")
        return None
    if not ctx.head_sha:
        print("⚠️ No head_sha — skipping check run")
        return None
    try:
        resp = client.post(
            f"/repos/{ctx.owner}/{ctx.repo}/check-runs",
            {
                "name": "GSC Security Scan",
                "head_sha": ctx.head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "output": {"title": title, "summary": summary[:65535]},
            }
        )
        if resp.status_code == 201:
            cid = resp.json()["id"]
            print(f"✅ Check run #{cid}: {conclusion}")
            return cid
        print(f"⚠️ Check run failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"⚠️ Check run error: {e}")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Redaction audit
# ═══════════════════════════════════════════════════════════════════════════════

REDACT_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "API key"),
    (r'AKIA[A-Z0-9]{16}', "AWS key"),
    (r'-----BEGIN.*PRIVATE KEY-----', "Private key"),
    (r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\'][^\s"\']{8,}["\']', "Hardcoded credential"),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Email"),
]


def audit_redaction(text: str) -> list[str]:
    """Check text for raw secrets. Returns list of issues found."""
    issues = []
    for pattern, label in REDACT_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
        for m in matches:
            if "REDACTED" not in str(m):
                snippet = str(m)[:40].replace("\n", "\\n")
                issues.append(f"{label}: {snippet}")
    return issues


def audit_all(comment: str, sarif_text: str = "", check_summary: str = "") -> dict:
    """Audit all outputs for redaction leaks."""
    result = {"comment_leaks": [], "sarif_leaks": [], "check_leaks": [], "total": 0}
    result["comment_leaks"] = audit_redaction(comment)
    if sarif_text:
        result["sarif_leaks"] = audit_redaction(sarif_text)
    if check_summary:
        result["check_leaks"] = audit_redaction(check_summary)
    result["total"] = len(result["comment_leaks"]) + len(result["sarif_leaks"]) + len(result["check_leaks"])
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# GSC Doctor — GitHub diagnostics
# ═══════════════════════════════════════════════════════════════════════════════

def doctor_github(ctx: Optional[GitHubPRContext] = None) -> dict:
    """Diagnose GitHub integration readiness. Returns status dict."""
    status = {
        "token": False, "token_permissions": {},
        "pr_context": False, "fork": None,
        "llm_key": False, "sarif_ready": False,
        "redaction": "not checked", "rate_limit": None,
        "mode": "unknown", "errors": [],
    }

    # Token check
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        status["token"] = True
        try:
            client = GitHubAPIClient(token)
            resp = client.get("/rate_limit")
            if resp.status_code == 200:
                rl = resp.json()
                core = rl.get("resources", {}).get("core", {})
                status["rate_limit"] = f"{core.get('remaining', '?')}/{core.get('limit', '?')}"
            # Check token permissions by inspecting response headers
            if "X-OAuth-Scopes" in resp.headers:
                scopes = resp.headers["X-OAuth-Scopes"]
                status["token_permissions"]["scopes"] = scopes
                status["token_permissions"]["has_repo"] = "repo" in scopes
            status["token_permissions"]["note"] = "Token valid"
        except Exception as e:
            status["errors"].append(f"Token validation failed: {e}")
    else:
        status["errors"].append("No GITHUB_TOKEN found")

    # PR context
    if ctx:
        status["pr_context"] = True
        status["fork"] = ctx.is_fork
        status["mode"] = "fork-safe" if ctx.is_fork else "internal"
    else:
        status["mode"] = "local-only"

    # LLM key
    llm_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
    status["llm_key"] = bool(llm_key)
    if not llm_key and not (ctx and ctx.is_fork):
        status["errors"].append("No LLM API key found")

    # Mode decision
    if ctx and ctx.is_fork:
        status["llm_enabled"] = False
        status["blocking_enabled"] = False
    else:
        status["llm_enabled"] = status["llm_key"]
        status["blocking_enabled"] = True

    return status


def print_doctor(status: dict):
    print("🔍 GSC GitHub Diagnostics")
    print(f"  GitHub token: {'✅ found' if status['token'] else '❌ missing'}")
    if status["token_permissions"]:
        for k, v in status["token_permissions"].items():
            print(f"    {k}: {v}")
    print(f"  Rate limit: {status['rate_limit'] or 'unknown'}")
    print(f"  PR context: {'✅ ok' if status['pr_context'] else '⚠️ not available (local mode)'}")
    print(f"  Fork PR: {status['fork']}")
    print(f"  LLM key: {'✅ found' if status['llm_key'] else '❌ missing'}")
    print(f"  Mode: {status['mode']}")
    print(f"  LLM enabled: {status.get('llm_enabled', False)}")
    print(f"  Blocking enabled: {status.get('blocking_enabled', False)}")
    if status["errors"]:
        print(f"  ⚠️ Issues:")
        for e in status["errors"]:
            print(f"    - {e}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# Full PR adapter pipeline (v0.15)
# ═══════════════════════════════════════════════════════════════════════════════

def run_pr_adapter(ctx: GitHubPRContext, profile: str = "pr-gate",
                   dry_run: bool = False, post_comment: bool = False,
                   create_check: bool = False, fail_on_blocking: bool = False,
                   safe_mode: bool = False, no_llm: bool = False) -> int:
    """
    Full PR pipeline v0.15:
    1. Doctor diagnostics
    2. Determine mode (internal / fork-safe)
    3. Clone + diff scan
    4. Redaction audit
    5. Upsert comment + check run
    6. Return exit code
    """
    # Auto-detect safe mode
    if ctx.is_fork:
        safe_mode = True
        no_llm = True

    # Doctor
    status = doctor_github(ctx)
    print_doctor(status)

    print(f"🔍 GSC PR Gate — {ctx.owner}/{ctx.repo}#{ctx.pr_number}")
    print(f"   Base: {ctx.base_ref} → Head: {ctx.head_ref}")
    print(f"   Mode: {'fork-safe' if safe_mode else 'internal'}, "
          f"LLM: {'off' if no_llm else 'on'}, "
          f"Blocking: {'off' if safe_mode else 'on'}")

    # Resolve repo path
    repo_path = Path(f"/tmp/gsc-pr-{ctx.owner}-{ctx.repo}-{ctx.pr_number}")
    if ctx.clone_url:
        if repo_path.exists():
            subprocess.run(["rm", "-rf", str(repo_path)], timeout=10)
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ctx.head_ref,
             "--filter=blob:none", ctx.clone_url, str(repo_path)], timeout=120
        )
        if not repo_path.exists():
            print("❌ Clone failed")
            return 2
    else:
        repo_path = Path.cwd()

    # Build scan command
    scan_profile = profile
    if no_llm:
        scan_profile = "candidate-review"  # Uses 0 LLM budget effectively
    cmd = [
        sys.executable, str(GSC_EXTERNAL), "scan", str(repo_path),
        "--profile", scan_profile, "--mode", "diff",
        "--base", ctx.base_ref, "--head", "HEAD", "--format", "markdown",
    ]
    if fail_on_blocking and not safe_mode:
        cmd.append("--fail-on-blocking")

    r = subprocess.run(cmd, timeout=600)
    exit_code = 0 if dry_run else r.returncode

    # Find report
    from gsc_external import EXTERNAL_DIR
    reports = sorted(Path(EXTERNAL_DIR).rglob("*-diff"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    out_dir = reports[0] if reports else None

    # Build comment
    comment_body = _build_pr_comment(out_dir, ctx, safe_mode, no_llm)
    sarif_text = ""
    if out_dir:
        sarif_path = out_dir / "report.sarif.json"
        if sarif_path.exists():
            sarif_text = sarif_path.read_text()

    # Redaction audit
    redact_result = audit_all(comment_body, sarif_text)
    if redact_result["total"] > 0:
        print(f"❌ REDACTION AUDIT FAILED: {redact_result['total']} leaks")
        for loc, leaks in [("comment", redact_result["comment_leaks"]),
                           ("sarif", redact_result["sarif_leaks"]),
                           ("check", redact_result["check_leaks"])]:
            for leak in leaks:
                print(f"   [{loc}] {leak}")
        if not dry_run:
            return 2

    # Post comment
    token = ctx.token
    if (post_comment) and token:
        client = GitHubAPIClient(token)
        comment_id = upsert_comment(client, ctx, comment_body.strip(), dry_run)
        if comment_id and not dry_run:
            try:
                from gsc_db import GSCDatabase
                db = GSCDatabase()
                db.upsert_published_comment(
                    repo=f"{ctx.owner}/{ctx.repo}",
                    pr_number=ctx.pr_number,
                    comment_id=comment_id,
                    head_sha=ctx.head_sha or "",
                )
            except Exception as e:
                print(f"⚠️ Failed to record comment_id {comment_id}: {e}")

    # Check run
    if create_check and token:
        client = GitHubAPIClient(token) if not post_comment else client
        blocking = 1 if exit_code == 1 else 0
        warnings = _count_warnings(out_dir)
        concl = conclusion_from_result(blocking, warnings, safe_mode)
        summary = (f"Blocking: {blocking} · Warnings: {warnings} · "
                   f"Mode: {'safe' if safe_mode else 'internal'} · "
                   f"LLM: {'off' if no_llm else 'on'}")
        create_check_run(client, ctx, concl, summary, dry_run=dry_run)

    # SARIF
    if out_dir:
        sarif = out_dir / "report.sarif.json"
        if sarif.exists():
            print(f"📎 SARIF: {sarif}")

    # Cleanup
    if ctx.clone_url:
        subprocess.run(["rm", "-rf", str(repo_path)], timeout=10)

    return exit_code


def _build_pr_comment(out_dir: Optional[Path], ctx: GitHubPRContext,
                      safe_mode: bool, no_llm: bool) -> str:
    """Build PR comment with v0.15 template."""
    mode_label = "⚠️ Fork-safe (limited)" if safe_mode else "🔒 Internal (full)"
    llm_label = "Disabled" if no_llm else "Enabled"

    lines = [
        f"## 🔒 GSC Security Scan",
        "",
        f"**Profile:** `pr-gate` · **Mode:** {mode_label}",
        f"**Base:** `{ctx.base_ref}` → **Head:** `{ctx.head_ref}`",
        f"**LLM:** {llm_label} · **Blocking:** {'Disabled' if safe_mode else 'Enabled'}",
    ]

    if safe_mode:
        lines.extend([
            "",
            "> ⚠️ This PR is from a fork. LLM revalidation is disabled for security.",
            "> Only static regex patterns were checked. Confidence is capped.",
            "> Maintainers can request a full scan by adding the `gsc-safe-to-test` label.",
        ])

    lines.append("")

    if out_dir:
        summary_path = out_dir / "summary.json"
        if summary_path.exists():
            try:
                s = json.loads(summary_path.read_text())
                f = s.get("findings", {})
                lines.extend([
                    f"**Blocking:** {f.get('blocking', 0)} · "
                    f"**Confirmed:** {f.get('confirmed', 0)} · "
                    f"**Likely:** {f.get('likely', 0)} · "
                    f"**Uncertain:** {f.get('uncertain', 0)}",
                    f"**Overall risk:** {s.get('overall_risk', 'UNKNOWN')}",
                ])
            except Exception:
                pass

    lines.extend([
        "",
        "---",
        f"*Blocking policy: severity ≥ HIGH, confidence ≥ 80%.*",
    ])
    return "\n".join(lines)


def _count_warnings(out_dir: Optional[Path]) -> int:
    if not out_dir:
        return 0
    summary_path = out_dir / "summary.json"
    if summary_path.exists():
        try:
            return json.loads(summary_path.read_text()).get("findings", {}).get("likely", 0)
        except Exception:
            return 0
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC GitHub Adapter v0.15")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run PR scan with GitHub integration")
    scan.add_argument("target", help="GitHub PR URL or '.' for local")
    scan.add_argument("--profile", default="pr-gate")
    scan.add_argument("--github-context", help="Path to GITHUB_EVENT_PATH JSON")
    scan.add_argument("--dry-run", action="store_true")
    scan.add_argument("--post-comment", action="store_true")
    scan.add_argument("--create-check", action="store_true")
    scan.add_argument("--fail-on-blocking", action="store_true")
    scan.add_argument("--safe-mode", action="store_true")
    scan.add_argument("--no-llm", action="store_true")

    doctor = sub.add_parser("doctor", help="GitHub diagnostics")
    doctor.add_argument("--github-context", help="Path to GITHUB_EVENT_PATH JSON")

    args = p.parse_args()

    if args.command == "doctor":
        ctx = None
        if getattr(args, "github_context", None):
            ctx = parse_github_event(args.github_context)
        status = doctor_github(ctx)
        print_doctor(status)
        sys.exit(0 if not status["errors"] else 2)

    elif args.command == "scan":
        ctx = None
        if getattr(args, "github_context", None):
            ctx = parse_github_event(args.github_context)
        elif args.target.startswith("http"):
            ctx = parse_pr_url(args.target)

        if not ctx and args.target == ".":
            # Local scan with dummy context
            ctx = GitHubPRContext(
                owner="local", repo="local", pr_number=0,
                base_ref="main", head_ref="HEAD",
                token=os.environ.get("GITHUB_TOKEN", ""),
            )

        if not ctx:
            print("❌ Could not determine PR context")
            sys.exit(2)

        exit_code = run_pr_adapter(
            ctx, args.profile,
            dry_run=getattr(args, "dry_run", False),
            post_comment=getattr(args, "post_comment", False),
            create_check=getattr(args, "create_check", False),
            fail_on_blocking=getattr(args, "fail_on_blocking", False),
            safe_mode=getattr(args, "safe_mode", False),
            no_llm=getattr(args, "no_llm", False),
        )
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
