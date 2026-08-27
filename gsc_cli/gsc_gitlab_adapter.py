# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GitLab MR adapter glue (Phase 15 — RF Enterprise).

Bridges the pure MR-context parser (``gsc_gitlab_mr_context``) and the GitLab
API client (``gsc_gitlab_api_client``) into a single pipeline: parse a
merge-request URL, resolve credentials from the environment, assemble the scan
note body, and idempotently upsert it as a note on the MR.

This is the GitLab analogue of ``gsc_github_adapter.run_pr_adapter``, scoped to
the minimum needed for self-hosted GitLab / GitFlic (RF on-prem): a single MR
note carrying the GSC scan result. The clone / diff-scan / check-run layer lives
in the GitHub adapter and can be ported here later.

Exit codes: 0 ok · 2 unparseable URL · 3 missing token · 4 API failure.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from gsc_cli.gsc_gitlab_api_client import GitLabAPIClient, upsert_note
from gsc_cli.gsc_gitlab_mr_context import GitLabMRContext, parse_gitlab_mr_url


def _marker(ctx: GitLabMRContext) -> str:
    """Stable idempotency marker unique to this project + MR."""
    return f"<!-- gsc:scan:{ctx.project_path}:{ctx.mr_iid} -->"


def build_mr_note_body(ctx: GitLabMRContext, summary: str,
                       findings_text: str = "") -> str:
    """Assemble the markdown note body, headed by the idempotency marker."""
    header = f"## 🔍 GSC Security Scan — MR !{ctx.mr_iid}"
    lines = [_marker(ctx), header, "", summary]
    if findings_text and findings_text.strip():
        lines += ["", "### Findings", findings_text]
    return "\n".join(lines)


def _load_report(path: Optional[str]) -> str:
    """Read a markdown report file; return "" on missing/unreadable path."""
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def run_gitlab_mr_adapter(url: str, report_path: Optional[str] = None,
                          dry_run: bool = False) -> int:
    """Parse a GitLab MR URL and upsert a GSC scan-result note (idempotent)."""
    ctx = parse_gitlab_mr_url(url)
    if ctx is None:
        print("❌ Could not parse GitLab merge-request URL")
        return 2

    token = os.environ.get("GITLAB_TOKEN", "")
    if not token:
        print("❌ GITLAB_TOKEN is not set (self-hosted GitLab/GitFlic requires it)")
        return 3

    report = _load_report(report_path)
    summary = report or "GSC scan complete — no report text provided."
    body = build_mr_note_body(ctx, summary)

    if dry_run:
        print(f"[dry-run] would upsert note on {ctx.project_path} !{ctx.mr_iid}")
        print("-" * 40)
        print(body)
        return 0

    client = GitLabAPIClient(token, ctx.api_base)
    note_id = upsert_note(client, ctx.project_path, ctx.mr_iid, body, _marker(ctx))
    if note_id is None:
        print("❌ Failed to upsert GSC note on the merge request")
        return 4

    print(f"✅ GSC note upserted (id {note_id}) on {ctx.project_path} !{ctx.mr_iid}")
    return 0


def main(argv: Optional[list] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        description="Post a GSC scan result to a GitLab merge-request note")
    p.add_argument("url", help="GitLab merge-request URL")
    p.add_argument("--report", help="Path to a markdown report to attach")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the note without posting")
    a = p.parse_args(argv)
    return run_gitlab_mr_adapter(a.url, report_path=a.report, dry_run=a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
