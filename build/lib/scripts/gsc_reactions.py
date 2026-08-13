#!/usr/bin/env python3
"""GSC Reactions Collector (Phase 2). Nightly 04:30 MSK.

Queries GitHub Reactions API for published comments and stores
aggregated counts (thumbs_up/down/confused) — no actor logins.

Privacy: only aggregated counts are stored.
"""
import json, os, sqlite3, sys, urllib.request
from pathlib import Path

DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"
API = "https://api.github.com"
ALLOWED = {"+1": "thumbs_up", "-1": "thumbs_down", "confused": "confused"}


def gh_get(url: str, token: str):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def collect(token: str) -> dict:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT repo, pr_number, comment_id FROM published_comments"
    ).fetchall()

    stats = {"processed": 0, "errors": 0}
    for row in rows:
        try:
            cid = row['comment_id']
            if cid and cid > 0:
                url = f"{API}/repos/{row['repo']}/issues/comments/{cid}/reactions"
            else:
                # GSC content in PR body (not a comment) — use issue reactions
                url = f"{API}/repos/{row['repo']}/issues/{row['pr_number']}/reactions"
            reactions = gh_get(url, token)
        except Exception as e:
            stats["errors"] += 1
            print(f"  {row['repo']}#{row['pr_number']}: {e}", file=sys.stderr)
            continue

        counts = {"thumbs_up": 0, "thumbs_down": 0, "confused": 0}
        for r in reactions:
            field = ALLOWED.get(r.get("content"))
            if field:
                counts[field] += 1

        conn.execute("""
            INSERT INTO comment_reactions
                (comment_id, repo, pr_number, thumbs_up, thumbs_down,
                 confused, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(comment_id) DO UPDATE SET
                thumbs_up = excluded.thumbs_up,
                thumbs_down = excluded.thumbs_down,
                confused = excluded.confused,
                collected_at = excluded.collected_at
        """, (row["comment_id"], row["repo"], row["pr_number"],
              counts["thumbs_up"], counts["thumbs_down"],
              counts["confused"]))
        stats["processed"] += 1

    conn.commit()
    conn.close()
    return stats


if __name__ == "__main__":
    token = os.environ.get("GSC_GITHUB_TOKEN")
    if not token:
        print("GSC_GITHUB_TOKEN not set — skip", file=sys.stderr)
        sys.exit(0)
    result = collect(token)
    print(f"Reactions collected: {result}")
