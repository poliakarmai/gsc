#!/usr/bin/env python3
"""Phase 3: Parse /gsc commands from PR comments.

SAFETY:
  - Comment body read ONLY from GITHUB_EVENT_PATH (JSON);
  - No shell interpolation — workflow injection is impossible;
  - Verdicts accepted only from OWNER/MEMBER/COLLABORATOR;
  - Reason is sent as API data, never a command.
"""
import json, os, re, sys, urllib.error, urllib.request

COMMAND_RE = re.compile(
    r"^\s*/gsc\s+(tp|fp|fixed|override)\s+([a-f0-9]{12})(?:\s+(.*))?$",
    re.IGNORECASE)
ALLOWED = {"OWNER", "MEMBER", "COLLABORATOR"}
MAX_REASON = 500
GH_API = "https://api.github.com"


def parse_commands(body: str) -> list[dict]:
    cmds = []
    for line in (body or "").splitlines():
        m = COMMAND_RE.match(line.strip())
        if not m:
            continue
        cmds.append({
            "finding_key": m.group(2).lower(),
            "verdict": m.group(1).lower(),
            "reason": (m.group(3) or "").strip()[:MAX_REASON],
        })
    return cmds


def _post(url, payload, headers, method="POST"):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method=method)
    return urllib.request.urlopen(req, timeout=10)


def main() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return 0
    with open(event_path, encoding="utf-8") as f:
        event = json.load(f)

    comment = event.get("comment", {})
    association = comment.get("author_association", "")
    if association not in ALLOWED:
        print(f"Ignored: author_association={association!r}", file=sys.stderr)
        return 0

    cmds = parse_commands(comment.get("body", ""))
    if not cmds:
        return 0

    api_url = os.environ.get("GSC_API_URL", "")
    api_key = os.environ.get("GSC_API_KEY", "")
    if not api_url or not api_key:
        return 0

    repo = event.get("repository", {}).get("full_name", "")
    pr_number = event.get("issue", {}).get("number")
    actor = (comment.get("user", {}) or {}).get("login", "")[:60]

    ok, failed = 0, []
    for cmd in cmds:
        if cmd["verdict"] == "override":
            endpoint = f"{api_url.rstrip('/')}/api/v1/overrides"
            payload = {"finding_key": cmd["finding_key"],
                       "reason": cmd["reason"], "repo": repo,
                       "pr_number": pr_number, "actor": actor}
        else:
            endpoint = f"{api_url.rstrip('/')}/api/v1/feedback"
            payload = {**cmd, "source": "pr-reply", "actor": actor,
                       "pr_number": pr_number}
        try:
            _post(endpoint, payload, {"x-api-key": api_key})
            ok += 1
        except urllib.error.HTTPError as e:
            failed.append(f"{cmd['finding_key']} -> HTTP {e.code}")
        except Exception as e:
            failed.append(f"{cmd['finding_key']} -> {e}")

    # Confirm with +1 reaction (not a new comment)
    token = os.environ.get("GITHUB_TOKEN")
    if ok and token and repo:
        try:
            _post(f"{GH_API}/repos/{repo}/issues/comments/"
                  f"{comment['id']}/reactions",
                  {"content": "+1"},
                  {"Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github+json"})
        except urllib.error.HTTPError as e:
            if e.code not in (200, 422):  # 422 = already reacted
                print(f"Reaction failed: {e.code}", file=sys.stderr)
        except Exception:
            pass

    print(f"Feedback recorded: {ok}, failed: {len(failed)}")
    for fmsg in failed:
        print(f"  {fmsg}", file=sys.stderr)
    return 0  # best-effort: never fail the workflow


if __name__ == "__main__":
    sys.exit(main())
