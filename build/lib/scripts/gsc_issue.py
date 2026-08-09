#!/usr/bin/env python3
"""
GSC Issue Tracker — create Jira/Linear tickets from findings.
Usage: gsc issue <finding-id> [--jira|--linear]
"""
import sys, os, json, sqlite3
from pathlib import Path
import subprocess

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

JIRA_TEMPLATE = """h2. {title}
*Category:* {category} | *CVSS:* {cvss}
*File:* {file_path}:{line_number}
*Pattern:* {pattern}

h3. Detail
{detail}

h3. Fix
{fix}

*Found by GSC:* https://github.com/poliakarmai/gsc"""

LINEAR_TEMPLATE = """## {title}
**Severity:** {category} | **CVSS:** {cvss}
**File:** `{file_path}:{line_number}`
**Pattern:** {pattern}

### Detail
{detail}

### Suggested Fix
{fix}

> Found by [GSC](https://github.com/poliakarmai/gsc)"""


def get_finding(fid: str) -> dict:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone() if fid.isdigit() else None
    conn.close()
    return dict(row) if row else None


def create_jira(finding: dict):
    """Create Jira ticket via REST API."""
    jira_url = os.environ.get("JIRA_URL")
    jira_token = os.environ.get("JIRA_TOKEN")
    project_key = os.environ.get("JIRA_PROJECT", "SEC")

    if not jira_url or not jira_token:
        print("Set JIRA_URL, JIRA_TOKEN, JIRA_PROJECT env vars")
        return

    body = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[GSC/{finding['category']}] {finding['title'][:80]}",
            "description": JIRA_TEMPLATE.format(
                title=finding['title'], category=finding['category'],
                cvss="N/A", file_path=finding.get('file_path','?'),
                line_number=finding.get('line_number',0),
                pattern=finding.get('pattern_title','N/A'),
                detail=finding.get('detail',''), fix="See gsc fix"
            ),
            "issuetype": {"name": "Bug"},
            "priority": {"name": {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium"}.get(finding['category'], "Low")}
        }
    }

    import requests
    r = requests.post(f"{jira_url}/rest/api/2/issue", json=body,
        headers={"Authorization": f"Bearer {jira_token}", "Content-Type": "application/json"})
    if r.status_code == 201:
        print(f"✅ Jira: {r.json().get('key')} — {r.json().get('self','')}")
    else:
        print(f"❌ Jira error: {r.status_code} {r.text[:200]}")


def create_linear(finding: dict):
    """Create Linear issue via GraphQL API."""
    linear_key = os.environ.get("LINEAR_API_KEY")

    if not linear_key:
        print("Set LINEAR_API_KEY env var"); return

    query = """
    mutation CreateIssue($title: String!, $description: String!, $priority: Int!) {
        issueCreate(input: {
            title: $title,
            description: $description,
            priority: $priority,
            teamId: "%s"
        }) {
            success
            issue { id url identifier }
        }
    }""" % os.environ.get("LINEAR_TEAM_ID", "")

    priority = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(finding['category'], 3)

    body = {
        "query": query,
        "variables": {
            "title": f"[GSC/{finding['category']}] {finding['title'][:80]}",
            "description": LINEAR_TEMPLATE.format(
                title=finding['title'], category=finding['category'],
                cvss="N/A", file_path=finding.get('file_path','?'),
                line_number=finding.get('line_number',0),
                pattern=finding.get('pattern_title','N/A'),
                detail=finding.get('detail',''), fix="See gsc fix"
            ),
            "priority": priority
        }
    }

    import requests
    r = requests.post("https://api.linear.app/graphql", json=body,
        headers={"Authorization": f"{linear_key}", "Content-Type": "application/json"})
    data = r.json()
    if data.get("data", {}).get("issueCreate", {}).get("success"):
        issue = data["data"]["issueCreate"]["issue"]
        print(f"✅ Linear: {issue['identifier']} — {issue['url']}")
    else:
        print(f"❌ Linear error: {r.text[:200]}")


def print_markdown(finding: dict):
    """Print a ready-to-paste markdown ticket."""
    print("```markdown")
    print(LINEAR_TEMPLATE.format(
        title=finding['title'], category=finding['category'],
        cvss="N/A", file_path=finding.get('file_path','?'),
        line_number=finding.get('line_number',0),
        pattern=finding.get('pattern_title','N/A'),
        detail=finding.get('detail',''), fix="See gsc fix"
    ))
    print("```")
    print("  ℹ️  For auto-creation set JIRA_URL/JIRA_TOKEN or LINEAR_API_KEY env vars")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gsc issue <finding-id> [--jira|--linear|--md]")
        sys.exit(1)

    finding = get_finding(sys.argv[1])
    if not finding:
        print(f"Finding #{sys.argv[1]} not found"); sys.exit(1)

    mode = sys.argv[2] if len(sys.argv) > 2 else "--md"
    if mode == "--jira":
        create_jira(finding)
    elif mode == "--linear":
        create_linear(finding)
    else:
        print_markdown(finding)
