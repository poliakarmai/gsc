# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Tracker Adapters v0.1 — Jira, Linear, GitLab Issue Creation
"""

import os
import json
import requests  # Using requests as in gsc_github_adapter.py
from typing import Optional, Any
from pathlib import Path
from datetime import datetime, timezone

# Credentials are read from os.environ inside each function (not at import
# time), so tests can override them with unittest.mock.patch.dict.

# --- Issue Formatting ---

def format_finding_for_tracker(finding: dict) -> str:
    """
    Formats a GSC finding into a Markdown description suitable for issue trackers.
    Reuses the structure from gsc_github_adapter where applicable.
    """
    lines = []
    lines.append(f"### {finding.get('title', 'GSC Security Finding')}")
    lines.append("")
    
    severity = finding.get('severity', 'UNKNOWN').upper()
    confidence = finding.get('confidence', 'UNKNOWN').upper()
    
    lines.append(f"**Severity:** {severity}")
    lines.append(f"**Confidence:** {confidence}")
    lines.append("")

    # File and line
    file_path = finding.get('file_path')
    line_number = finding.get('line_number')
    if file_path and line_number:
        lines.append(f"**Location:** `{file_path}:{line_number}`")
        lines.append("")

    # Description/Detail
    detail = finding.get('detail')
    if detail:
        lines.append("#### Description")
        lines.append(detail)
        lines.append("")

    # Snippet
    snippet = finding.get('snippet')
    if snippet:
        lines.append("#### Code Snippet")
        lines.append("```python") # Assuming python for now, can be improved later
        lines.append(snippet)
        lines.append("```")
        lines.append("")

    # PoC/Logs
    poc_url = finding.get('poc_url')
    if poc_url:
        lines.append(f"**Proof-of-Concept/Logs:** [Link]({poc_url})")
        lines.append("")
    
    # Finding Key
    finding_key = finding.get('finding_key')
    if finding_key:
        lines.append(f"**GSC Finding Key:** `{finding_key}`")
        lines.append("")

    return "\n".join(lines)

# --- Jira Adapter ---

def create_jira_issue(project_key: str, summary: str, description: str, **opts) -> Optional[str]:
    """
    Creates a Jira issue.
    Returns the URL of the created issue or None on failure.
    Requires JIRA_API_BASE_URL, JIRA_API_TOKEN, JIRA_EMAIL environment variables.
    """
    jira_base = os.environ.get("JIRA_API_BASE_URL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_email = os.environ.get("JIRA_EMAIL")
    if not all([jira_base, jira_token, jira_email]):
        print("❌ Jira credentials missing. Set JIRA_API_BASE_URL, JIRA_API_TOKEN, JIRA_EMAIL.")
        return None

    issue_type = opts.get("issue_type", "Bug")
    priority = opts.get("priority", "Medium")

    url = f"{jira_base}/rest/api/2/issue"
    headers = {
        "Authorization": f"Basic {os.environ.get('JIRA_BASIC_AUTH', '')}", # JIRA_BASIC_AUTH is base64(email:token)
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Try to generate basic auth if not provided
    if "JIRA_BASIC_AUTH" not in os.environ and jira_email and jira_token:
        import base64
        user_pass = f"{jira_email}:{jira_token}".encode("ascii")
        headers["Authorization"] = f"Basic {base64.b64encode(user_pass).decode('ascii')}"

    payload = json.dumps({
        "fields": {
            "project": {
                "key": project_key
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": issue_type
            },
            "priority": {
                "name": priority
            }
        }
    })

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=20)
        response.raise_for_status()
        issue_data = response.json()
        issue_url = issue_data.get("self", "")
        print(f"✅ Jira issue created: {issue_url}")
        return issue_url
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating Jira issue: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return None

# --- Linear Adapter ---

def create_linear_issue(team_id: str, title: str, description: str, **opts) -> Optional[str]:
    """
    Creates a Linear issue.
    Returns the URL of the created issue or None on failure.
    Requires LINEAR_API_KEY environment variable.
    """
    linear_key = os.environ.get("LINEAR_API_KEY")
    if not linear_key:
        print("❌ Linear API key missing. Set LINEAR_API_KEY.")
        return None

    url = os.environ.get("LINEAR_API_BASE_URL", "https://api.linear.app/graphql")
    headers = {
        "Authorization": f"Bearer {linear_key}",
        "Content-Type": "application/json",
    }

    # Linear uses GraphQL
    query = """
    mutation IssueCreate($teamId: String!, $title: String!, $description: String) {
      issueCreate(
        input: {
          teamId: $teamId,
          title: $title,
          description: $description
        }
      ) {
        success
        issue {
          id
          url
        }
      }
    }
    """
    variables = {
        "teamId": team_id,
        "title": title,
        "description": description,
    }

    payload = json.dumps({"query": query, "variables": variables})

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=20)
        response.raise_for_status()
        response_data = response.json()
        
        if response_data.get("errors"):
            print(f"❌ Error creating Linear issue: {response_data['errors']}")
            return None

        issue_data = response_data.get("data", {}).get("issueCreate", {}).get("issue", {})
        issue_url = issue_data.get("url")
        if issue_url:
            print(f"✅ Linear issue created: {issue_url}")
            return issue_url
        else:
            print("❌ Linear issue URL not found in response.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating Linear issue: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return None

# --- GitLab Adapter ---

def create_gitlab_issue(project_id: str, title: str, description: str, **opts) -> Optional[str]:
    """
    Creates a GitLab issue.
    Returns the URL of the created issue or None on failure.
    Requires GITLAB_API_BASE_URL, GITLAB_TOKEN environment variables.
    """
    gitlab_base = os.environ.get("GITLAB_API_BASE_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    if not all([gitlab_base, gitlab_token]):
        print("❌ GitLab credentials missing. Set GITLAB_API_BASE_URL, GITLAB_TOKEN.")
        return None

    # GitLab API expects project_id to be URL-encoded if it's a path (e.g., 'group/subgroup/project')
    # Or just the numeric ID. Assuming numeric ID or already encoded path for simplicity here.
    import urllib.parse
    encoded_project_id = urllib.parse.quote_plus(project_id) 

    url = f"{gitlab_base}/api/v4/projects/{encoded_project_id}/issues"
    headers = {
        "Private-Token": gitlab_token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = json.dumps({
        "title": title,
        "description": description,
        "labels": opts.get("labels", []),
        "milestone_id": opts.get("milestone_id"),
        "assignee_ids": opts.get("assignee_ids", []),
    })

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=20)
        response.raise_for_status()
        issue_data = response.json()
        issue_url = issue_data.get("web_url")
        if issue_url:
            print(f"✅ GitLab issue created: {issue_url}")
            return issue_url
        else:
            print("❌ GitLab issue URL not found in response.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating GitLab issue: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response: {e.response.text}")
        return None

# --- Main CLI integration (Placeholder for now) ---
# This part will be integrated into gsc_cli/main.py or gsc_issue.py
# For now, it's just here for context

def get_finding(finding_id: str) -> Optional[dict]:
    """
    Placeholder: retrieves a finding by ID.
    In a real scenario, this would query the GSC database.
    """
    print(f"Retrieving finding {finding_id}...")
    # Mock finding for testing
    return {
        "finding_key": finding_id,
        "title": f"SQL Injection in user login for {finding_id}",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "file_path": "/app/auth.py",
        "line_number": 123,
        "snippet": "cursor.execute(\"SELECT * FROM users WHERE username='\" + username + \"'\")",
        "detail": "Untrusted input `username` is directly concatenated into a SQL query, leading to potential SQL injection vulnerabilities.",
        "poc_url": "http://example.com/poc/sql_injection_test.html"
    }

def print_markdown(finding: dict):
    print("--- Markdown Issue Description ---")
    print(format_finding_for_tracker(finding))
    print("----------------------------------")