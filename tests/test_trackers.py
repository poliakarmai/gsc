#!/usr/bin/env python3
"""
tests/test_trackers.py — tests for GSC tracker adapters (Jira, Linear, GitLab)
"""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from unittest.mock import patch, MagicMock
import json

# Import the module to test
from gsc_cli.gsc_trackers import (
    create_jira_issue,
    create_linear_issue,
    create_gitlab_issue,
    format_finding_for_tracker,
    get_finding
)

# Sample finding for testing
SAMPLE_FINDING = {
    "finding_key": "abc123",
    "title": "SQL Injection in user login",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "file_path": "/app/auth.py",
    "line_number": 123,
    "snippet": "cursor.execute(\"SELECT * FROM users WHERE username='\" + username + \"'\")",
    "detail": "Untrusted input `username` is directly concatenated into a SQL query, leading to potential SQL injection vulnerabilities.",
    "poc_url": "http://example.com/poc/sql_injection_test.html"
}

def test_format_finding_for_tracker():
    """Test that the formatter produces expected markdown sections"""
    desc = format_finding_for_tracker(SAMPLE_FINDING)
    assert "### SQL Injection in user login" in desc
    assert "**Severity:** CRITICAL" in desc
    assert "**Confidence:** HIGH" in desc
    assert "**Location:** `/app/auth.py:123`" in desc
    assert "#### Description" in desc
    assert "#### Code Snippet" in desc
    assert "```python" in desc
    assert "**Proof-of-Concept/Logs:** [Link](http://example.com/poc/sql_injection_test.html)" in desc
    assert "**GSC Finding Key:** `abc123`" in desc
    print("✅ test_format_finding_for_tracker passed")

def test_create_jira_issue_success():
    """Test successful Jira issue creation with mock"""
    with patch('requests.post') as mock_post:
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "10001", "self": "https://jira.example.com/rest/api/2/issue/10001"}
        mock_post.return_value = mock_response

        # Set required env vars
        with patch.dict(os.environ, {
            "JIRA_API_BASE_URL": "https://jira.example.com",
            "JIRA_API_TOKEN": "dummy_token",
            "JIRA_EMAIL": "user@example.com"
        }):
            url = create_jira_issue("PROJ", "Test Summary", "Test Description")
            assert url == "https://jira.example.com/rest/api/2/issue/10001"
            # Verify request was made
            assert mock_post.called
            args, kwargs = mock_post.call_args
            assert args[0] == "https://jira.example.com/rest/api/2/issue"
            assert kwargs['headers']['Authorization'].startswith("Basic")
            assert kwargs['headers']['Content-Type'] == "application/json"
            payload = json.loads(kwargs['data'])
            assert payload['fields']['summary'] == "Test Summary"
            assert payload['fields']['project']['key'] == "PROJ"
            print("✅ test_create_jira_issue_success passed")

def test_create_jira_issue_missing_creds():
    """Test Jira issue creation fails when credentials missing"""
    with patch.dict(os.environ, {}, clear=True):
        url = create_jira_issue("PROJ", "Test", "Desc")
        assert url is None
        print("✅ test_create_jira_issue_missing_creds passed")

def test_create_linear_issue_success():
    """Test successful Linear issue creation with mock"""
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "issueCreate": {
                    "success": True,
                    "issue": {
                        "id": "abc123",
                        "url": "https://linear.app/team/issue/abc123"
                    }
                }
            }
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"LINEAR_API_KEY": "dummy_linear_key"}):
            url = create_linear_issue("team123", "Test Title", "Test Description")
            assert url == "https://linear.app/team/issue/abc123"
            assert mock_post.called
            args, kwargs = mock_post.call_args
            assert args[0] == "https://api.linear.app/graphql"
            assert kwargs['headers']['Authorization'] == "Bearer dummy_linear_key"
            payload = json.loads(kwargs['data'])
            assert payload['query'].strip().startswith("mutation IssueCreate")
            assert payload['variables']['teamId'] == "team123"
            assert payload['variables']['title'] == "Test Title"
            print("✅ test_create_linear_issue_success passed")

def test_create_linear_issue_missing_key():
    """Test Linear issue creation fails when API key missing"""
    with patch.dict(os.environ, {}, clear=True):
        url = create_linear_issue("team123", "Title", "Desc")
        assert url is None
        print("✅ test_create_linear_issue_missing_key passed")

def test_create_gitlab_issue_success():
    """Test successful GitLab issue creation with mock"""
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 42,
            "iid": 7,
            "project_id": 1,
            "title": "Test Issue",
            "description": "Test Description",
            "web_url": "https://gitlab.example.com/group/project/-/issues/7"
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "GITLAB_API_BASE_URL": "https://gitlab.example.com",
            "GITLAB_TOKEN": "glpat-dummytoken"
        }):
            url = create_gitlab_issue("1", "Test Title", "Test Description")
            assert url == "https://gitlab.example.com/group/project/-/issues/7"
            assert mock_post.called
            args, kwargs = mock_post.call_args
            assert args[0] == "https://gitlab.example.com/api/v4/projects/1/issues"
            assert kwargs['headers']['Private-Token'] == "glpat-dummytoken"
            payload = json.loads(kwargs['data'])
            assert payload['title'] == "Test Title"
            assert payload['description'] == "Test Description"
            print("✅ test_create_gitlab_issue_success passed")

def test_create_gitlab_issue_missing_creds():
    """Test GitLab issue creation fails when credentials missing"""
    with patch.dict(os.environ, {}, clear=True):
        url = create_gitlab_issue("1", "Test", "Desc")
        assert url is None
        print("✅ test_create_gitlab_issue_missing_creds passed")

def test_get_finding():
    """Test the placeholder get_finding function"""
    finding = get_finding("test123")
    assert finding is not None
    assert finding["finding_key"] == "test123"
    assert "SQL Injection in user login for test123" in finding["title"]
    print("✅ test_get_finding passed")

def run_all_tests():
    """Run all tests"""
    tests = [
        test_format_finding_for_tracker,
        test_create_jira_issue_success,
        test_create_jira_issue_missing_creds,
        test_create_linear_issue_success,
        test_create_linear_issue_missing_key,
        test_create_gitlab_issue_success,
        test_create_gitlab_issue_missing_creds,
        test_get_finding
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
            failed += 1
    print(f"\n🏁 Tests completed: {passed} passed, {failed} failed")
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)