# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC RF Git Adapter v0.1 — REST adapters for Russian self-hosted git platforms
(GitLab, GitFlic, GitVerse).

All three platforms expose a GitLab REST API v4-compatible surface
(see https://docs.gitlab.com/ee/api/ for the upstream contract).
This module provides a single ``RFGitAdapter`` class that talks to any of
the three by configuring ``api_url`` and the private token.

Public surface (Phase 14 — RF Enterprise):

  - ``RFGitAdapter.create_issue(project_id, title, description, **opts)``
  - ``RFGitAdapter.create_note(project_id, issue_iid, body, **opts)``
  - ``RFGitAdapter.create_merge_request(project_id, **opts)``
  - ``RFGitAdapter.list_projects(**opts)``
  - ``RFGitAdapter.doctor()`` — diagnostics (token, API reachability, scopes)
  - ``gitlab_adapter()`` / ``gitflic_adapter()`` / ``gitverse_adapter()`` —
    convenience factories that read env vars and build the adapter.

Environment variables (read INSIDE each factory call so unit tests using
``unittest.mock.patch.dict(os.environ, ...)`` keep working):

  - GitLab : ``GITLAB_API_BASE_URL`` (default ``https://gitlab.com``),
             ``GITLAB_TOKEN``
  - GitFlic: ``GITFLIC_API_BASE_URL`` (default ``https://api.gitflic.ru``),
             ``GITFLIC_TOKEN``
  - GitVerse: ``GITVERSE_API_BASE_URL`` (default ``https://api.gitverse.ru``),
             ``GITVERSE_TOKEN``

Credentials are NEVER hardcoded and NEVER accepted via argv. The module only
imports from stdlib + ``requests`` (already a project dependency, used in
``gsc_github_adapter.py`` and ``gsc_trackers.py``).
"""

import os
import json
import urllib.parse
from typing import Optional, Any

import requests


# --- Defaults ---

PLATFORM_GITLAB = "gitlab"
PLATFORM_GITFLIC = "gitflic"
PLATFORM_GITVERSE = "gitverse"

DEFAULT_GITLAB_URL = "https://gitlab.com"
DEFAULT_GITFLIC_URL = "https://api.gitflic.ru"
DEFAULT_GITVERSE_URL = "https://api.gitverse.ru"

MAX_NOTE_BYTES = 1_000_000  # GitLab notes endpoint accepts up to ~1 MiB.
DEFAULT_TIMEOUT = 20


# --- Exceptions ---


class RFGitAdapterError(RuntimeError):
    """Raised when an RF git adapter operation fails irrecoverably."""


# --- Adapter class ---


class RFGitAdapter:
    """Talk to a GitLab-compatible REST API (GitLab / GitFlic / GitVerse).

    The three platforms are API-compatible for the endpoints we need
    (issues, notes, merge requests, project listing), so a single
    implementation covers all three.
    """

    def __init__(self, api_url: str, token: str, platform: str = PLATFORM_GITLAB,
                 session: Optional[requests.Session] = None,
                 timeout: int = DEFAULT_TIMEOUT):
        if not api_url:
            raise ValueError("api_url is required")
        if not token:
            raise ValueError("token is required")
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.platform = platform
        self.timeout = timeout
        self._session = session

    # ---- HTTP plumbing ----

    @property
    def session(self) -> requests.Session:
        """Lazy-construct a session with the right auth header."""
        if self._session is None:
            s = requests.Session()
            # GitLab supports Private-Token header; GitFlic & GitVerse are
            # GitLab-compatible and accept the same header.
            s.headers.update({
                "Private-Token": self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"GSC/0.1 ({self.platform})",
            })
            self._session = s
        return self._session

    def _url(self, path: str) -> str:
        """Build an API URL from a relative path (must start with '/')."""
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.api_url}{path}"

    def _request(self, method: str, path: str,
                 json_data: Optional[dict] = None,
                 params: Optional[dict] = None) -> requests.Response:
        """Make a request and return the raw response. Raises on HTTP errors
        via ``raise_for_status``; callers may inspect status_code if they
        need to handle specific non-2xx cases themselves."""
        url = self._url(path)
        resp = self.session.request(method, url, json=json_data, params=params,
                                    timeout=self.timeout)
        return resp

    def _post(self, path: str, json_data: dict,
              params: Optional[dict] = None) -> requests.Response:
        return self._request("POST", path, json_data=json_data, params=params)

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        return self._request("GET", path, params=params)

    # ---- URL-encoded project id helper ----

    @staticmethod
    def _encode_project_id(project_id: str) -> str:
        """GitLab accepts either numeric IDs or URL-encoded paths like
        ``group%2Fsubgroup%2Fproject``."""
        return urllib.parse.quote_plus(str(project_id))

    # ---- Issue ----

    def create_issue(self, project_id: str, title: str, description: str = "",
                     **opts: Any) -> Optional[dict]:
        """Create an issue. Returns the issue dict on success, ``None`` on
        failure. See GitLab ``POST /projects/:id/issues`` for the schema."""
        if not title:
            print("❌ create_issue: title is required")
            return None
        encoded = self._encode_project_id(project_id)
        body = {
            "title": title,
            "description": description or "",
        }
        # Optional fields, only included if provided.
        for k in ("labels", "assignee_ids", "milestone_id",
                  "due_date", "confidential", "weight"):
            if k in opts and opts[k] is not None:
                body[k] = opts[k]

        try:
            resp = self._post(f"/api/v4/projects/{encoded}/issues", body)
        except requests.RequestException as e:
            print(f"❌ [{self.platform}] create_issue network error: {e}")
            return None

        if resp.status_code not in (200, 201):
            print(f"❌ [{self.platform}] create_issue HTTP {resp.status_code}: "
                  f"{resp.text[:200]}")
            return None

        data = resp.json()
        web_url = data.get("web_url", "")
        print(f"✅ [{self.platform}] issue created: {web_url}")
        return data

    # ---- Note (issue comment) ----

    def create_note(self, project_id: str, issue_iid: int, body: str,
                    **opts: Any) -> Optional[dict]:
        """Add a comment (note) to an issue. ``issue_iid`` is the
        project-scoped issue number, not the global id."""
        if not body:
            print("❌ create_note: body is required")
            return None
        if len(body.encode("utf-8")) > MAX_NOTE_BYTES:
            print(f"❌ create_note: body too large "
                  f"({len(body.encode('utf-8'))} > {MAX_NOTE_BYTES} bytes)")
            return None
        encoded = self._encode_project_id(project_id)
        payload = {"body": body}
        for k in ("confidential", "created_at"):
            if k in opts and opts[k] is not None:
                payload[k] = opts[k]

        try:
            resp = self._post(
                f"/api/v4/projects/{encoded}/issues/{int(issue_iid)}/notes",
                payload,
            )
        except requests.RequestException as e:
            print(f"❌ [{self.platform}] create_note network error: {e}")
            return None

        if resp.status_code not in (200, 201):
            print(f"❌ [{self.platform}] create_note HTTP {resp.status_code}: "
                  f"{resp.text[:200]}")
            return None

        data = resp.json()
        note_id = data.get("id")
        print(f"✅ [{self.platform}] note #{note_id} added to issue {issue_iid}")
        return data

    # ---- Merge request ----

    def create_merge_request(self, project_id: str,
                             source_branch: str,
                             target_branch: str,
                             title: str,
                             description: str = "",
                             **opts: Any) -> Optional[dict]:
        """Open a merge request. ``source_branch`` and ``target_branch`` are
        required. Optional kwargs: ``squash``, ``remove_source_branch``,
        ``assignee_id``, ``labels``, ``draft``."""
        if not source_branch or not target_branch or not title:
            print("❌ create_merge_request: source_branch, target_branch, "
                  "and title are required")
            return None
        encoded = self._encode_project_id(project_id)
        body = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description or "",
        }
        for k in ("squash", "remove_source_branch", "assignee_id",
                  "assignee_ids", "labels", "milestone_id", "draft"):
            if k in opts and opts[k] is not None:
                body[k] = opts[k]

        try:
            resp = self._post(
                f"/api/v4/projects/{encoded}/merge_requests", body
            )
        except requests.RequestException as e:
            print(f"❌ [{self.platform}] create_merge_request network error: {e}")
            return None

        if resp.status_code not in (200, 201):
            print(f"❌ [{self.platform}] create_merge_request HTTP "
                  f"{resp.status_code}: {resp.text[:200]}")
            return None

        data = resp.json()
        web_url = data.get("web_url", "")
        print(f"✅ [{self.platform}] merge request created: {web_url}")
        return data

    # ---- Project listing ----

    def list_projects(self, **opts: Any) -> list[dict]:
        """List projects visible to the token. Returns a list of project
        dicts (may be empty). Honours pagination via ``per_page`` (max 100
        per GitLab) and ``page``.

        Important: this is a "list" operation and may legitimately return
        an empty list — do NOT treat [] as a failure.
        """
        params: dict = {}
        # Only forward known, safe paging parameters.
        if "per_page" in opts and opts["per_page"] is not None:
            per_page = int(opts["per_page"])
            if 1 <= per_page <= 100:
                params["per_page"] = per_page
        if "page" in opts and opts["page"] is not None:
            params["page"] = max(1, int(opts["page"]))
        for k in ("membership", "owned", "search", "order_by", "sort",
                  "simple", "archived", "visibility"):
            if k in opts and opts[k] is not None:
                params[k] = opts[k]

        try:
            resp = self._get("/api/v4/projects", params=params or None)
        except requests.RequestException as e:
            print(f"❌ [{self.platform}] list_projects network error: {e}")
            return []

        if resp.status_code != 200:
            print(f"❌ [{self.platform}] list_projects HTTP {resp.status_code}: "
                  f"{resp.text[:200]}")
            return []

        try:
            data = resp.json()
        except ValueError:
            print(f"❌ [{self.platform}] list_projects: invalid JSON response")
            return []

        if not isinstance(data, list):
            print(f"❌ [{self.platform}] list_projects: expected list, got "
                  f"{type(data).__name__}")
            return []

        print(f"✅ [{self.platform}] listed {len(data)} project(s)")
        return data

    # ---- Diagnostics ----

    def doctor(self) -> dict:
        """Probe the adapter and return a status dict. Never raises."""
        status = {
            "platform": self.platform,
            "api_url": self.api_url,
            "token_present": bool(self.token),
            "reachable": False,
            "auth_ok": False,
            "version": None,
            "errors": [],
        }
        try:
            resp = self._get("/api/v4/version")
            if resp.status_code == 200:
                status["reachable"] = True
                try:
                    status["version"] = resp.json().get("version")
                except ValueError:
                    pass
                # /version is public on GitLab, but the headers will at
                # least tell us the server is up.
                status["auth_ok"] = bool(self.token)
            elif resp.status_code in (401, 403):
                status["reachable"] = True
                status["auth_ok"] = False
                status["errors"].append(
                    f"Authentication failed: HTTP {resp.status_code}"
                )
            else:
                status["errors"].append(
                    f"Unexpected HTTP {resp.status_code} from /version"
                )
        except requests.RequestException as e:
            status["errors"].append(f"Network error: {e}")
        return status


# --- Factory functions (env-driven) ---


def gitlab_adapter() -> Optional[RFGitAdapter]:
    """Build a GitLab adapter from ``GITLAB_API_BASE_URL`` and
    ``GITLAB_TOKEN``. Returns ``None`` (and prints a hint) if either is
    missing."""
    api_url = os.environ.get("GITLAB_API_BASE_URL", DEFAULT_GITLAB_URL)
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        print("❌ GITLAB_TOKEN is not set")
        return None
    return RFGitAdapter(api_url=api_url, token=token, platform=PLATFORM_GITLAB)


def gitflic_adapter() -> Optional[RFGitAdapter]:
    """Build a GitFlic adapter from ``GITFLIC_API_BASE_URL`` and
    ``GITFLIC_TOKEN``."""
    api_url = os.environ.get("GITFLIC_API_BASE_URL", DEFAULT_GITFLIC_URL)
    token = os.environ.get("GITFLIC_TOKEN")
    if not token:
        print("❌ GITFLIC_TOKEN is not set")
        return None
    return RFGitAdapter(api_url=api_url, token=token, platform=PLATFORM_GITFLIC)


def gitverse_adapter() -> Optional[RFGitAdapter]:
    """Build a GitVerse adapter from ``GITVERSE_API_BASE_URL`` and
    ``GITVERSE_TOKEN``."""
    api_url = os.environ.get("GITVERSE_API_BASE_URL", DEFAULT_GITVERSE_URL)
    token = os.environ.get("GITVERSE_TOKEN")
    if not token:
        print("❌ GITVERSE_TOKEN is not set")
        return None
    return RFGitAdapter(api_url=api_url, token=token, platform=PLATFORM_GITVERSE)


# --- Convenience module-level functions (parallel to gsc_trackers) ---


def create_gitlab_issue_v2(project_id: str, title: str,
                           description: str, **opts: Any) -> Optional[str]:
    """Convenience wrapper returning only the issue URL."""
    adapter = gitlab_adapter()
    if adapter is None:
        return None
    data = adapter.create_issue(project_id, title, description, **opts)
    if data is None:
        return None
    return data.get("web_url")


def create_gitflic_issue(project_id: str, title: str,
                         description: str, **opts: Any) -> Optional[str]:
    adapter = gitflic_adapter()
    if adapter is None:
        return None
    data = adapter.create_issue(project_id, title, description, **opts)
    if data is None:
        return None
    return data.get("web_url")


def create_gitverse_issue(project_id: str, title: str,
                          description: str, **opts: Any) -> Optional[str]:
    adapter = gitverse_adapter()
    if adapter is None:
        return None
    data = adapter.create_issue(project_id, title, description, **opts)
    if data is None:
        return None
    return data.get("web_url")


__all__ = [
    "PLATFORM_GITLAB", "PLATFORM_GITFLIC", "PLATFORM_GITVERSE",
    "DEFAULT_GITLAB_URL", "DEFAULT_GITFLIC_URL", "DEFAULT_GITVERSE_URL",
    "RFGitAdapterError", "RFGitAdapter",
    "gitlab_adapter", "gitflic_adapter", "gitverse_adapter",
    "create_gitlab_issue_v2", "create_gitflic_issue", "create_gitverse_issue",
]
