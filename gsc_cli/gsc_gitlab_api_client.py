# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GitLab API Client (RF Enterprise, Phase 15).

Minimal GitLab REST API v4 client for MR note operations:

  - ``GitLabAPIClient`` — thin wrapper over ``requests`` with ``Private-Token``
    auth header. The token and ``base_url`` (e.g. ``https://gitlab.com/api/v4``
    or a self-hosted instance) are passed to the constructor; the module never
    reads ``os.environ`` at import time.

  - ``find_existing_note`` — list an MR's notes and locate one whose ``body``
    contains a given ``marker`` substring; returns its ``id`` or ``None``.

  - ``upsert_note`` — create or (idempotently) update a single MR note,
    identified by ``marker``, returning the note ``id`` or ``None``.

Dependencies: stdlib + ``requests`` (already a project dependency — see
``gsc_trackers.py`` and ``gsc_github_adapter.py``). No new third-party packages.
"""

import json
import urllib.parse
from typing import Optional, Any

import requests


class GitLabAPIClient:
    """GitLab REST API v4 client using ``Private-Token`` auth.

    ``base_url`` must include the API root, e.g.
    ``https://gitlab.com/api/v4`` or ``https://gitlab.example.com/api/v4``.
    The token is stored on the instance and injected into every request as the
    ``Private-Token`` header (GitLab accepts this header — see
    ``gsc_trackers.create_gitlab_issue``).
    """

    def __init__(self, token: str, base_url: str):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Private-Token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "GSC/GitLabAPIClient",
        }

    # ------------------------------------------------------------------ #
    # Low-level HTTP verbs
    # ------------------------------------------------------------------ #
    def get(self, path: str, params: Optional[dict] = None) -> Any:
        """GET ``base_url + path``; call ``raise_for_status`` and return ``.json()``.

        On non-2xx responses the raised ``HTTPError`` propagates to the caller.
        On a non-JSON body (e.g. HTML error page) ``ValueError`` is swallowed and
        ``{}`` is returned in its place.
        """
        url = f"{self.base_url}{path}"
        resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {}

    def post(self, path: str, json_data: Optional[dict] = None) -> Any:
        """POST ``base_url + path`` with a JSON body; ``raise_for_status``; return ``.json()``.

        Same tolerant JSON handling as :meth:`get`.
        """
        url = f"{self.base_url}{path}"
        resp = requests.post(url, headers=self.headers, json=json_data, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return None

    def put(self, path: str, json_data: Optional[dict] = None) -> Any:
        """PUT ``base_url + path`` with a JSON body; ``raise_for_status``; return ``.json()``.

        Same tolerant JSON handling as :meth:`get`.
        """
        url = f"{self.base_url}{path}"
        resp = requests.put(url, headers=self.headers, json=json_data, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return None


def _encode_project_path(project_path: str) -> str:
    """URL-encode a GitLab project path for use in a URL path segment.

    ``group/subgroup/project`` → ``group%2Fsubgroup%2Fproject``. Matches the
    encoding used by ``gsc_trackers.create_gitlab_issue`` (which used
    ``quote_plus``) but preserves slashes-free single-segment IDs untouched.
    """
    return urllib.parse.quote(project_path, safe="")


def find_existing_note(client: GitLabAPIClient, project_path: str,
                       mr_iid: int, marker: str) -> Optional[int]:
    """Find an existing MR note whose ``body`` contains ``marker``.

    GETs ``/projects/{encoded}/merge_requests/{iid}/notes`` (GitLab returns a
    list of note objects, each with at least ``id`` and ``body``) and returns
    the first match's ``id`` (int). Returns ``None`` when no note contains the
    marker, or when the request fails.
    """
    encoded = _encode_project_path(project_path)
    path = f"/projects/{encoded}/merge_requests/{int(mr_iid)}/notes"
    try:
        notes = client.get(path)
    except requests.RequestException:
        return None

    if not isinstance(notes, list):
        # A non-list (e.g. {} from a tolerant parse) means "no notes found".
        return None

    for note in notes:
        if isinstance(note, dict) and marker in (note.get("body") or ""):
            note_id = note.get("id")
            if isinstance(note_id, int):
                return note_id
            # Be lenient: coerce a numeric string id to int.
            if note_id is not None:
                try:
                    return int(note_id)
                except (TypeError, ValueError):
                    continue
    return None


def upsert_note(client: GitLabAPIClient, project_path: str, mr_iid: int,
                body: str, marker: str) -> Optional[int]:
    """Create or update a single MR note identified by ``marker``.

    1. ``find_existing_note`` — if a note with ``marker`` exists, ``PUT`` to
       its ``/notes/{note_id}`` endpoint with ``{"body": body}`` and return the
       existing (unchanged) note id.
    2. Otherwise ``POST`` to ``/notes`` with ``{"body": body}`` and return the
       new note id (from the server response's ``id`` field).

    Returns ``None`` on any failure (network, HTTP, or missing id in response).
    """
    encoded = _encode_project_path(project_path)
    base = f"/projects/{encoded}/merge_requests/{int(mr_iid)}/notes"

    existing_id = find_existing_note(client, project_path, int(mr_iid), marker)
    if existing_id is not None:
        try:
            client.put(f"{base}/{existing_id}", json_data={"body": body})
        except requests.RequestException:
            return None
        # The PUT response carries the updated note; preserve the original id.
        return existing_id

    try:
        created = client.post(base, json_data={"body": body})
    except requests.RequestException:
        return None

    if not isinstance(created, dict):
        return None
    note_id = created.get("id")
    if note_id is None:
        return None
    try:
        return int(note_id)
    except (TypeError, ValueError):
        return None


__all__ = [
    "GitLabAPIClient",
    "find_existing_note",
    "upsert_note",
]
