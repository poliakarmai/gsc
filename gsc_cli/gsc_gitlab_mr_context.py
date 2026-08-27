# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GitLab Merge Request Context Parser (Phase 15 — RF Enterprise self-hosted).

Pure, side-effect-free helpers used by the GitLab MR adapter to extract the
minimal context slice it needs from a merge-request URL or a GitLab webhook
payload:

  * ``parse_gitlab_mr_url(url)``     — URL parser: ``https://<host>/<project>/-/merge_requests/<iid>``
                                       into a ``GitLabMRContext`` dataclass.
  * ``parse_gitlab_webhook(payload)`` — GitLab webhook payload (event
                                       ``merge_request``) into a ``GitLabMRContext``.

Both URL forms are supported:

  * gitlab.com    — ``https://gitlab.com/group/project/-/merge_requests/123``
  * self-hosted   — ``https://gitlab.company.ru/group/sub/project/-/merge_requests/5``

Design notes
------------
* No filesystem access, no environment variables, no HTTP, no I/O. Functions
  take a string / dict and return a dataclass — fully unit-testable in
  isolation. The companion transport / API client (Phase 15 follow-up) will
  read tokens at call time, never at module import time.
* The parser is best-effort: malformed input yields ``None`` rather than
  raising. Downstream callers (the future ``gsc gitlab-scan`` CLI) can
  branch on ``None`` to surface a clean "no MR context available" message
  without exception plumbing.
* Only stdlib is used (``re``, ``dataclasses``, ``urllib.parse``, ``typing``)
  — Python 3.10 compatible (no ``tomllib``, ``datetime.UTC``, ``typing.Self``,
  ``except*``).
* Backward-compatibility: this is a new module (Phase 15), no aliases
  needed. The public surface is the two parsers and the ``GitLabMRContext``
  dataclass.

Webhook payload contract
------------------------
A real GitLab ``merge_request`` webhook (Events API) carries at least::

  {
    "object_kind": "merge_request",
    "project": {
      "id": 12345,
      "path_with_namespace": "group/project",
      "web_url": "https://gitlab.company.ru/group/project",
      "http_url": "https://gitlab.company.ru/group/project.git"
    },
    "object_attributes": {
      "iid": 7,
      "source_branch": "feature",
      "target_branch": "main",
      ...
    }
  }

All four fields (``project.path_with_namespace``, ``project.id``,
``object_attributes.iid``, plus at least one of ``project.web_url`` /
``project.http_url``) are required to produce a valid context; missing
keys → ``None``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


# ── Dataclass ────────────────────────────────────────────────────────────


@dataclass
class GitLabMRContext:
    """A best-effort, parser-tolerant view of a GitLab Merge Request.

    All fields except ``mr_iid`` (int) are strings; ``valid`` is True only
    when a parser produced the context from a structurally valid input.
    The companion transport layer (Phase 15 follow-up) consumes this
    dataclass to build authenticated API calls against
    ``api_base`` = ``https://<host>/api/v4``.

    ``project_id`` is the numeric GitLab project id (``12345``) when it
    was available (webhook payloads always carry it); it is the empty
    string when the context was derived from a URL alone.
    """

    host: str = ""
    project_path: str = ""
    project_id: str = ""
    mr_iid: int = 0
    api_base: str = ""
    source_branch: str = ""
    target_branch: str = ""
    valid: bool = False

    def to_dict(self) -> dict:
        """Return a JSON-serialisable view of the context.

        ``mr_iid`` is kept as ``int`` to mirror the dataclass field; the
        transport layer is responsible for stringifying it into the URL
        path when needed.
        """
        return {
            "host": self.host,
            "project_path": self.project_path,
            "project_id": self.project_id,
            "mr_iid": self.mr_iid,
            "api_base": self.api_base,
            "source_branch": self.source_branch,
            "target_branch": self.target_branch,
            "valid": self.valid,
        }


# ── Public API ───────────────────────────────────────────────────────────

# Split the path on the GitLab MR marker ``/-/merge_requests/``. We anchor
# the marker so a project named ``something/-/merge_requests`` (unlikely
# but legal) doesn't trip the parser — the marker must be a path segment
# preceded by ``/-/``.
_MR_MARKER = "/-/merge_requests/"

# A positive integer MR iid (GitLab iids are 1-based and never zero/negative).
_IID_RE = re.compile(r"^(\d+)/?$")


def parse_gitlab_mr_url(url: str) -> Optional[GitLabMRContext]:
    """Parse a GitLab MR URL into a ``GitLabMRContext`` or return ``None``.

    Accepted forms::

      https://gitlab.com/group/project/-/merge_requests/123
      https://gitlab.company.ru/group/sub/project/-/merge_requests/5
      http://gitlab.local/group/project/-/merge_requests/7/  (trailing slash)
      https://gitlab.com/group/project/-/merge_requests/9?diff_id=1#note_1
      https://gitlab.com/group/project/-/merge_requests/9/diffs

    Trailing slashes, ``?query`` strings and ``#fragments`` are tolerated.
    A non-positive or non-integer ``iid`` is rejected (returns ``None``).
    ``http://`` is accepted so corporate deployments behind TLS-terminating
    proxies still parse; the ``api_base`` is always reconstructed as
    ``https://<host>/api/v4`` per GitLab convention regardless of the
    scheme used for the web URL.
    """
    if not isinstance(url, str) or not url.strip():
        return None

    parsed = urlparse(url.strip())
    host = (parsed.netloc or "").strip()
    if not host:
        return None

    # ``urlparse`` puts the path *and* the query/fragment together on
    # some platforms' older Python builds when the URL contains nested
    # fragments; we operate on ``parsed.path`` only and re-attach the
    # trailing path segments (e.g. ``/diffs``) below.
    path = parsed.path or ""
    if not path:
        return None

    marker_idx = path.find(_MR_MARKER)
    if marker_idx < 0:
        return None

    project_path = path[:marker_idx].strip("/")
    if not project_path:
        return None

    # Reject obvious project_path malformations: empty segments, ".." or
    # "." path components. Defensive only — GitLab never emits these.
    for segment in project_path.split("/"):
        if not segment or segment in (".", ".."):
            return None

    tail = path[marker_idx + len(_MR_MARKER):]
    # Drop any further path segments after the iid ("/diffs", "/commits",
    # etc.) — the URL contract only needs the iid.
    iid_str = tail.split("/", 1)[0].strip()
    m = _IID_RE.match(iid_str)
    if not m:
        return None
    mr_iid = int(m.group(1))
    if mr_iid <= 0:
        return None

    return GitLabMRContext(
        host=host,
        project_path=project_path,
        project_id="",
        mr_iid=mr_iid,
        api_base=f"https://{host}/api/v4",
        source_branch="",
        target_branch="",
        valid=True,
    )


def parse_gitlab_webhook(payload: dict) -> Optional[GitLabMRContext]:
    """Extract a ``GitLabMRContext`` from a GitLab webhook payload.

    Accepts the canonical ``merge_request`` event payload as documented at
    https://docs.gitlab.com/ee/user/project/integrations/webhook_events.html#merge-request-events
    — specifically the ``project`` and ``object_attributes`` sub-trees.

    Required keys (missing → ``None``):

      * ``project.path_with_namespace``  (str, e.g. ``"group/project"``)
      * ``object_attributes.iid``        (int, e.g. ``7``)

    Optional but resolved when present:

      * ``project.id``                    (int/str) → ``project_id``
      * ``project.web_url`` / ``http_url`` (str)   → host (netloc only)
      * ``object_attributes.source_branch`` (str)  → ``source_branch``
      * ``object_attributes.target_branch`` (str)  → ``target_branch``

    Non-dict payloads (``None``, lists, strings, ints) are rejected early.
    The function is defensive: every value lookup tolerates non-dict
    intermediate nodes (e.g. ``payload.get("object_attributes")`` being
    ``None``) and falls through to the ``None`` return on any missing
    critical key.
    """
    if not isinstance(payload, dict):
        return None

    project = payload.get("project")
    object_attributes = payload.get("object_attributes")
    if not isinstance(project, dict) or not isinstance(object_attributes, dict):
        return None

    project_path = project.get("path_with_namespace")
    iid = object_attributes.get("iid")
    if not isinstance(project_path, str) or not project_path.strip():
        return None
    if not isinstance(iid, int) or iid <= 0:
        # Some GitLab webhook variants serialise iid as a string; be
        # lenient but only when the string is a clean positive int.
        if isinstance(iid, str) and iid.strip().isdigit() and int(iid.strip()) > 0:
            iid = int(iid.strip())
        else:
            return None

    # Reject obvious path malformations — mirrors parse_gitlab_mr_url().
    for segment in project_path.strip().split("/"):
        if not segment or segment in (".", ".."):
            return None

    # Resolve host: prefer ``web_url`` (canonical, points at the project
    # view), fall back to ``http_url`` (clone URL with ``.git`` suffix),
    # then ``git_http_url`` / ``ssh_url`` (less common). When none of
    # these is available we still produce a context but with an empty
    # host — ``api_base`` is then ``https:///api/v4`` which the transport
    # layer will reject. We deliberately return ``None`` in that case
    # because a context without a target host is unusable.
    host = _extract_host(project)
    if not host:
        return None

    # project_id may be int or string depending on GitLab version.
    raw_project_id = project.get("id", "")
    if isinstance(raw_project_id, int):
        project_id = str(raw_project_id)
    elif isinstance(raw_project_id, str) and raw_project_id.strip():
        project_id = raw_project_id.strip()
    else:
        project_id = ""

    source_branch = object_attributes.get("source_branch") or ""
    target_branch = object_attributes.get("target_branch") or ""
    if not isinstance(source_branch, str):
        source_branch = ""
    if not isinstance(target_branch, str):
        target_branch = ""

    return GitLabMRContext(
        host=host,
        project_path=project_path.strip(),
        project_id=project_id,
        mr_iid=iid,
        api_base=f"https://{host}/api/v4",
        source_branch=source_branch,
        target_branch=target_branch,
        valid=True,
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _extract_host(project: dict) -> str:
    """Return the netloc (host[:port]) of the GitLab instance, or ``""``.

    Inspects the URL fields GitLab exposes on the ``project`` object,
    in order of preference. ``web_url`` is the canonical web link;
    ``http_url`` is the clone URL (``*.git`` suffix); ``git_http_url``
    and ``ssh_url`` are last-resort fallbacks because ``ssh_url`` does
    not contain a usable HTTP host.

    A non-string value at any candidate key is silently skipped, not
    treated as a hard error — the parser tolerates partial payloads
    so a webhook replayed from disk after a partial deserialise still
    yields a usable host when at least one URL is intact.
    """
    for key in ("web_url", "http_url", "git_http_url"):
        candidate = project.get(key)
        if isinstance(candidate, str) and candidate.strip():
            parsed = urlparse(candidate.strip())
            if parsed.netloc:
                return parsed.netloc
    return ""
