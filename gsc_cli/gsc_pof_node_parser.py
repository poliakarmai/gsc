# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Node.js PoF Project Parser (Phase 14 — PoF multilingualism: start with Node.js).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a Node.js project and extract the minimal manifest slice it needs:

  * ``detect_node_project(files)``  — presence check of ``package.json`` in
    a file list (case-insensitive, basename only).
  * ``parse_package_json(content)`` — tolerant JSON loader that returns a
    ``NodeProject`` dataclass with ``name``, ``main`` entry point, ``scripts``
    and dependency maps. Never raises on malformed input — the PoF orchestrator
    is allowed to proceed with an empty result and try a different strategy.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The function is intentionally permissive: missing fields, non-dict ``scripts``,
  non-string values, BOM, comments, trailing commas, and ``// line comments``
  inside JSON are all accepted as "no value" rather than as fatal errors. That
  is consistent with the GSC approach of "best-effort manifest read; flag
  uncertain results downstream" — see gsc_sca.parse_package_json for the
  parallel SCA-side parser.
* No third-party dependencies. The stdlib ``json`` loader accepts only
  strict JSON, so we apply small, well-known cleanups before parsing.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable


# A file is considered a package.json candidate when its basename is
# exactly "package.json" (case-insensitive). The PoF pipeline is run on
# already-walked file lists, so we don't try to guess paths here.
_PACKAGE_JSON_BASENAME = "package.json"

# Strip BOM (utf-8-sig) and JS-style // line comments which some legacy
# tools embed in hand-edited package.json files. Block comments are rare
# in JSON and not stripped — that would require a real parser.
_BOM = "\ufeff"
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)


@dataclass
class NodeScript:
    """A single entry from the ``scripts`` map of package.json.

    ``name`` is the npm script name (``"test"``, ``"start"`` …);
    ``command`` is the shell command string.
    """

    name: str
    command: str

    def to_dict(self) -> dict:
        return {"name": self.name, "command": self.command}


@dataclass
class NodeProject:
    """A best-effort, parser-tolerant view of a Node.js package.json.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty or not parseable as JSON object — the PoF orchestrator
    can use that flag to skip Node-specific fix strategies without
    surfacing a hard error.
    """

    valid: bool = False
    name: str = ""
    version: str = ""
    main: str = ""
    scripts: list[NodeScript] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    dev_dependencies: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "name": self.name,
            "version": self.version,
            "main": self.main,
            "scripts": [s.to_dict() for s in self.scripts],
            "dependencies": dict(self.dependencies),
            "devDependencies": dict(self.dev_dependencies),
        }

    def script(self, name: str) -> str:
        """Return the command for the given npm script, or "" if absent.

        Helper for the PoF orchestrator: "if package.json has a 'test'
        script, run it after the fix to make sure the patch didn't break
        the build".
        """
        for s in self.scripts:
            if s.name == name:
                return s.command
        return ""


# ── Public API ───────────────────────────────────────────────────────────


def detect_node_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``package.json``.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match Windows / macOS
    filesystems where ``Package.JSON`` would otherwise be invisible.
    """
    if not files:
        return False
    target = _PACKAGE_JSON_BASENAME.lower()
    for f in files:
        if not isinstance(f, str):
            continue
        # os.path.basename is avoided to keep the helper purely functional
        # and free of filesystem semantics; split on both / and \ so we
        # work on POSIX and Windows-style paths.
        base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base.lower() == target:
            return True
    return False


def parse_package_json(content: str) -> NodeProject:
    """Parse a ``package.json`` string into a ``NodeProject``.

    Tolerant: empty input, non-JSON, and JSON values of the wrong type
    all yield a ``NodeProject(valid=False)`` with empty fields rather
    than raising. The PoF orchestrator can then decide to skip the
    Node-specific strategy without catching exceptions.
    """
    if not isinstance(content, str) or not content.strip():
        return NodeProject(valid=False)

    cleaned = _preclean(content)
    try:
        data = json.loads(cleaned)
    except (ValueError, json.JSONDecodeError):
        return NodeProject(valid=False)

    if not isinstance(data, dict):
        return NodeProject(valid=False)

    name = _as_str(data.get("name"))
    version = _as_str(data.get("version"))
    main = _as_str(data.get("main"))
    scripts = _coerce_scripts(data.get("scripts"))
    dependencies = _coerce_dep_map(data.get("dependencies"))
    dev_dependencies = _coerce_dep_map(data.get("devDependencies"))

    return NodeProject(
        valid=True,
        name=name,
        version=version,
        main=main,
        scripts=scripts,
        dependencies=dependencies,
        dev_dependencies=dev_dependencies,
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _preclean(content: str) -> str:
    """Strip BOM and // line comments from a JSON-ish text.

    Conservative: only removes comments that occupy a whole line. We do
    NOT attempt to strip block comments or inline ``//`` after values —
    doing so safely requires a real JSON-with-comments parser, which is
    out of scope for a best-effort manifest reader.
    """
    if content.startswith(_BOM):
        content = content[len(_BOM):]
    return _LINE_COMMENT.sub("", content)


def _as_str(value) -> str:
    """Return ``value`` if it is a non-empty string, else ``""``."""
    if isinstance(value, str) and value:
        return value
    return ""


def _coerce_scripts(value) -> list[NodeScript]:
    """Build a list of NodeScript from a JSON object, dropping non-strings."""
    if not isinstance(value, dict):
        return []
    out: list[NodeScript] = []
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            continue
        cmd = _as_str(v)
        out.append(NodeScript(name=k, command=cmd))
    # Stable, alphabetical order — easier to test and reason about.
    out.sort(key=lambda s: s.name)
    return out


def _coerce_dep_map(value) -> dict[str, str]:
    """Build a {name: version_spec} dict from a JSON object.

    npm / yarn are forgiving: a non-string version is kept as its ``str()``
    representation, matching the SCA-side parser in ``gsc_sca``. Empty
    or non-dict inputs return ``{}``.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            continue
        out[k] = str(v) if v is not None else ""
    return out
