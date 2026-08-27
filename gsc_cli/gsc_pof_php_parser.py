# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""PHP / Composer PoF Project Parser (Phase 14 — PoF multilingualism: PHP).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a PHP / Composer project and extract the minimal manifest slice it needs:

  * ``detect_php_project(files)``     — presence check of ``composer.json``
    in a file list (case-insensitive, basename only).
  * ``parse_composer_json(content)`` — tolerant JSON loader that returns a
    ``ComposerProject`` dataclass with ``name``, ``require`` and
    ``require-dev`` dependency maps. Never raises on malformed input —
    the PoF orchestrator is allowed to proceed with an empty result and
    try a different strategy.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser mirrors ``gsc_pof_node_parser`` 1:1 because ``composer.json``
  is structurally a near-twin of ``package.json``: an object with a string
  ``name`` and two string-to-string maps (``require`` / ``require-dev``).
  We share the same tolerant preclean (BOM + ``//`` line comments) and
  the same "non-string value => keep as ``str()``" coercion policy.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.
* Stdlib only (``json``, ``re``, ``dataclasses``, ``typing``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a composer.json candidate when its basename is
# exactly "composer.json" (case-insensitive). The PoF pipeline is run on
# already-walked file lists, so we don't try to guess paths here.
_COMPOSER_JSON_BASENAME = "composer.json"

# Strip BOM (utf-8-sig) and JS-style // line comments which some legacy
# tools embed in hand-edited composer.json files. Block comments are rare
# in JSON and not stripped — that would require a real parser.
_BOM = "\ufeff"
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)


@dataclass
class ComposerProject:
    """A best-effort, parser-tolerant view of a PHP ``composer.json``.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty, not parseable as JSON, not an object, missing the
    ``name`` field, or had a non-dict ``require`` section — the PoF
    orchestrator can use that flag to skip PHP-specific fix strategies
    without surfacing a hard error.
    """

    valid: bool = False
    name: str = ""
    require: dict[str, str] = field(default_factory=dict)
    require_dev: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "name": self.name,
            "require": dict(self.require),
            "require-dev": dict(self.require_dev),
        }

    def require_for(self, name: str) -> str | None:
        """Return the version constraint for the given package, or None.

        Looks up ``name`` first in ``require`` and then in ``require-dev``,
        matching the resolution order the Composer runtime itself uses
        when a package appears in both maps (``require`` wins). Returns
        ``None`` if the package is not declared in either map.
        """
        if not isinstance(name, str) or not name:
            return None
        if name in self.require:
            return self.require[name]
        if name in self.require_dev:
            return self.require_dev[name]
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_php_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``composer.json``.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match Windows / macOS
    filesystems where ``Composer.JSON`` would otherwise be invisible.
    """
    if not files:
        return False
    target = _COMPOSER_JSON_BASENAME.lower()
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


def parse_composer_json(content: str) -> ComposerProject:
    """Parse a ``composer.json`` string into a ``ComposerProject``.

    Tolerant: empty input, non-JSON, JSON values of the wrong type, and
    a missing or non-string ``name`` (or a non-dict ``require``) all
    yield ``ComposerProject(valid=False)`` with empty fields rather than
    raising. The PoF orchestrator can then decide to skip the
    PHP-specific strategy without catching exceptions.
    """
    if not isinstance(content, str) or not content.strip():
        return ComposerProject(valid=False)

    cleaned = _preclean(content)
    try:
        data = json.loads(cleaned)
    except (ValueError, json.JSONDecodeError):
        return ComposerProject(valid=False)

    if not isinstance(data, dict):
        return ComposerProject(valid=False)

    name = _as_str(data.get("name"))
    require = _coerce_dep_map(data.get("require"))

    # A "require" map is the structural core of composer.json — without
    # one we cannot meaningfully run Composer-based fix strategies, so we
    # mark the result as invalid. ``require-dev`` is optional.
    if not name or not require:
        return ComposerProject(valid=False, name=name)

    require_dev = _coerce_dep_map(data.get("require-dev"))

    return ComposerProject(
        valid=True,
        name=name,
        require=require,
        require_dev=require_dev,
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


def _coerce_dep_map(value) -> dict[str, str]:
    """Build a {name: version_spec} dict from a JSON object.

    Composer is forgiving: a non-string version is kept as its ``str()``
    representation, matching the SCA-side parser in ``gsc_sca`` and the
    Node.js parser in ``gsc_pof_node_parser``. Empty or non-dict inputs
    return ``{}``.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            continue
        out[k] = str(v) if v is not None else ""
    return out
