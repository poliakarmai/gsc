# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""uv PoF Project Parser (Phase 14 — PoF multilingualism: uv / Python).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a Python project managed by `uv` (https://docs.astral.sh/uv/) and extract the
minimal manifest slice it needs:

  * ``detect_uv_project(files)`` — presence check of ``uv.lock`` in a
    file list (case-insensitive, basename only).
  * ``parse_uv_lock(content)`` — line-based parser that extracts the
    top-level ``requires-python`` value and every ``[[package]]`` table's
    ``name`` / ``version`` pair. Dependency lists and source blocks are
    tolerated and must not break the parse.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser is best-effort: malformed input yields an
  ``UvProject(valid=False)`` with empty fields rather than raising. The
  PoF orchestrator can then skip uv-specific fix strategies without
  catching exceptions.
* Stdlib only (``re``). Intentionally NOT using ``tomllib`` (Python 3.11+)
  or ``tomli`` — CI still runs Python 3.10. uv.lock is a TOML-like
  document but we only need a thin slice, so a regex-based scan is
  sufficient and keeps the dependency surface at zero.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.

uv.lock grammar (relevant subset)
---------------------------------
  version = 1
  requires-python = ">=3.11"

  [manifest]
  members = ["myapp"]

  [[package]]
  name = "click"
  version = "8.1.7"
  source = { registry = "https://pypi.org/simple" }
  dependencies = [
      { name = "colorama" },
  ]
  sdist = { url = "https://...", hash = "sha256:..." }
  wheels = [ { url = "https://...", hash = "sha256:..." } ]

Other sections (``[tool.uv]``, ``[[tool.uv.index]]``, ``[manifest.*]``)
are ignored — they don't change the resolved set of Python packages.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a uv.lock candidate when its basename is exactly
# "uv.lock" (case-insensitive). The PoF pipeline is run on already-walked
# file lists, so we don't try to guess paths here.
_UV_LOCK_BASENAME = "uv.lock"

# Matches a [section] header line. We anchor on the brackets so that the
# same name appearing as a value can't be confused with a section opener.
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")

# Matches a [[package]] table-of-arrays header. We treat it as a separate
# concept from [section] because the boundary semantics differ: inside a
# [[package]] we collect name/version, then any following [[...]] or [...]
# closes the current package.
_PACKAGE_SECTION_RE = re.compile(r"^\s*\[\[([^\]]+)\]\]\s*$")

# Matches a key = "value" pair (the most common form for name/version/deps).
# Captures the raw value, which is later stripped of any leading/trailing
# whitespace.
_SIMPLE_KV_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*\"([^\"\n]*)\"")


@dataclass
class UvPackage:
    """A single ``[[package]]`` table extracted from ``uv.lock``.

    ``name`` is the distribution name as it appears in the lock file
    (e.g. ``"click"``, ``"my-pkg"``); ``version`` is the resolved version
    string and may be empty when the package table omits a ``version``
    key (rare but tolerated).
    """

    name: str
    version: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version}


@dataclass
class UvProject:
    """A best-effort, tolerant view of a ``uv.lock`` file.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty / non-string / contained no ``[[package]]`` table
    with a non-empty ``name`` — the PoF orchestrator can use that flag to
    skip uv-specific fix strategies without surfacing a hard error.
    """

    valid: bool = False
    requires_python: str = ""
    packages: list[UvPackage] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "requires_python": self.requires_python,
            "packages": [p.to_dict() for p in self.packages],
        }

    def require_for(self, name: str) -> UvPackage | None:
        """Return the first UvPackage with the given distribution name.

        Searches the full ``packages`` list in declaration order (which
        mirrors the order in ``uv.lock``) so callers can rely on the
        "first match wins" semantics consistent with the other PoF
        language parsers.
        """

        for p in self.packages:
            if p.name == name:
                return p
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_uv_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``uv.lock``.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match Windows / macOS
    filesystems where ``UV.LOCK`` or ``Uv.Lock`` would otherwise be
    invisible.
    """
    if not files:
        return False
    target = _UV_LOCK_BASENAME.lower()
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


def parse_uv_lock(content: str) -> UvProject:
    """Parse a ``uv.lock`` string into a ``UvProject``.

    Tolerant: empty input, non-string input, and uv.lock files without
    a single ``[[package]]`` table with a ``name`` field all yield
    ``UvProject(valid=False)`` with empty fields rather than raising.
    ``#`` line comments are stripped before parsing so annotated values
    are handled correctly. Multi-line inline tables / arrays (e.g.
    ``source = { ... }``) are joined into a single logical line so the
    outer key/value scanner doesn't drift out of section.
    """
    if not isinstance(content, str) or not content.strip():
        return UvProject(valid=False)

    cleaned = _strip_comments(content)
    logical = _logical_lines(cleaned)
    requires_python = _parse_requires_python(logical)
    packages = _parse_packages(logical)

    # Without any [[package]] with a non-empty name the file is not a
    # usable uv.lock. Bare config-style fragments are accepted as
    # valid=False so the orchestrator can fall back to a different
    # strategy.
    if not any(p.name for p in packages):
        return UvProject(valid=False, requires_python=requires_python)

    return UvProject(
        valid=True,
        requires_python=requires_python,
        packages=packages,
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _strip_comments(content: str) -> str:
    """Remove ``#`` line comments from a uv.lock string.

    TOML only allows ``#`` line comments (no ``/* */`` block comments),
    so a single regex pass is sufficient. Comments may appear on their
    own line or after a value; both forms are stripped.
    """
    # Strip "  #comment" on its own line and "value  # trailing".
    # We don't try to preserve strings containing '#' — uv.lock values
    # are quoted and the simple ``#`` strip is good enough for a
    # best-effort lockfile reader.
    return re.sub(r"#[^\n]*", "", content)


def _logical_lines(content: str) -> list[str]:
    """Join continuation lines into single logical lines.

    uv.lock allows inline tables and arrays to span multiple lines, e.g.::

        dependencies = [
            { name = "colorama" },
        ]

        source = { registry = "https://pypi.org/simple" }

    For our simple parser we only need to handle one specific case: when
    an opening ``[`` or ``{`` on a line is not balanced by a closing
    ``]`` or ``}`` on the same line, we keep appending the next physical
    line until balance is restored. This is enough to keep section
    detection stable; the inner contents of multi-line literals are
    otherwise ignored because we only care about top-level ``name`` /
    ``version`` keys.
    """
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for raw in content.splitlines():
        if not buf:
            # Fast path: balanced on this line — no continuation.
            opens = raw.count("[") + raw.count("{")
            closes = raw.count("]") + raw.count("}")
            if opens == closes:
                out.append(raw)
                continue
            buf.append(raw)
            depth = opens - closes
            continue
        buf.append(raw)
        depth += raw.count("[") + raw.count("{")
        depth -= raw.count("]") + raw.count("}")
        if depth <= 0:
            out.append(" ".join(buf))
            buf = []
            depth = 0
    if buf:
        out.append(" ".join(buf))
    return out


def _parse_requires_python(logical_lines: list[str]) -> str:
    """Extract the top-level ``requires-python`` value.

    The key must appear BEFORE the first ``[...]`` / ``[[...]]`` header
    (top-level only). A ``requires-python`` declared inside a section
    would be ignored by uv and is ignored here too.
    """
    for line in logical_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Any section header closes the top-level window.
        if _SECTION_RE.match(stripped) or _PACKAGE_SECTION_RE.match(stripped):
            break
        m = _SIMPLE_KV_RE.match(stripped)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key == "requires-python":
            return value
    return ""


def _parse_packages(logical_lines: list[str]) -> list[UvPackage]:
    """Extract every ``[[package]]`` table as a ``UvPackage``.

    We track the current package header and accumulate its ``name`` and
    ``version`` keys until the next ``[[...]]`` or ``[...]`` header,
    which closes the current table. Multi-line inline tables / arrays
    (e.g. ``source = { ... }``, ``dependencies = [ ... ]``,
    ``wheels = [ ... ]``) are pre-joined by ``_logical_lines`` so the
    section boundary detector stays accurate.
    """
    packages: list[UvPackage] = []
    in_package = False
    current_name = ""
    current_version = ""

    for line in logical_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # A new [[package]] header closes the previous table.
        pkg_match = _PACKAGE_SECTION_RE.match(stripped)
        if pkg_match:
            if in_package:
                packages.append(
                    UvPackage(name=current_name, version=current_version)
                )
            in_package = True
            current_name = ""
            current_version = ""
            continue
        # Any other [...] header also closes the current package table.
        if _SECTION_RE.match(stripped):
            if in_package:
                packages.append(
                    UvPackage(name=current_name, version=current_version)
                )
            in_package = False
            current_name = ""
            current_version = ""
            continue
        if not in_package:
            continue
        m = _SIMPLE_KV_RE.match(stripped)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key == "name" and not current_name:
            current_name = value
        elif key == "version" and not current_version:
            current_version = value

    # Flush the last [[package]] if the file ended without a trailing
    # section header.
    if in_package:
        packages.append(UvPackage(name=current_name, version=current_version))

    return packages
