# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Go PoF Project Parser (Phase 14 — PoF multilingualism: Go).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a Go project and extract the minimal manifest slice it needs:

  * ``detect_go_project(files)`` — presence check of ``go.mod`` in a file list
    (case-insensitive, basename only).
  * ``parse_go_mod(content)`` — line-based parser that extracts the ``module``
    path, the ``go`` directive version, and all ``require`` directives
    (direct + indirect). Tolerant of ``//`` line comments and ``/* */`` block
    comments, which Go's grammar permits inside go.mod.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser is best-effort: malformed input yields a ``GoProject(valid=False)``
  with empty fields rather than raising. The PoF orchestrator can then skip
  Go-specific fix strategies without catching exceptions.
* Only the stdlib ``re`` module is used — no third-party dependencies.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.

go.mod grammar (relevant subset)
--------------------------------
  module <module-path>
  go <version>            // e.g. 1.21  or  1.21.0
  require (               // block form
      <module> v<version> // indirect  (optional "// indirect" comment)
      ...
  )
  require <module> v<version>  // single-line form

Lines that are not ``module``/``go``/``require`` (e.g. ``replace``, ``exclude``,
``toolchain``, blank lines, comments) are ignored — they don't change the
set of resolved dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a go.mod candidate when its basename is exactly
# "go.mod" (case-insensitive). The PoF pipeline is run on already-walked
# file lists, so we don't try to guess paths here.
_GO_MOD_BASENAME = "go.mod"

# Matches "module <path>" — captures the import path.
_MODULE_RE = re.compile(r"^\s*module\s+(\S+)")

# Matches "go <version>" — captures the version token (e.g. "1.21", "1.21.3").
_GO_VERSION_RE = re.compile(r"^\s*go\s+(\S+)")

# Matches the start of a block-form require: "require (".
_REQUIRE_BLOCK_START_RE = re.compile(r"^\s*require\s*\(")

# Matches a single-line require: "require <module> v<version>".
_REQUIRE_SINGLE_RE = re.compile(r"^\s*require\s+(\S+)\s+(\S+)")

# Matches one requirement line inside a block: "<module> v<version> [// ...]"
# The "// indirect" annotation is captured but not stored separately —
# indirect deps are treated the same as direct ones by the PoF orchestrator.
_BLOCK_REQ_LINE_RE = re.compile(r"^\s*(\S+)\s+(\S+)")


@dataclass
class GoModule:
    """A single Go module dependency extracted from go.mod.

    ``name`` is the module path (import path); ``version`` is the version
    string without the leading ``v`` marker stripped (e.g. ``v1.2.3``),
    matching the raw go.mod text so callers can compare directly.
    """

    name: str
    version: str
    indirect: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "indirect": self.indirect,
        }


@dataclass
class GoProject:
    """A best-effort, tolerant view of a Go go.mod manifest.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty or contained no recognisable ``module`` directive —
    the PoF orchestrator can use that flag to skip Go-specific fix
    strategies without surfacing a hard error.
    """

    valid: bool = False
    module: str = ""
    go_version: str = ""
    require: list[GoModule] = field(default_factory=list)
    # Backwards-compatible alias — some downstream code expects ``dependencies``.
    dependencies: list[GoModule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "module": self.module,
            "go_version": self.go_version,
            "require": [m.to_dict() for m in self.require],
            "dependencies": [m.to_dict() for m in self.dependencies],
        }

    def require_for(self, name: str) -> GoModule | None:
        """Return the first GoModule with the given import path, or None."""
        for m in self.require:
            if m.name == name:
                return m
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_go_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``go.mod``.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match filesystems where
    ``GO.MOD`` would otherwise be invisible.
    """
    if not files:
        return False
    target = _GO_MOD_BASENAME.lower()
    for f in files:
        if not isinstance(f, str):
            continue
        # os.path.basename is avoided to keep the helper purely functional
        # and free of filesystem semantics; split on both / and \\ so we
        # work on POSIX and Windows-style paths.
        base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base.lower() == target:
            return True
    return False


def parse_go_mod(content: str) -> GoProject:
    """Parse a ``go.mod`` string into a ``GoProject``.

    Tolerant: empty input, non-string input, and go.mod files with no
    ``module`` directive all yield a ``GoProject(valid=False)`` with empty
    fields rather than raising. Line comments (``//``) and block comments
    (``/* */``) are stripped before parsing so annotated directives are
    handled correctly.
    """
    if not isinstance(content, str) or not content.strip():
        return GoProject(valid=False)

    cleaned = _strip_comments(content)
    module_path = _parse_module(cleaned)
    go_version = _parse_go_directive(cleaned)
    # Requirements must be parsed from the ORIGINAL content (not ``cleaned``):
    # ``_parse_block_line`` detects the ``// indirect`` annotation, and
    # ``_strip_comments`` would have already removed it.
    requires = _parse_requirements(content)

    # Without a module directive the file is not a usable go.mod.
    if not module_path:
        return GoProject(valid=False)

    requires_copy = list(requires)
    return GoProject(
        valid=True,
        module=module_path,
        go_version=go_version,
        require=requires_copy,
        dependencies=requires_copy,
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _strip_comments(content: str) -> str:
    """Remove ``//`` line comments and ``/* */`` block comments from go.mod.

    Go permits comments on their own lines and after directives. We strip
    both forms before line-by-line parsing so that, e.g., a ``// indirect``
    annotation doesn't interfere with module/version extraction.

    Block comments may span multiple lines; line comments run to end-of-line.
    Order matters: strip block comments first (they can span newlines), then
    line comments.
    """
    # Remove block comments /* ... */ (non-greedy, multi-line).
    result = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    # Remove line comments // ... $ (only when // starts a comment, not inside
    # a string — go.mod paths/versions don't contain // so this is safe).
    result = re.sub(r"//[^\n]*", "", result)
    return result


def _parse_module(content: str) -> str:
    """Extract the module path from the ``module`` directive."""
    for line in content.splitlines():
        m = _MODULE_RE.match(line)
        if m:
            return m.group(1)
    return ""


def _parse_go_directive(content: str) -> str:
    """Extract the version token from the ``go`` directive.

    Go 1.21+ uses two-token form: ``go 1.21``. Older toolchains accepted
    ``go 1.21.0``. We capture the token after ``go`` as-is.
    """
    for line in content.splitlines():
        m = _GO_VERSION_RE.match(line)
        if m:
            return m.group(1)
    return ""


def _parse_requirements(content: str) -> list[GoModule]:
    """Extract all module dependencies from require directives.

    Handles both block form (``require ( … )``) and single-line form
    (``require <module> <version>``). ``// indirect`` annotations are
    detected and recorded on the ``GoModule.indirect`` flag but do not
    affect membership in the result set.
    """
    requires: list[GoModule] = []
    lines = content.splitlines()
    in_block = False

    for line in lines:
        stripped = line.strip()

        if in_block:
            if _is_block_close(stripped):
                in_block = False
                continue
            mod = _parse_block_line(stripped)
            if mod is not None:
                requires.append(mod)
            continue

        if _REQUIRE_BLOCK_START_RE.match(line):
            in_block = True
            continue

        # Single-line "require <module> v<version>"
        m = _REQUIRE_SINGLE_RE.match(line)
        if m:
            name = m.group(1)
            version = m.group(2)
            requires.append(GoModule(name=name, version=version, indirect=False))

    return requires


def _is_block_close(stripped: str) -> bool:
    """True when a stripped line closes a require block."""
    return stripped == ")"


def _parse_block_line(stripped: str) -> GoModule | None:
    """Parse one line inside a ``require ( … )`` block.

    Lines look like: ``github.com/foo/bar v1.2.3`` or
    ``github.com/foo/bar v1.2.3 // indirect``.
    """
    if not stripped:
        return None
    # Split off any trailing comment annotation.
    code_part = re.split(r"\s*//", stripped, maxsplit=1)[0].strip()
    if not code_part:
        return None
    m = _BLOCK_REQ_LINE_RE.match(code_part)
    if not m:
        return None
    name = m.group(1)
    version = m.group(2)
    # The "// indirect" was already split away above; detect it from the
    # original stripped line.
    indirect = "// indirect" in stripped
    return GoModule(name=name, version=version, indirect=indirect)
