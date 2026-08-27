# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Rust PoF Project Parser (Phase 14 — PoF multilingualism: Rust).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a Rust project and extract the minimal manifest slice it needs:

  * ``detect_rust_project(files)`` — presence check of ``Cargo.toml`` in a
    file list (case-insensitive, basename only).
  * ``parse_cargo_toml(content)`` — line-based parser that extracts the
    ``package`` name and version, and all direct dependencies from
    ``[dependencies]`` and ``[dev-dependencies]`` sections. The
    ``[build-dependencies]`` section is recognised but ignored by design:
    build-time deps don't influence runtime SCA decisions.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser is best-effort: malformed input yields a
  ``RustProject(valid=False)`` with empty fields rather than raising. The
  PoF orchestrator can then skip Rust-specific fix strategies without
  catching exceptions.
* Stdlib only (``re``). Intentionally NOT using ``tomllib`` (Python 3.11+)
  or ``tomli`` — CI still runs Python 3.10.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.

Cargo.toml grammar (relevant subset)
------------------------------------
  [package]
  name = "demo"
  version = "0.1.0"
  edition = "2021"

  [dependencies]
  serde = "1.0"
  tokio = { version = "1.0", features = ["full"] }

  [dev-dependencies]
  proptest = "1.0"

  [build-dependencies]
  cc = "1.0"            # parsed but not exposed (runtime SCA scope)

Other sections (``[[bin]]``, ``[features]``, ``[profile.*]``, ``[workspace]``)
are ignored — they don't change the set of resolved runtime dependencies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a Cargo.toml candidate when its basename is exactly
# "Cargo.toml" (case-insensitive). The PoF pipeline is run on already-walked
# file lists, so we don't try to guess paths here.
_CARGO_TOML_BASENAME = "Cargo.toml"

# Matches a [section] header line. We anchor on the brackets so that the
# same name appearing as a value can't be confused with a section opener.
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")

# Matches a key = "value" pair (the most common form for name/version/deps).
# Captures the raw value, including any inline ``# ...`` comment which we
# strip afterwards.
_SIMPLE_KV_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*\"([^\"\n]*)\"")

# Matches a table-form dependency:
#   tokio = { version = "1.0", features = ["full"] }
# Captures the entire brace block so we can scan it for an inner ``version``.
_TABLE_DEP_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*\{(.*)\}\s*$")

# Matches ``version = "1.0"`` anywhere inside a table-form body (no ``^`` anchor
# so it works as a sub-search, unlike ``_SIMPLE_KV_RE`` which is start-anchored).
_TABLE_VERSION_RE = re.compile(r'version\s*=\s*"([^"\n]*)"')


@dataclass
class RustDependency:
    """A single Rust crate dependency extracted from Cargo.toml.

    ``name`` is the crate name as it appears under ``[dependencies]`` /
    ``[dev-dependencies]``; ``version`` is the resolved version string
    (empty when the user supplied a path/git dependency without a
    ``version`` key inside the table).
    """

    name: str
    version: str = ""
    dev: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "dev": self.dev,
        }


@dataclass
class RustProject:
    """A best-effort, tolerant view of a Rust ``Cargo.toml`` manifest.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty or contained no recognisable ``[package]`` section
    with a ``name`` field — the PoF orchestrator can use that flag to
    skip Rust-specific fix strategies without surfacing a hard error.
    """

    valid: bool = False
    name: str = ""
    version: str = ""
    dependencies: list[RustDependency] = field(default_factory=list)
    dev_dependencies: list[RustDependency] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "name": self.name,
            "version": self.version,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "dev_dependencies": [d.to_dict() for d in self.dev_dependencies],
        }

    def require_for(self, name: str) -> RustDependency | None:
        """Return the first RustDependency with the given crate name.

        Searches both ``dependencies`` and ``dev_dependencies`` so callers
        don't have to know which side the crate was declared on.
        """

        for d in self.dependencies:
            if d.name == name:
                return d
        for d in self.dev_dependencies:
            if d.name == name:
                return d
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_rust_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``Cargo.toml``.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match Windows / macOS
    filesystems where ``cargo.TOML`` or ``CARGO.TOML`` would otherwise be
    invisible.
    """
    if not files:
        return False
    target = _CARGO_TOML_BASENAME.lower()
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


def parse_cargo_toml(content: str) -> RustProject:
    """Parse a ``Cargo.toml`` string into a ``RustProject``.

    Tolerant: empty input, non-string input, and Cargo.toml files without
    a ``[package]`` section all yield ``RustProject(valid=False)`` with
    empty fields rather than raising. ``#`` line comments are stripped
    before parsing so annotated values are handled correctly.
    """
    if not isinstance(content, str) or not content.strip():
        return RustProject(valid=False)

    cleaned = _strip_comments(content)
    name, version = _parse_package(cleaned)
    deps, dev_deps = _parse_dependency_sections(content)

    # Without a [package] name the file is not a usable Cargo.toml.
    if not name:
        return RustProject(valid=False)

    return RustProject(
        valid=True,
        name=name,
        version=version,
        dependencies=list(deps),
        dev_dependencies=list(dev_deps),
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _strip_comments(content: str) -> str:
    """Remove ``#`` line comments from a Cargo.toml string.

    Cargo only allows ``#`` line comments (no ``/* */`` block comments),
    so a single regex pass is sufficient. Comments may appear on their
    own line or after a value; both forms are stripped.
    """
    # Strip "  # comment" on its own line and "value  # trailing".
    # We don't try to preserve strings containing '#' — Cargo.toml
    # values are quoted and the simple ``#`` strip is good enough for
    # a best-effort manifest reader.
    return re.sub(r"#[^\n]*", "", content)


def _section_name(line: str) -> str:
    """Return the lower-cased section name from a ``[section]`` header, or ``""``."""
    m = _SECTION_RE.match(line)
    if not m:
        return ""
    return m.group(1).strip().lower()


def _parse_package(content: str) -> tuple[str, str]:
    """Extract ``package.name`` and ``package.version`` from ``[package]``.

    Returns ``("", "")`` when no ``[package]`` section is found or when
    the section is missing a ``name`` field.
    """
    in_section = False
    name = ""
    version = ""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        section = _section_name(stripped)
        if section:
            # Leaving [package] ends our interest. Other sections that
            # contain a "name" key (e.g. [[bin]]) are ignored on purpose.
            if in_section:
                break
            in_section = section == "package"
            continue
        if not in_section:
            continue
        m = _SIMPLE_KV_RE.match(stripped)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if key == "name" and not name:
            name = value
        elif key == "version" and not version:
            version = value
    return name, version


def _parse_dependency_sections(content: str) -> tuple[list[RustDependency], list[RustDependency]]:
    """Extract dependencies from ``[dependencies]`` and ``[dev-dependencies]``.

    ``[build-dependencies]`` is recognised (so we can ``continue`` past
    it cleanly) but its entries are dropped — build-time crates don't
    affect runtime SCA decisions. Multi-line table values like::

        tokio = { version = "1.0", features = [
            "full",
            "rt-multi-thread",
        ] }

    are handled by joining continuation lines into a single logical line
    before applying the table regex.
    """
    deps: list[RustDependency] = []
    dev_deps: list[RustDependency] = []

    logical_lines = _logical_lines(content)
    current: str | None = None  # one of: "dependencies", "dev-dependencies", "build-dependencies", None
    for line in logical_lines:
        stripped = line.strip()
        if not stripped:
            continue
        section = _section_name(stripped)
        if section:
            if section == "dependencies":
                current = "dependencies"
            elif section == "dev-dependencies":
                current = "dev-dependencies"
            elif section == "build-dependencies":
                current = "build-dependencies"
            else:
                current = None
            continue
        if current is None or current == "build-dependencies":
            continue
        dep = _parse_dependency_line(stripped)
        if dep is None:
            continue
        if current == "dev-dependencies":
            dep = RustDependency(name=dep.name, version=dep.version, dev=True)
            dev_deps.append(dep)
        else:
            deps.append(dep)
    return deps, dev_deps


def _logical_lines(content: str) -> list[str]:
    """Join continuation lines into single logical lines.

    Cargo allows values to span multiple lines inside a table literal,
    e.g.::

        tokio = { version = "1.0", features = [
            "full",
        ] }

    For our simple parser we only need to handle one specific case: when
    an opening ``{`` on a line is not balanced by a closing ``}`` on the
    same line, we keep appending the next physical line until balance is
    restored. This is enough to extract a ``version = "..."`` from the
    first line of a multi-line table; the rest of the table is ignored
    since we only need the crate name + version.
    """
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for raw in content.splitlines():
        if not buf:
            # Fast path: balanced on this line — no continuation.
            opens = raw.count("{")
            closes = raw.count("}")
            if opens == closes:
                out.append(raw)
                continue
            buf.append(raw)
            depth = opens - closes
            continue
        buf.append(raw)
        depth += raw.count("{") - raw.count("}")
        if depth <= 0:
            out.append(" ".join(buf))
            buf = []
            depth = 0
    if buf:
        out.append(" ".join(buf))
    return out


def _parse_dependency_line(stripped: str) -> RustDependency | None:
    """Parse a single ``crate = "version"`` or ``crate = { ... }`` line.

    Returns ``None`` when the line is empty, a comment, or otherwise
    not a dependency declaration. For table-form dependencies without a
    ``version`` key (e.g. ``crate = { path = "..." }``), the returned
    ``version`` is the empty string.
    """
    if not stripped or stripped.startswith("#"):
        return None

    # Table form: tokio = { version = "1.0", features = [...] }
    m = _TABLE_DEP_RE.match(stripped)
    if m:
        name = m.group(1)
        body = m.group(2)
        # Look for the first ``version = "..."`` inside the body. We use a
        # dedicated non-anchored regex (``_TABLE_VERSION_RE``) because the
        # body may contain other ``key = "..."`` pairs after ``version``.
        vmatch = _TABLE_VERSION_RE.search(body)
        version = vmatch.group(1).strip() if vmatch else ""
        return RustDependency(name=name, version=version)

    # Simple form: serde = "1.0"
    m = _SIMPLE_KV_RE.match(stripped)
    if m:
        return RustDependency(name=m.group(1), version=m.group(2).strip())

    return None
