# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Gradle (Groovy DSL) PoF Project Parser (Phase 14 — PoF multilingualism: JVM).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a Gradle project and extract the minimal manifest slice it needs:

  * ``detect_gradle_project(files)`` — presence check of ``build.gradle`` in a
    file list (case-insensitive, basename only). ``build.gradle.kts`` (Kotlin
    DSL) is intentionally NOT matched: that dialect is handled by a separate
    module.
  * ``parse_gradle(content)`` — tolerant, line-based parser that extracts all
    direct dependencies from the ``dependencies { ... }`` block. Both the
    string-form (``'group:name:version'``) and the named-form
    (``group: 'g', name: 'n', version: 'v'``) are recognised.

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser is best-effort: malformed input yields a
  ``GradleProject(valid=False)`` with an empty dependency list rather than
  raising. The PoF orchestrator can then skip JVM/Groovy-specific fix
  strategies without catching exceptions.
* Stdlib only (``re``). Intentionally NOT using ``tomllib`` / ``tomli`` /
  ``pyyaml`` — and no third-party Gradle parser. CI still runs Python 3.10.
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.

build.gradle grammar (relevant subset)
--------------------------------------
Groovy DSL only (``.kts`` files are a different dialect and skipped on
purpose)::

    plugins {
        id 'java'
    }

    dependencies {
        implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
        testImplementation 'junit:junit:4.13.2'
        compileOnly 'org.projectlombok:lombok:1.18.30'
        api group: 'org.slf4j', name: 'slf4j-api', version: '2.0.9'
    }

We only consume the ``dependencies`` block — every other section (``plugins``,
``repositories``, ``tasks``, ``subprojects`` …) is ignored because it does
not change the resolved set of runtime classpath dependencies.

Comment handling
----------------
* Line comments ``// ...`` and block comments ``/* ... */`` are stripped
  before the dependency scan so annotated values are handled correctly.
* Inside a ``/* ... */`` block we replace the content with spaces (not
  remove it) so the rest of the line remains well-aligned for any later
  pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a build.gradle candidate when its basename is exactly
# "build.gradle" (case-insensitive). The Kotlin-DSL counterpart
# "build.gradle.kts" is intentionally excluded — it's a different dialect
# and will be handled by a separate parser module.
_GRADLE_BASENAME = "build.gradle"

# Match the opening of the ``dependencies { ... }`` block. The closing
# brace is detected by bracket balance in the main scan loop, so we do
# not need a separate "end" regex.
_DEPENDENCIES_HEADER_RE = re.compile(r"^\s*dependencies\s*\{\s*$")

# String-form dependency:
#   implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
#   implementation 'com.google.guava:guava'              # no version (dynamic)
#   implementation 'com.google.guava:guava:32.+'          # dynamic version
# Captures scope / group / artifact / version. The version group is
# tolerant (``[^']*``) because Gradle accepts dependencies without a
# hard-coded version — these are then resolved against a BOM, a property
# or a dynamic range and the parser's job is just to keep the entry.
_STRING_DEP_RE = re.compile(
    r"^(\w+)\s+['\"]([^:'\"]+):([^:'\"]+)(?::([^'\"]*))?['\"]"
)

# Named-form dependency:
#   api group: 'org.slf4j', name: 'slf4j-api', version: '2.0.9'
#   api group: 'org.apache.commons', name: 'commons-lang3'   # no version
# Captures scope / group / artifact / version. The version group is
# optional for the same reason as the string form above.
_NAMED_DEP_RE = re.compile(
    r"^(\w+)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"](?:,\s*version:\s*['\"]([^'\"]*)['\"])?"
)

# A line-comment that starts a whole physical line with ``//``.
# We do not strip inline ``//`` after a value: a value can in principle
# contain ``//`` (rare, but the named form already proved that strings are
# the unit of work), so we keep this conservative.
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# A block comment ``/* ... */`` that may span multiple physical lines.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


@dataclass
class GradleDependency:
    """A single Gradle dependency extracted from a ``dependencies { ... }`` block.

    ``scope`` is the Gradle configuration — one of ``implementation``,
    ``testImplementation``, ``compileOnly``, ``runtimeOnly``,
    ``annotationProcessor`` or ``api`` (also accepted as-is when the user
    defines a custom configuration). ``group`` and ``name`` are the Maven
    coordinates; ``version`` is the resolved version string and may be
    empty for dynamic versions (``+``), variables (``$ver``) or BOM
    imports.
    """

    scope: str
    group: str
    name: str
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "group": self.group,
            "name": self.name,
            "version": self.version,
        }


@dataclass
class GradleProject:
    """A best-effort, tolerant view of a Gradle ``build.gradle`` manifest.

    All fields are optional / may be empty. ``valid`` is False when the
    input was empty, was not a string, or did not contain a recognisable
    ``dependencies`` block with at least one dependency that has both a
    non-empty ``group`` and ``name`` — the PoF orchestrator can use that
    flag to skip JVM/Groovy-specific fix strategies without surfacing a
    hard error.
    """

    valid: bool = False
    dependencies: list[GradleDependency] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "dependencies": [d.to_dict() for d in self.dependencies],
        }

    def require_for(self, name: str) -> GradleDependency | None:
        """Return the first GradleDependency with the given Maven artifact name.

        ``name`` is matched against the artifact (``name``) field, not the
        group — so two different groups can declare artifacts with the
        same name and we always pick the first one (matches the lookup
        style used by the Rust / Node parsers in this family).
        """

        for d in self.dependencies:
            if d.name == name:
                return d
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_gradle_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``build.gradle`` (Groovy DSL).

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Comparison is case-insensitive to match Windows / macOS
    filesystems where ``Build.Gradle`` or ``BUILD.GRADLE`` would
    otherwise be invisible. ``build.gradle.kts`` (Kotlin DSL) is
    intentionally NOT matched — it is a different dialect.
    """

    if not files:
        return False
    target = _GRADLE_BASENAME.lower()
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


def parse_gradle(content: str) -> GradleProject:
    """Parse a ``build.gradle`` string into a ``GradleProject``.

    Tolerant: empty input, non-string input, and files without a
    ``dependencies { ... }`` block all yield ``GradleProject(valid=False)``
    with an empty dependency list rather than raising. ``//`` and
    ``/* */`` comments are stripped before the scan so annotated values
    are handled correctly.
    """

    if not isinstance(content, str) or not content.strip():
        return GradleProject(valid=False)

    cleaned = _strip_comments(content)
    deps = _parse_dependencies(cleaned)

    # valid=True requires at least one dependency with a non-empty
    # group AND a non-empty name. Empty / malformed entries do not count.
    real = [d for d in deps if d.group and d.name]
    if not real:
        return GradleProject(valid=False)

    return GradleProject(valid=True, dependencies=list(real))


# ── Internal helpers ─────────────────────────────────────────────────────


def _strip_comments(content: str) -> str:
    """Remove ``//`` and ``/* */`` comments from a build.gradle string.

    Block comments may span multiple physical lines; we replace the
    comment body with whitespace of the same length so line numbers
    remain stable for any later pass (not used here, but keeps things
    predictable). The regex is intentionally simple — Groovy strings can
    legally contain ``/*``, but the named-form dependency regex already
    anchors on a leading scope word, so a real dependency line will
    never be matched as the start of a comment.
    """

    def _blank_block(match: re.Match) -> str:
        # Preserve newlines so line numbers stay aligned, but blank out
        # every other character so the rest of the line is harmless.
        original = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in original)

    cleaned = _BLOCK_COMMENT_RE.sub(_blank_block, content)
    cleaned = _LINE_COMMENT_RE.sub("", cleaned)
    return cleaned


def _parse_dependencies(content: str) -> list[GradleDependency]:
    """Extract dependencies from the TOP-LEVEL ``dependencies { ... }`` block.

    Gradle files often nest a ``dependencies { ... }`` block inside
    ``buildscript { ... }`` (Spring Boot's plugin classpath) or inside
    ``subprojects { ... }``. Those nested blocks are build-time classpath,
    NOT runtime dependencies — the parser must skip them and keep scanning
    for the top-level block. We therefore track the overall ``{}`` nesting
    depth and only open the dependency scan when a ``dependencies {``
    header appears at depth 0.
    """

    deps: list[GradleDependency] = []
    overall_depth = 0
    in_deps_block = False
    deps_depth = 0

    for line in content.splitlines():
        stripped = line.strip()

        if in_deps_block:
            # Inside the top-level dependencies block: count its braces
            # so the matching closing brace ends the scan.
            deps_depth += line.count("{") - line.count("}")
            if deps_depth <= 0:
                in_deps_block = False
                continue
            if not stripped:
                continue
            m = _STRING_DEP_RE.match(stripped)
            if m:
                scope, group, name = m.group(1), m.group(2), m.group(3)
                version = m.group(4) or ""
                deps.append(GradleDependency(scope=scope, group=group, name=name, version=version))
                continue
            m = _NAMED_DEP_RE.match(stripped)
            if m:
                scope, group, name = m.group(1), m.group(2), m.group(3)
                version = m.group(4) or ""
                deps.append(GradleDependency(scope=scope, group=group, name=name, version=version))
                continue
            continue

        # Outside any dependency block: only a TOP-LEVEL ``dependencies {``
        # (overall_depth == 0) opens the runtime scan. A nested one
        # (buildscript / subprojects) is skipped.
        if _DEPENDENCIES_HEADER_RE.match(line) and overall_depth == 0:
            in_deps_block = True
            deps_depth = 1  # the opening brace sits on this line
            continue

        overall_depth += line.count("{") - line.count("}")

    return deps
