# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Java/Maven PoF parser (Phase 14, PoF multi-language support).

Pure, I/O-free helpers that detect a Maven project from a file list and
parse a ``pom.xml`` string into a structured ``MavenProject``. Mirrors the
shape and style of the Node.js (``gsc_pof_node_parser``) and Go
(``gsc_pof_go_parser``) parsers so the PoF orchestrator can treat all
ecosystems uniformly.

Uses ``xml.etree.ElementTree`` (stdlib, available on Python 3.8+). The
parser is tolerant of broken XML (returns ``valid=False``) and of Maven's
default namespace (``http://maven.apache.org/POM/4.0.0``) — tags are matched
by local name after stripping any ``{namespace}`` prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
import xml.etree.ElementTree as ET


_POM_BASENAME = "pom.xml"
_DEFAULT_SCOPE = "compile"


def _local(tag: str) -> str:
    """Strip a ``{namespace}`` prefix, leaving the bare element name."""
    return tag.split("}", 1)[-1]


@dataclass
class MavenDependency:
    """A single Maven dependency (groupId/artifactId/version/scope)."""

    group_id: str
    artifact_id: str
    version: str
    scope: str = _DEFAULT_SCOPE

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "artifact_id": self.artifact_id,
            "version": self.version,
            "scope": self.scope,
        }


@dataclass
class MavenProject:
    """A best-effort, tolerant view of a Maven ``pom.xml``.

    ``valid`` is False when the input was empty, non-string, unparseable
    XML, or contained no recognisable ``<project>`` root — the PoF
    orchestrator can use that flag to skip Java-specific fix strategies
    without surfacing a hard error.
    """

    valid: bool = False
    group_id: str = ""
    artifact_id: str = ""
    version: str = ""
    dependencies: list[MavenDependency] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "group_id": self.group_id,
            "artifact_id": self.artifact_id,
            "version": self.version,
            "dependencies": [d.to_dict() for d in self.dependencies],
        }


def detect_java_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``pom.xml``.

    Paths may be absolute or relative; only the basename is inspected.
    Comparison is case-insensitive.
    """
    if not files:
        return False
    target = _POM_BASENAME.lower()
    for f in files:
        if not isinstance(f, str):
            continue
        base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base.lower() == target:
            return True
    return False


def parse_pom_xml(content: str) -> MavenProject:
    """Parse a ``pom.xml`` string into a ``MavenProject``.

    Tolerant: empty input, non-string input, broken XML, and XML without a
    ``<project>`` root all yield ``MavenProject(valid=False)`` rather than
    raising.
    """
    if not isinstance(content, str) or not content.strip():
        return MavenProject(valid=False)

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return MavenProject(valid=False)

    if _local(root.tag) != "project":
        return MavenProject(valid=False)

    group_id = artifact_id = version = ""
    dependencies: list[MavenDependency] = []

    for child in root:
        name = _local(child.tag)
        if name == "groupId":
            group_id = (child.text or "").strip()
        elif name == "artifactId":
            artifact_id = (child.text or "").strip()
        elif name == "version":
            version = (child.text or "").strip()
        elif name == "dependencies":
            dependencies = _parse_dependencies(child)

    return MavenProject(
        valid=True,
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        dependencies=dependencies,
    )


def _parse_dependencies(deps_elem) -> list[MavenDependency]:
    """Extract ``<dependency>`` children from a ``<dependencies>`` element."""
    out: list[MavenDependency] = []
    for dep in deps_elem:
        if _local(dep.tag) != "dependency":
            continue
        gid = aid = ver = ""
        scope = _DEFAULT_SCOPE
        for el in dep:
            name = _local(el.tag)
            if name == "groupId":
                gid = (el.text or "").strip()
            elif name == "artifactId":
                aid = (el.text or "").strip()
            elif name == "version":
                ver = (el.text or "").strip()
            elif name == "scope":
                scope = (el.text or "").strip() or _DEFAULT_SCOPE
        out.append(MavenDependency(gid, aid, ver, scope))
    return out
