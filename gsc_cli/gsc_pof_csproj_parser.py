# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""C# / .NET (csproj) PoF Project Parser (Phase 14 — PoF multilingualism: .NET).

Pure, side-effect-free helpers used by the Proof-of-Fix pipeline to recognize
a .NET SDK-style project and extract the minimal manifest slice it needs:

  * ``detect_csharp_project(files)`` — presence check of any ``*.csproj`` in
    a file list (case-insensitive, basename only).
  * ``parse_csproj(content)``       — tolerant XML parser that returns a
    ``CsprojProject`` dataclass with ``target_framework`` and a list of
    ``CsprojPackage`` (from ``<PackageReference Include="..." Version="..."/>``).

Design notes
------------
* No filesystem access, no environment variables, no I/O. Functions take
  strings / lists and return dataclasses — fully unit-testable in isolation.
* The parser is best-effort: malformed input, broken XML, or a ``.csproj``
  without any ``<PackageReference>`` all yield ``CsprojProject(valid=False)``
  rather than raising. The PoF orchestrator can then skip .NET-specific
  fix strategies without catching exceptions.
* ``<PackageReference>`` in SDK-style csproj is a SELF-CLOSING element with
  ATTRIBUTES (NOT child elements, unlike Maven's ``<dependency>`` which uses
  child ``<groupId>`` / ``<artifactId>`` / ``<version>``). We read them via
  ``el.attrib.get("Include")`` and ``el.attrib.get("Version")``.
* ``Version`` may be absent (Central Package Management — ``Directory.Packages.props``
  provides versions centrally). In that case ``CsprojPackage.version`` is
  the empty string, mirroring the Node.js / Yarn tolerant behaviour.
* Namespace-agnostic: csproj files are usually namespace-free, but we
  tolerate ``xmlns="http://schemas.microsoft.com/developer/msbuild/2003"``
  by stripping any ``{namespace}`` prefix from element tags via the same
  ``_local(tag)`` helper used by ``gsc_pof_java_parser``.
* Stdlib only (``xml.etree.ElementTree``, ``dataclasses``, ``typing``).
* Backward-compatibility: this is a new module (Phase 14), no aliases needed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable

# A file is considered a csproj candidate when its basename ENDS with
# ".csproj" (case-insensitive). The PoF pipeline is run on already-walked
# file lists, so we don't try to guess paths here. The stem is intentionally
# free-form — MyApp.csproj, Foo.csproj, Backend.Api.csproj are all valid.
_CSPROJ_SUFFIX = ".csproj"


def _local(tag: str) -> str:
    """Strip a ``{namespace}`` prefix, leaving the bare element name.

    Mirrors the same helper in ``gsc_pof_java_parser`` so both XML-based
    parsers stay in lock-step.
    """
    return tag.split("}", 1)[-1]


@dataclass
class CsprojPackage:
    """A single ``<PackageReference>`` extracted from a ``.csproj``.

    ``name`` is the NuGet package id (the ``Include`` attribute);
    ``version`` is the ``Version`` attribute and may be empty when the
    project relies on Central Package Management.
    """

    name: str
    version: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version}


@dataclass
class CsprojProject:
    """A best-effort, parser-tolerant view of a .NET SDK-style ``.csproj``.

    ``valid`` is False when the input was empty, non-string, broken XML,
    had no ``<Project>`` root, or contained no ``<PackageReference>`` with
    a non-empty ``Include``. The PoF orchestrator can use that flag to skip
    .NET-specific fix strategies without surfacing a hard error.
    """

    valid: bool = False
    target_framework: str = ""
    packages: list[CsprojPackage] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "target_framework": self.target_framework,
            "packages": [p.to_dict() for p in self.packages],
        }

    def require_for(self, name: str) -> CsprojPackage | None:
        """Return the first CsprojPackage with the given name, or None.

        Match is exact and case-sensitive — NuGet package ids are
        case-insensitive in theory, but a csproj that writes
        ``Include="Newtonsoft.Json"`` should be matched by the same
        string the orchestrator carries in its findings, so we do not
        re-fold case here. Empty / unknown names return None.
        """
        for p in self.packages:
            if p.name == name:
                return p
        return None


# ── Public API ───────────────────────────────────────────────────────────


def detect_csharp_project(files: Iterable[str]) -> bool:
    """Return True if any of ``files`` is a ``*.csproj``.

    The check is on the SUFFIX of the basename, not on a fixed filename
    — SDK-style project files may be named ``MyApp.csproj``,
    ``Backend.Api.csproj``, ``Foo.csproj``, etc. Comparison is
    case-insensitive to match Windows / macOS filesystems where
    ``PROJECT.CSPROJ`` would otherwise be invisible.

    ``files`` may be absolute or relative paths; only the basename is
    inspected. Non-string entries are silently skipped.
    """
    if not files:
        return False
    target = _CSPROJ_SUFFIX.lower()
    for f in files:
        if not isinstance(f, str):
            continue
        # os.path.basename is avoided to keep the helper purely functional
        # and free of filesystem semantics; split on both / and \ so we
        # work on POSIX and Windows-style paths.
        base = f.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base.lower().endswith(target):
            return True
    return False


def parse_csproj(content: str) -> CsprojProject:
    """Parse a ``.csproj`` XML string into a ``CsprojProject``.

    Tolerant: empty input, non-string input, broken XML, XML without a
    ``<Project>`` root, and a ``.csproj`` with no ``<PackageReference>``
    elements all yield ``CsprojProject(valid=False)`` rather than raising.
    The PoF orchestrator can then decide to skip the .NET-specific
    strategy without catching exceptions.
    """
    if not isinstance(content, str) or not content.strip():
        return CsprojProject(valid=False)

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return CsprojProject(valid=False)

    if _local(root.tag) != "Project":
        return CsprojProject(valid=False)

    target_framework, packages = _walk(root)

    if not packages:
        return CsprojProject(valid=False)

    return CsprojProject(
        valid=True,
        target_framework=target_framework,
        packages=packages,
    )


# ── Internal helpers ─────────────────────────────────────────────────────


def _walk(root) -> tuple[str, list[CsprojPackage]]:
    """Extract ``<TargetFramework>`` text and ``<PackageReference>`` list.

    Walks every direct child of ``<Project>`` once, descending into
    ``<ItemGroup>`` to find ``<PackageReference>`` (the SDK-style format
    almost always nests PackageReferences inside ItemGroup, but a
    well-formed ``<PackageReference>`` placed directly under
    ``<Project>`` is also handled for robustness).

    ``<TargetFramework>`` may appear under ``<PropertyGroup>`` (the
    common SDK form) or directly under ``<Project>`` (legacy form).
    The first non-empty value wins — MSBuild's multi-targeting uses
    ``<TargetFrameworks>`` (plural, semicolon-joined) which we
    intentionally do not auto-split; the SCA fix path can decide
    how to react to that edge case.
    """
    target_framework = ""
    packages: list[CsprojPackage] = []

    for child in root:
        name = _local(child.tag)
        if name == "TargetFramework":
            value = (child.text or "").strip()
            if value and not target_framework:
                target_framework = value
        elif name == "PropertyGroup":
            tf = _find_target_framework(child)
            if tf and not target_framework:
                target_framework = tf
        elif name == "PackageReference":
            pkg = _package_from_el(child)
            if pkg is not None:
                packages.append(pkg)
        elif name == "ItemGroup":
            for sub in child:
                if _local(sub.tag) == "PackageReference":
                    pkg = _package_from_el(sub)
                    if pkg is not None:
                        packages.append(pkg)

    return target_framework, packages


def _find_target_framework(prop_group) -> str:
    """Return the first non-empty ``<TargetFramework>`` under a PropertyGroup."""
    for el in prop_group:
        if _local(el.tag) == "TargetFramework":
            value = (el.text or "").strip()
            if value:
                return value
    return ""


def _package_from_el(el) -> CsprojPackage | None:
    """Build a CsprojPackage from a ``<PackageReference ... />`` element.

    Returns None when the ``Include`` attribute is missing or empty —
    such elements are dropped so ``valid=False`` is returned downstream
    only for projects that have at least one usable package reference.
    ``Version`` is optional (Central Package Management); when missing
    the dataclass stores ``version=""``.
    """
    name = (el.attrib.get("Include") or "").strip()
    if not name:
        return None
    version = (el.attrib.get("Version") or "").strip()
    return CsprojPackage(name=name, version=version)
