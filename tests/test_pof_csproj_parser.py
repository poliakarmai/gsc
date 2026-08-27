# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the C# / .NET (csproj) PoF project parser (Phase 14).

Covers:
  * detect_csharp_project: suffix match (any stem), case-insensitive,
    POSIX + Windows paths, ignores non-string entries, returns False on
    empty list, rejects ".csproj.bak" (no suffix overlap) and "package.json".
  * parse_csproj: real-world SDK-style sample, multiple PackageReference,
    PackageReference without Version (Central Package Management), empty
    string, non-string input, broken XML, XML without <Project> root,
    XML with a non-Project root, multiple PropertyGroups, ItemGroup
    without PackageReference, namespace-prefixed tags.
  * CsprojProject.to_dict() and CsprojPackage.to_dict() shape.
  * CsprojProject.require_for(name) exact match + None on miss.
"""

import pytest

from gsc_cli.gsc_pof_csproj_parser import (
    CsprojPackage,
    CsprojProject,
    detect_csharp_project,
    parse_csproj,
)


# ── detect_csharp_project ────────────────────────────────────────────────


def test_detect_csharp_project_empty_list():
    assert detect_csharp_project([]) is False


def test_detect_csharp_project_simple_filename():
    assert detect_csharp_project(["MyApp.csproj"]) is True


def test_detect_csharp_project_nested_posix_path():
    assert detect_csharp_project(["src/Foo.csproj"]) is True


def test_detect_csharp_project_nested_windows_path():
    assert detect_csharp_project(["src\\Foo.csproj"]) is True


def test_detect_csharp_project_absolute_path():
    assert detect_csharp_project(["/home/user/proj/Backend.Api.csproj"]) is True


def test_detect_csharp_project_case_insensitive():
    # Windows / macOS filesystems can surface any casing.
    assert detect_csharp_project(["PROJECT.CSPROJ"]) is True
    assert detect_csharp_project(["Foo.CsProj"]) is True


def test_detect_csharp_project_ignores_non_string_entries():
    # Defensive: a buggy caller might pass mixed types; should not crash.
    assert (
        detect_csharp_project(
            [None, 42, b"MyApp.csproj", "MyApp.csproj"]  # type: ignore[list-item]
        )
        is True
    )


def test_detect_csharp_project_rejects_other_files():
    assert detect_csharp_project(["package.json", "pom.xml", "Cargo.toml"]) is False


def test_detect_csharp_project_rejects_csproj_bak():
    # ".csproj.bak" must NOT match — the check is a strict suffix.
    assert detect_csharp_project(["MyApp.csproj.bak"]) is False


def test_detect_csharp_project_rejects_myapp_csproj_path():
    # Suffix is on the basename, not on a containing directory that
    # happens to be named "*.csproj". A directory "old.csproj/foo.cs"
    # is not a csproj file.
    assert detect_csharp_project(["old.csproj/foo.cs"]) is False


# ── parse_csproj — happy path ────────────────────────────────────────────


def test_parse_csproj_minimal_sdk_style():
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert isinstance(p, CsprojProject)
    assert p.valid is True
    assert p.target_framework == "net8.0"
    assert len(p.packages) == 2
    assert p.packages[0].name == "Newtonsoft.Json"
    assert p.packages[0].version == "13.0.3"
    assert p.packages[1].name == "Serilog"
    assert p.packages[1].version == "3.1.1"


def test_parse_csproj_single_package_reference():
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is True
    assert p.target_framework == ""
    assert len(p.packages) == 1
    assert p.packages[0].name == "Newtonsoft.Json"
    assert p.packages[0].version == "13.0.3"


def test_parse_csproj_package_reference_without_version():
    # Central Package Management: <PackageReference Include="X" /> with no
    # Version attribute — the version lives in Directory.Packages.props.
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is True
    assert len(p.packages) == 1
    assert p.packages[0].name == "Newtonsoft.Json"
    assert p.packages[0].version == ""


def test_parse_csproj_multiple_property_groups_picks_first_target_framework():
    # Real-world multi-targeting sometimes splits PropertyGroups — we
    # take the first non-empty <TargetFramework> we see.
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <TargetFramework>net6.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is True
    assert p.target_framework == "net6.0"
    assert len(p.packages) == 1


def test_parse_csproj_itemgroup_without_packagereference_is_ok():
    # A project that uses <Reference Include="..." /> instead of
    # PackageReference should still be rejected as having no useful
    # packages for the SCA fix path.
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <Reference Include="System.Data" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is False
    assert p.target_framework == ""


def test_parse_csproj_drop_packagereference_with_empty_include():
    # <PackageReference /> with no Include attribute is not actionable.
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        "    <PackageReference />\n"
        '    <PackageReference Include="" />\n'
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is True
    # Only the one with a non-empty Include is kept.
    assert len(p.packages) == 1
    assert p.packages[0].name == "Newtonsoft.Json"


def test_parse_csproj_namespace_aware_xml():
    # Real msbuild namespace — tags arrive as {ns}Project / {ns}ItemGroup
    # / {ns}PackageReference. The parser must still extract everything.
    content = (
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003" '
        'Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is True
    assert p.target_framework == "net8.0"
    names = [pkg.name for pkg in p.packages]
    assert names == ["Newtonsoft.Json", "Serilog"]
    versions = [pkg.version for pkg in p.packages]
    assert versions == ["13.0.3", "3.1.1"]


# ── parse_csproj — failure paths ─────────────────────────────────────────


def test_parse_csproj_empty_string_is_invalid():
    p = parse_csproj("")
    assert p.valid is False
    assert p.target_framework == ""
    assert p.packages == []


def test_parse_csproj_whitespace_only_is_invalid():
    p = parse_csproj("   \n\t  \n")
    assert p.valid is False


def test_parse_csproj_non_string_input_is_invalid():
    p = parse_csproj(None)  # type: ignore[arg-type]
    assert p.valid is False
    p = parse_csproj(12345)  # type: ignore[arg-type]
    assert p.valid is False
    p = parse_csproj(b"<Project><ItemGroup><PackageReference Include='X' Version='1' /></ItemGroup></Project>")  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_csproj_broken_xml_is_invalid():
    p = parse_csproj("<Project><ItemGroup><PackageReference Include='X'")  # truncated
    assert p.valid is False


def test_parse_csproj_wrong_root_is_invalid():
    # Root is <Solution>, not <Project>.
    content = (
        "<Solution>\n"
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Solution>\n"
    )
    p = parse_csproj(content)
    assert p.valid is False


def test_parse_csproj_xml_without_packagereference_is_invalid():
    # Well-formed <Project> but no PackageReference at all — the
    # orchestrator has nothing to drive a NuGet fix on.
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "  </PropertyGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.valid is False
    # target_framework is intentionally NOT populated when valid=False,
    # so a downstream caller cannot accidentally act on a half-parsed
    # view of a "no packages" project.
    assert p.target_framework == ""


# ── to_dict ──────────────────────────────────────────────────────────────


def test_csprojproject_to_dict_shape():
    p = CsprojProject(
        valid=True,
        target_framework="net8.0",
        packages=[
            CsprojPackage(name="Newtonsoft.Json", version="13.0.3"),
            CsprojPackage(name="Serilog", version=""),
        ],
    )
    d = p.to_dict()
    assert d == {
        "valid": True,
        "target_framework": "net8.0",
        "packages": [
            {"name": "Newtonsoft.Json", "version": "13.0.3"},
            {"name": "Serilog", "version": ""},
        ],
    }


def test_csprojpackage_to_dict_shape():
    pkg = CsprojPackage(name="Serilog", version="3.1.1")
    assert pkg.to_dict() == {"name": "Serilog", "version": "3.1.1"}


def test_csprojproject_to_dict_invalid_default_shape():
    # Default-constructed CsprojProject is valid=False with empty fields.
    p = CsprojProject()
    assert p.to_dict() == {
        "valid": False,
        "target_framework": "",
        "packages": [],
    }


# ── require_for ──────────────────────────────────────────────────────────


def test_require_for_finds_named_package():
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    dep = p.require_for("Serilog")
    assert dep is not None
    assert dep.name == "Serilog"
    assert dep.version == "3.1.1"


def test_require_for_returns_none_when_absent():
    content = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    p = parse_csproj(content)
    assert p.require_for("not-here") is None
    assert p.require_for("") is None
    # Substring must not match — exact-only.
    assert p.require_for("Newtonsoft") is None


def test_require_for_on_invalid_project_returns_none():
    p = parse_csproj("<not-project/>")
    assert p.require_for("anything") is None
