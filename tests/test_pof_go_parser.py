# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the Go PoF project parser (Phase 14).

Covers:
  * detect_go_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list.
  * parse_go_mod: valid manifest, empty input, module-only, go directive
    extraction, single-line require, block require, indirect annotation,
    // line comments, /* */ block comments (single-line and multi-line),
    malformed input, non-string input, real-world example.
  * GoProject.require_for() helper.
"""

import pytest

from gsc_cli.gsc_pof_go_parser import (
    GoModule,
    GoProject,
    detect_go_project,
    parse_go_mod,
)


# ── detect_go_project ─────────────────────────────────────────────────────


def test_detect_go_project_with_go_mod():
    assert detect_go_project(["src/main.go", "go.mod", "README.md"]) is True


def test_detect_go_project_no_go_mod():
    assert detect_go_project(["src/main.go", "README.md", "go.sum"]) is False


def test_detect_go_project_empty_list():
    assert detect_go_project([]) is False


def test_detect_go_project_case_insensitive():
    assert detect_go_project(["GO.MOD"]) is True
    assert detect_go_project(["Go.Mod"]) is True


def test_detect_go_project_handles_absolute_and_windows_paths():
    files = [
        "/home/user/proj/go.mod",
        "C:\\projects\\demo\\go.mod",
        "src\\nested\\go.mod",
    ]
    assert detect_go_project(files) is True


def test_detect_go_project_ignores_non_string_entries():
    detect_go_project([None, 42, b"go.mod", "go.mod"])  # type: ignore[list-item]


def test_detect_go_project_ignores_substring_matches():
    assert detect_go_project(["mygo.mod", "go.mod.bak"]) is False


# ── parse_go_mod — happy path ─────────────────────────────────────────────


def test_parse_go_mod_minimal():
    p = parse_go_mod("module example.com/demo")
    assert isinstance(p, GoProject)
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == ""
    assert p.require == []
    assert p.dependencies == []


def test_parse_go_mod_with_go_version():
    p = parse_go_mod("module example.com/demo\ngo 1.21\n")
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == "1.21"


def test_parse_go_mod_single_line_require():
    content = "module example.com/demo\n\ngo 1.20\n\nrequire github.com/foo/bar v1.2.3\n"
    p = parse_go_mod(content)
    assert p.valid is True
    assert len(p.require) == 1
    assert p.require[0] == GoModule(
        name="github.com/foo/bar", version="v1.2.3", indirect=False
    )


def test_parse_go_mod_block_require():
    content = """module example.com/demo

go 1.21

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.1.0
)
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert len(p.require) == 2
    assert p.require[0].name == "github.com/foo/bar"
    assert p.require[0].version == "v1.2.3"
    assert p.require[1].name == "github.com/baz/qux"
    assert p.require[1].version == "v0.1.0"


def test_parse_go_mod_indirect_annotation():
    content = """module example.com/demo

require (
	github.com/foo/bar v1.2.3 // indirect
)
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.require[0].indirect is True


def test_parse_go_mod_mixed_direct_indirect():
    content = """module example.com/demo

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.1.0 // indirect
)
"""
    p = parse_go_mod(content)
    assert p.require[0].indirect is False
    assert p.require[1].indirect is True


def test_parse_go_mod_to_dict_roundtrip():
    content = """module example.com/demo

go 1.21

require github.com/foo/bar v1.2.3
"""
    p = parse_go_mod(content)
    d = p.to_dict()
    assert d["valid"] is True
    assert d["module"] == "example.com/demo"
    assert d["go_version"] == "1.21"
    assert d["require"] == [
        {"name": "github.com/foo/bar", "version": "v1.2.3", "indirect": False}
    ]


def test_parse_go_mod_real_world_example():
    content = """module github.com/myorg/service

go 1.22.5

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/go-sql-driver/mysql v1.7.1
	golang.org/x/crypto v0.25.0 // indirect
	google.golang.org/grpc v1.65.0 // indirect
)
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.module == "github.com/myorg/service"
    assert p.go_version == "1.22.5"
    assert len(p.require) == 4
    assert p.require[0].name == "github.com/gin-gonic/gin"
    assert p.require[0].version == "v1.9.1"
    assert p.require[0].indirect is False
    assert p.require[3].name == "google.golang.org/grpc"
    assert p.require[3].indirect is True


# ── parse_go_mod — comments ───────────────────────────────────────────────


def test_parse_go_mod_strips_line_comments():
    content = """module example.com/demo // my module

go 1.21 // toolchain comment

require github.com/foo/bar v1.2.3 // some note
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == "1.21"
    assert p.require[0].name == "github.com/foo/bar"
    assert p.require[0].version == "v1.2.3"


def test_parse_go_mod_strips_block_comments_multiline():
    content = """/* This is a
multi-line block comment
spanning several lines */

module example.com/demo

go 1.21
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == "1.21"


def test_parse_go_mod_strips_inline_block_comment():
    content = "module example.com/demo /* inline comment */\n\ngo 1.21\n"
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == "1.21"


# ── parse_go_mod — error & edge cases ─────────────────────────────────────


def test_parse_go_mod_empty_string():
    p = parse_go_mod("")
    assert p.valid is False
    assert p.module == ""
    assert p.go_version == ""
    assert p.require == []


def test_parse_go_mod_whitespace_only():
    p = parse_go_mod("   \n\t  \n")
    assert p.valid is False


def test_parse_go_mod_none_input():
    p = parse_go_mod(None)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_go_mod_non_string_input():
    p = parse_go_mod(12345)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_go_mod_no_module_directive():
    p = parse_go_mod("go 1.21\n\nrequire github.com/foo/bar v1.2.3\n")
    assert p.valid is False


def test_parse_go_mod_only_module_directive():
    p = parse_go_mod("module example.com/demo\n")
    assert p.valid is True
    assert p.go_version == ""
    assert p.require == []


def test_parse_go_mod_replaces_and_excludes_ignored():
    content = """module example.com/demo

go 1.21

replace github.com/old/old v1.0.0 => github.com/new/new v1.1.0

require github.com/foo/bar v1.2.3

exclude github.com/baz/qux v0.1.0
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert len(p.require) == 1
    assert p.require[0].name == "github.com/foo/bar"


def test_parse_go_mod_toolchain_directive_ignored():
    content = """module example.com/demo

go 1.21

toolchain go1.22.5

require github.com/foo/bar v1.2.3
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.module == "example.com/demo"
    assert p.go_version == "1.21"
    assert len(p.require) == 1


def test_parse_go_mod_empty_require_block():
    content = """module example.com/demo

require (
)
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert p.require == []


def test_parse_go_mod_blank_lines_and_comments_between_requires():
    content = """module example.com/demo

go 1.21

require (
	github.com/foo/bar v1.2.3
	// a comment line
	github.com/baz/qux v0.1.0
)
"""
    p = parse_go_mod(content)
    assert p.valid is True
    assert len(p.require) == 2


# ── GoProject.require_for() helper ────────────────────────────────────────


def test_go_project_require_for_found():
    p = parse_go_mod("require github.com/foo/bar v1.2.3\n\nmodule example.com/demo\n")
    mod = p.require_for("github.com/foo/bar")
    assert mod is not None
    assert mod.version == "v1.2.3"


def test_go_project_require_for_not_found():
    p = parse_go_mod("module example.com/demo\n")
    mod = p.require_for("github.com/missing/thing")
    assert mod is None


def test_go_project_dependencies_aliases_require():
    content = "module example.com/demo\n\nrequire github.com/foo/bar v1.2.3\n"
    p = parse_go_mod(content)
    assert p.dependencies is p.require
