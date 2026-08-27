# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the Rust PoF project parser (Phase 14).

Covers:
  * detect_rust_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list.
  * parse_cargo_toml: valid manifest, empty input, package-only, simple
    ``crate = "1.0"`` deps, table-form ``crate = { version = "1.0", ... }``
    deps, dev-dependencies, build-dependencies (ignored), trailing ``#``
    comments, multi-line table values, malformed input, non-string input,
    real-world example.
  * RustProject.require_for() helper.
"""

import pytest

from gsc_cli.gsc_pof_rust_parser import (
    RustDependency,
    RustProject,
    detect_rust_project,
    parse_cargo_toml,
)


# ── detect_rust_project ───────────────────────────────────────────────────


def test_detect_rust_project_with_cargo_toml():
    assert detect_rust_project(["src/main.rs", "Cargo.toml", "README.md"]) is True


def test_detect_rust_project_no_cargo_toml():
    assert detect_rust_project(["src/main.rs", "README.md", "Cargo.lock"]) is False


def test_detect_rust_project_empty_list():
    assert detect_rust_project([]) is False


def test_detect_rust_project_case_insensitive():
    assert detect_rust_project(["CARGO.TOML"]) is True
    assert detect_rust_project(["Cargo.toml"]) is True
    assert detect_rust_project(["cargo.toml"]) is True
    assert detect_rust_project(["cArGo.ToMl"]) is True


def test_detect_rust_project_handles_absolute_and_windows_paths():
    files = [
        "/home/user/proj/Cargo.toml",
        "C:\\projects\\demo\\Cargo.toml",
        "src\\nested\\Cargo.toml",
    ]
    assert detect_rust_project(files) is True


def test_detect_rust_project_ignores_non_string_entries():
    # Should not raise even when the list contains garbage.
    detect_rust_project([None, 42, b"Cargo.toml", "Cargo.toml"])  # type: ignore[list-item]


def test_detect_rust_project_ignores_substring_matches():
    assert detect_rust_project(["my-cargo.toml", "Cargo.toml.bak", "Cargo.tomlx"]) is False


# ── parse_cargo_toml — happy path ─────────────────────────────────────────


def test_parse_cargo_toml_minimal():
    p = parse_cargo_toml('[package]\nname = "demo"\nversion = "0.1.0"\n')
    assert isinstance(p, RustProject)
    assert p.valid is True
    assert p.name == "demo"
    assert p.version == "0.1.0"
    assert p.dependencies == []
    assert p.dev_dependencies == []


def test_parse_cargo_toml_package_only_no_version():
    p = parse_cargo_toml('[package]\nname = "demo"\n')
    assert p.valid is True
    assert p.name == "demo"
    assert p.version == ""
    assert p.dependencies == []


def test_parse_cargo_toml_with_simple_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0] == RustDependency(name="serde", version="1.0", dev=False)
    assert p.dependencies[1] == RustDependency(name="tokio", version="1.0", dev=False)


def test_parse_cargo_toml_with_table_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
reqwest = { version = "0.12", default-features = false }
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0] == RustDependency(name="tokio", version="1.0", dev=False)
    assert p.dependencies[1] == RustDependency(name="reqwest", version="0.12", dev=False)


def test_parse_cargo_toml_mixed_simple_and_table_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 3
    assert p.dependencies[0].name == "serde"
    assert p.dependencies[0].version == "1.0"
    assert p.dependencies[1].name == "tokio"
    assert p.dependencies[1].version == "1.0"
    assert p.dependencies[2].name == "anyhow"
    assert p.dependencies[2].version == "1.0"


def test_parse_cargo_toml_with_dev_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"

[dev-dependencies]
proptest = "1.0"
criterion = { version = "0.5", features = ["html_reports"] }
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0] == RustDependency(name="serde", version="1.0", dev=False)
    assert len(p.dev_dependencies) == 2
    assert p.dev_dependencies[0] == RustDependency(name="proptest", version="1.0", dev=True)
    assert p.dev_dependencies[1] == RustDependency(
        name="criterion", version="0.5", dev=True
    )


def test_parse_cargo_toml_ignores_build_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[build-dependencies]
cc = "1.0"

[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0].name == "serde"
    # build-dependencies must NOT show up anywhere.
    assert all(d.name != "cc" for d in p.dependencies)
    assert all(d.name != "cc" for d in p.dev_dependencies)


def test_parse_cargo_toml_ignores_other_sections():
    content = """[package]
name = "demo"
version = "0.1.0"

[[bin]]
name = "demo-bin"
path = "src/bin.rs"

[features]
default = []

[profile.release]
opt-level = 3

[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert p.name == "demo"
    assert len(p.dependencies) == 1
    assert p.dependencies[0].name == "serde"


def test_parse_cargo_toml_table_dep_without_version_key():
    """A path-only or git-only dependency has no ``version`` key.

    The parser must still record the crate name; ``version`` stays empty
    so the SCA layer knows to look up the manifest for a resolved version.
    """
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
my-local = { path = "vendor/my-local" }
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0] == RustDependency(name="my-local", version="", dev=False)
    assert p.dependencies[1] == RustDependency(name="serde", version="1.0", dev=False)


def test_parse_cargo_toml_to_dict_roundtrip():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    d = p.to_dict()
    assert d == {
        "valid": True,
        "name": "demo",
        "version": "0.1.0",
        "dependencies": [{"name": "serde", "version": "1.0", "dev": False}],
        "dev_dependencies": [],
    }


def test_parse_cargo_toml_real_world_example():
    content = """[package]
name = "my-crate"
version = "0.2.1"
edition = "2021"
authors = ["Alex <alex@example.com>"]
description = "A demo crate"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
thiserror = "1.0"

[dev-dependencies]
proptest = "1.0"
criterion = { version = "0.5", features = ["html_reports"] }

[build-dependencies]
cc = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert p.name == "my-crate"
    assert p.version == "0.2.1"
    assert len(p.dependencies) == 5
    assert p.dependencies[0].name == "serde"
    assert p.dependencies[0].version == "1.0"
    assert p.dependencies[2].name == "tokio"
    assert p.dependencies[2].version == "1.0"
    assert len(p.dev_dependencies) == 2
    # build-deps (cc) must not leak into either list.
    all_dep_names = [d.name for d in p.dependencies] + [
        d.name for d in p.dev_dependencies
    ]
    assert "cc" not in all_dep_names


# ── parse_cargo_toml — comments ───────────────────────────────────────────


def test_parse_cargo_toml_strips_line_comments():
    content = """[package]            # project metadata
name = "demo"        # the name
version = "0.1.0"    # semver

[dependencies]
# a regular comment line
serde = "1.0"        # used for serialization
tokio = "1.0"        # async runtime
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert p.name == "demo"
    assert p.version == "0.1.0"
    assert len(p.dependencies) == 2
    assert p.dependencies[0] == RustDependency(name="serde", version="1.0", dev=False)
    assert p.dependencies[1] == RustDependency(name="tokio", version="1.0", dev=False)


def test_parse_cargo_toml_comment_only_line():
    content = """[package]
# this is just a comment
name = "demo"
# another one
version = "0.1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert p.name == "demo"
    assert p.version == "0.1.0"


# ── parse_cargo_toml — multi-line table values ───────────────────────────


def test_parse_cargo_toml_multiline_table_dependency():
    """A table form spanning several physical lines must still be parsed."""
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
tokio = { version = "1.0", features = [
    "full",
    "rt-multi-thread",
] }
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0] == RustDependency(name="tokio", version="1.0", dev=False)


# ── parse_cargo_toml — error & edge cases ─────────────────────────────────


def test_parse_cargo_toml_empty_string():
    p = parse_cargo_toml("")
    assert p.valid is False
    assert p.name == ""
    assert p.version == ""
    assert p.dependencies == []
    assert p.dev_dependencies == []


def test_parse_cargo_toml_whitespace_only():
    p = parse_cargo_toml("   \n\t  \n")
    assert p.valid is False


def test_parse_cargo_toml_none_input():
    p = parse_cargo_toml(None)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_cargo_toml_non_string_input():
    p = parse_cargo_toml(12345)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_cargo_toml_no_package_section():
    """No [package] header → valid=False even if deps are present."""
    content = """[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is False
    assert p.name == ""


def test_parse_cargo_toml_package_section_without_name():
    """[package] without a name field → valid=False."""
    content = """[package]
version = "0.1.0"

[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    assert p.valid is False


def test_parse_cargo_toml_no_dependencies_sections():
    p = parse_cargo_toml('[package]\nname = "demo"\nversion = "0.1.0"\n')
    assert p.valid is True
    assert p.dependencies == []
    assert p.dev_dependencies == []


def test_parse_cargo_toml_empty_dependency_sections():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]

[dev-dependencies]
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert p.dependencies == []
    assert p.dev_dependencies == []


def test_parse_cargo_toml_crate_name_with_hyphen():
    """Cargo crate names commonly contain hyphens."""
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
my-crate = "1.0"
zero-copy = { version = "0.5", features = ["fast"] }
"""
    p = parse_cargo_toml(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0].name == "my-crate"
    assert p.dependencies[0].version == "1.0"
    assert p.dependencies[1].name == "zero-copy"
    assert p.dependencies[1].version == "0.5"


# ── RustProject.require_for() helper ──────────────────────────────────────


def test_rust_project_require_for_found_in_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"""
    p = parse_cargo_toml(content)
    dep = p.require_for("serde")
    assert dep is not None
    assert dep.version == "1.0"
    assert dep.dev is False


def test_rust_project_require_for_found_in_dev_dependencies():
    content = """[package]
name = "demo"
version = "0.1.0"

[dev-dependencies]
proptest = "1.0"
"""
    p = parse_cargo_toml(content)
    dep = p.require_for("proptest")
    assert dep is not None
    assert dep.version == "1.0"
    assert dep.dev is True


def test_rust_project_require_for_not_found():
    p = parse_cargo_toml('[package]\nname = "demo"\nversion = "0.1.0"\n')
    dep = p.require_for("nonexistent-crate")
    assert dep is None
