# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the uv PoF project parser (Phase 14).

Covers:
  * detect_uv_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list.
  * parse_uv_lock: valid manifest, multiple [[package]] tables, empty
    input, non-string input, broken input (no [[package]] with name),
    top-level requires-python, multi-line ``source = { ... }`` /
    ``dependencies = [ ... ]`` / ``wheels = [ ... ]`` blocks.
  * UvProject.require_for() helper.
"""

import pytest

from gsc_cli.gsc_pof_uv_parser import (
    UvPackage,
    UvProject,
    detect_uv_project,
    parse_uv_lock,
)


# ── detect_uv_project ────────────────────────────────────────────────────


def test_detect_uv_project_with_uv_lock():
    assert detect_uv_project(["src/main.py", "uv.lock", "README.md"]) is True


def test_detect_uv_project_no_uv_lock():
    assert detect_uv_project(["src/main.py", "README.md", "pyproject.toml"]) is False


def test_detect_uv_project_empty_list():
    assert detect_uv_project([]) is False


def test_detect_uv_project_case_insensitive():
    # Real Windows / macOS filesystems may yield "UV.LOCK".
    assert detect_uv_project(["UV.LOCK"]) is True
    assert detect_uv_project(["Uv.Lock"]) is True
    assert detect_uv_project(["uv.LOCK"]) is True


def test_detect_uv_project_does_not_match_package_json():
    # Substring-style filesystems can produce noise; only exact basename.
    assert detect_uv_project(["package.json"]) is False


def test_detect_uv_project_handles_absolute_and_windows_paths():
    files = [
        "/home/user/proj/uv.lock",
        "C:\\projects\\demo\\uv.lock",
        "src\\nested\\uv.lock",  # nested — still detected (basename match)
    ]
    assert detect_uv_project(files) is True


def test_detect_uv_project_ignores_non_string_entries():
    # Defensive: a buggy caller might pass mixed types; should not crash.
    # We pass a deliberately heterogeneous iterable to confirm the helper's
    # isinstance check is honoured at runtime (Pyright flags this on purpose).
    detect_uv_project([None, 42, b"uv.lock", "uv.lock"])  # type: ignore[list-item]


def test_detect_uv_project_ignores_substring_matches():
    # "myuv.lock" must NOT match — only an exact basename "uv.lock".
    assert detect_uv_project(["myuv.lock", "uv.lock.bak"]) is False


# ── parse_uv_lock — happy path ───────────────────────────────────────────


def test_parse_uv_lock_minimal_single_package():
    content = (
        'version = 1\n'
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
    )
    p = parse_uv_lock(content)
    assert isinstance(p, UvProject)
    assert p.valid is True
    assert p.requires_python == ">=3.11"
    assert len(p.packages) == 1
    assert p.packages[0] == UvPackage(name="click", version="8.1.7")


def test_parse_uv_lock_multiple_packages():
    content = (
        'version = 1\n'
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
        '\n'
        '[[package]]\n'
        'name = "colorama"\n'
        'version = "0.4.6"\n'
        '\n'
        '[[package]]\n'
        'name = "requests"\n'
        'version = "2.32.3"\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is True
    assert p.requires_python == ">=3.11"
    assert len(p.packages) == 3
    assert p.packages[0] == UvPackage(name="click", version="8.1.7")
    assert p.packages[1] == UvPackage(name="colorama", version="0.4.6")
    assert p.packages[2] == UvPackage(name="requests", version="2.32.3")


def test_parse_uv_lock_to_dict_roundtrip():
    content = (
        'requires-python = ">=3.12"\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
    )
    p = parse_uv_lock(content)
    d = p.to_dict()
    assert d == {
        "valid": True,
        "requires_python": ">=3.12",
        "packages": [{"name": "click", "version": "8.1.7"}],
    }


def test_parse_uv_lock_real_world_example():
    content = """\
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
sdist = { url = "https://files.pythonhosted.org/packages/source/c/click/click-8.1.7.tar.gz", hash = "sha256:abc123" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/wheel/c/click-8.1.7-py3-none-any.whl", hash = "sha256:def456" },
]

[[package]]
name = "colorama"
version = "0.4.6"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example/colorama-0.4.6.tar.gz", hash = "sha256:zzz999" }
wheels = [ { url = "https://example/colorama.whl", hash = "sha256:yyy888" } ]
"""
    p = parse_uv_lock(content)
    assert p.valid is True
    assert p.requires_python == ">=3.11"
    assert len(p.packages) == 2
    assert p.packages[0] == UvPackage(name="click", version="8.1.7")
    assert p.packages[1] == UvPackage(name="colorama", version="0.4.6")


def test_parse_uv_lock_with_package_dependencies_does_not_break():
    """A package with a multi-line ``dependencies = [...]`` block must
    still produce a clean UvPackage(name, version)."""
    content = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "flask"
version = "3.0.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "click" },
    { name = "itsdangerous" },
    { name = "jinja2" },
    { name = "markupsafe" },
    { name = "werkzeug" },
]
"""
    p = parse_uv_lock(content)
    assert p.valid is True
    assert len(p.packages) == 1
    assert p.packages[0] == UvPackage(name="flask", version="3.0.3")


def test_parse_uv_lock_with_multiline_source_block():
    """A ``source = { ... }`` inline table spread across several lines
    must not throw off the section boundary detector."""
    content = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "mypkg"
version = "1.0.0"
source = {
    registry = "https://pypi.org/simple",
}
sdist = { url = "https://example/mypkg-1.0.0.tar.gz", hash = "sha256:abc" }
wheels = [
    { url = "https://example/mypkg-1.0.0-py3-none-any.whl", hash = "sha256:def" },
]
"""
    p = parse_uv_lock(content)
    assert p.valid is True
    assert len(p.packages) == 1
    assert p.packages[0] == UvPackage(name="mypkg", version="1.0.0")


def test_parse_uv_lock_package_without_version():
    """A [[package]] table with a name but no version is tolerated
    (version is empty string) and the file stays valid."""
    content = (
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'name = "mypkg"\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is True
    assert p.requires_python == ">=3.11"
    assert p.packages == [UvPackage(name="mypkg", version="")]


def test_parse_uv_lock_without_requires_python():
    """A uv.lock without a top-level requires-python is valid; the
    field is just empty."""
    content = (
        'version = 1\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is True
    assert p.requires_python == ""
    assert p.packages == [UvPackage(name="click", version="8.1.7")]


# ── parse_uv_lock — error & edge cases ───────────────────────────────────


def test_parse_uv_lock_empty_string():
    p = parse_uv_lock("")
    assert p.valid is False
    assert p.requires_python == ""
    assert p.packages == []


def test_parse_uv_lock_whitespace_only():
    p = parse_uv_lock("   \n\t  \n")
    assert p.valid is False


def test_parse_uv_lock_none_input():
    p = parse_uv_lock(None)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_uv_lock_non_string_input():
    p = parse_uv_lock(12345)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_uv_lock_no_package_tables():
    """A file with only ``[manifest]`` but no ``[[package]]`` → valid=False."""
    content = (
        'version = 1\n'
        'requires-python = ">=3.11"\n'
        '\n'
        '[manifest]\n'
        'members = ["myapp"]\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is False
    assert p.requires_python == ">=3.11"
    assert p.packages == []


def test_parse_uv_lock_package_without_name_is_invalid():
    """A [[package]] table with no ``name`` field → valid=False even if
    a version is present. The lockfile would be unusable for SCA."""
    content = (
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'version = "0.0.1"\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is False
    assert p.packages == []


def test_parse_uv_lock_strips_line_comments():
    content = """\
# this is a comment
version = 1            # uv format version
requires-python = ">=3.11"   # python requirement

# the click package
[[package]]
name = "click"         # CLI builder
version = "8.1.7"      # resolved
"""
    p = parse_uv_lock(content)
    assert p.valid is True
    assert p.requires_python == ">=3.11"
    assert p.packages == [UvPackage(name="click", version="8.1.7")]


def test_parse_uv_lock_requires_python_only_inside_section_is_ignored():
    """A ``requires-python`` declared INSIDE a [[package]] table must
    not be picked up as the top-level value."""
    content = (
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
        'requires-python = ">=3.10"\n'
    )
    p = parse_uv_lock(content)
    assert p.valid is True
    # Top-level requires-python stays empty; the per-package one is ignored.
    assert p.requires_python == ""


# ── UvProject.require_for() helper ──────────────────────────────────────


def test_uv_project_require_for_found():
    content = (
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
        '\n'
        '[[package]]\n'
        'name = "colorama"\n'
        'version = "0.4.6"\n'
    )
    p = parse_uv_lock(content)
    dep = p.require_for("colorama")
    assert dep is not None
    assert dep.version == "0.4.6"


def test_uv_project_require_for_not_found():
    p = parse_uv_lock(
        '[[package]]\nname = "click"\nversion = "8.1.7"\n'
    )
    dep = p.require_for("nonexistent-package")
    assert dep is None
