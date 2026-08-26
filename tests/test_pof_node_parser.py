# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the Node.js PoF project parser (Phase 14).

Covers:
  * detect_node_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list.
  * parse_package_json: valid manifest, empty input, non-JSON, JSON array
    (not an object), missing fields, non-string values, BOM, line comments,
    and a real-world example with scripts + dev deps.
  * NodeProject.script(name) helper.
"""

import pytest

from gsc_cli.gsc_pof_node_parser import (
    NodeProject,
    NodeScript,
    detect_node_project,
    parse_package_json,
)


# ── detect_node_project ────────────────────────────────────────────────


def test_detect_node_project_with_package_json():
    assert detect_node_project(["src/index.js", "package.json", "README.md"]) is True


def test_detect_node_project_no_package_json():
    assert detect_node_project(["src/index.js", "README.md", "yarn.lock"]) is False


def test_detect_node_project_empty_list():
    assert detect_node_project([]) is False


def test_detect_node_project_case_insensitive():
    # Real Windows / macOS filesystems may yield "Package.JSON".
    assert detect_node_project(["Package.JSON"]) is True
    assert detect_node_project(["package.Json"]) is True


def test_detect_node_project_handles_absolute_and_windows_paths():
    files = [
        "/home/user/proj/package.json",
        "C:\\projects\\demo\\package.json",
        "src\\nested\\package.json",  # nested — still detected (basename match)
    ]
    assert detect_node_project(files) is True


def test_detect_node_project_ignores_non_string_entries():
    # Defensive: a buggy caller might pass mixed types; should not crash.
    # We pass a deliberately heterogeneous iterable to confirm the helper's
    # isinstance check is honoured at runtime (Pyright flags this on purpose).
    detect_node_project([None, 42, b"package.json", "package.json"])  # type: ignore[list-item]


def test_detect_node_project_ignores_substring_matches():
    # "mypackage.json" must NOT match — only an exact basename "package.json".
    assert detect_node_project(["mypackage.json", "package.json.bak"]) is False


# ── parse_package_json — happy path ───────────────────────────────────


def test_parse_package_json_minimal():
    p = parse_package_json('{"name": "demo"}')
    assert isinstance(p, NodeProject)
    assert p.valid is True
    assert p.name == "demo"
    assert p.version == ""
    assert p.main == ""
    assert p.scripts == []
    assert p.dependencies == {}
    assert p.dev_dependencies == {}


def test_parse_package_json_full_manifest():
    content = """{
        "name": "demo-app",
        "version": "1.2.3",
        "main": "dist/index.js",
        "scripts": {
            "start": "node dist/index.js",
            "test": "jest",
            "build": "tsc -p ."
        },
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "4.17.21"
        },
        "devDependencies": {
            "jest": "^29.0.0",
            "typescript": "5.0.0"
        }
    }"""
    p = parse_package_json(content)
    assert p.valid is True
    assert p.name == "demo-app"
    assert p.version == "1.2.3"
    assert p.main == "dist/index.js"
    assert p.script("start") == "node dist/index.js"
    assert p.script("test") == "jest"
    assert p.script("missing") == ""

    # Scripts are sorted alphabetically by name — explicit on the dataclass
    # contract, not accidental; tests below rely on it.
    assert [s.name for s in p.scripts] == ["build", "start", "test"]
    assert p.scripts[0] == NodeScript(name="build", command="tsc -p .")

    assert p.dependencies == {"express": "^4.18.0", "lodash": "4.17.21"}
    assert p.dev_dependencies == {"jest": "^29.0.0", "typescript": "5.0.0"}


def test_parse_package_json_to_dict_roundtrip():
    content = '{"name": "x", "main": "index.js", "scripts": {"a": "b"}}'
    p = parse_package_json(content)
    d = p.to_dict()
    assert d["name"] == "x"
    assert d["main"] == "index.js"
    assert d["scripts"] == [{"name": "a", "command": "b"}]
    assert d["dependencies"] == {}
    assert d["devDependencies"] == {}
    assert d["valid"] is True


# ── parse_package_json — error & edge cases ───────────────────────────


def test_parse_package_json_empty_string():
    p = parse_package_json("")
    assert p.valid is False
    assert p.name == "" and p.scripts == []


def test_parse_package_json_whitespace_only():
    p = parse_package_json("   \n\t  ")
    assert p.valid is False


def test_parse_package_json_none_input():
    p = parse_package_json(None)
    assert p.valid is False


def test_parse_package_json_non_string_input():
    p = parse_package_json(12345)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_package_json_malformed_returns_invalid():
    p = parse_package_json("{ this is not json }")
    assert p.valid is False
    assert p.name == ""


def test_parse_package_json_truncated_returns_invalid():
    p = parse_package_json('{"name": "demo", "vers')  # truncated
    assert p.valid is False


def test_parse_package_json_array_not_object():
    # JSON spec allows top-level arrays; package.json must be an object.
    p = parse_package_json("[1, 2, 3]")
    assert p.valid is False


def test_parse_package_json_string_at_top_level():
    p = parse_package_json('"just a string"')
    assert p.valid is False


def test_parse_package_json_strips_bom():
    content = '\ufeff{"name": "bom-demo", "main": "index.js"}'
    p = parse_package_json(content)
    assert p.valid is True
    assert p.name == "bom-demo"
    assert p.main == "index.js"


def test_parse_package_json_strips_line_comments():
    # Some legacy tools embed // comments in hand-edited package.json files.
    content = """// header comment
{
    // pick a real name later
    "name": "commented",
    "main": "index.js"
}
"""
    p = parse_package_json(content)
    assert p.valid is True
    assert p.name == "commented"
    assert p.main == "index.js"


def test_parse_package_json_skips_non_string_name():
    # A numeric "name" is non-conforming but must not crash the parser.
    p = parse_package_json('{"name": 42}')
    assert p.valid is True
    assert p.name == ""  # _as_str coerces non-strings to ""


def test_parse_package_json_skips_non_dict_scripts():
    p = parse_package_json('{"scripts": "not a dict"}')
    assert p.valid is True
    assert p.scripts == []


def test_parse_package_json_skips_non_dict_dependencies():
    p = parse_package_json('{"dependencies": ["express", "lodash"]}')
    assert p.valid is True
    assert p.dependencies == {}


def test_parse_package_json_coerces_non_string_versions():
    # npm accepts strings, but a buggy lockfile may produce ints — keep the
    # dependency entry instead of dropping it; the PoF orchestrator decides.
    p = parse_package_json('{"dependencies": {"express": 4}}')
    assert p.valid is True
    assert p.dependencies == {"express": "4"}


def test_parse_package_json_drops_empty_string_name():
    # Defensive: an empty key would make a useless dep entry.
    p = parse_package_json('{"dependencies": {"": "1.0.0", "real": "2.0.0"}}')
    assert p.valid is True
    assert p.dependencies == {"real": "2.0.0"}


# ── NodeProject.script() helper ───────────────────────────────────────


def test_nodeproject_script_helper_returns_command():
    p = parse_package_json('{"scripts": {"test": "jest --watch"}}')
    assert p.script("test") == "jest --watch"
    assert p.script("build") == ""


def test_nodeproject_script_helper_empty_command_value():
    p = parse_package_json('{"scripts": {"noop": ""}}')
    assert p.script("noop") == ""
