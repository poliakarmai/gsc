# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the PHP / Composer PoF project parser (Phase 14).

Covers:
  * detect_php_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list, never
    matches other manifest filenames (package.json, Cargo.lock, …).
  * parse_composer_json: valid manifest, empty input, non-JSON, JSON
    array (not an object), missing or non-string ``name``, non-dict
    ``require``, non-string version constraints, BOM, and ``//`` line
    comments — all of these must yield a non-raising, well-typed
    ``ComposerProject`` result.
  * ComposerProject.to_dict() and require_for() helpers.
"""

import pytest

from gsc_cli.gsc_pof_php_parser import (
    ComposerProject,
    detect_php_project,
    parse_composer_json,
)


# ── detect_php_project ────────────────────────────────────────────────


def test_detect_php_project_with_composer_json():
    assert detect_php_project(["src/index.php", "composer.json", "README.md"]) is True


def test_detect_php_project_no_composer_json():
    assert detect_php_project(["src/index.php", "README.md", "package.json"]) is False


def test_detect_php_project_empty_list():
    assert detect_php_project([]) is False


def test_detect_php_project_case_insensitive():
    # Real Windows / macOS filesystems may yield "Composer.JSON".
    assert detect_php_project(["COMPOSER.JSON"]) is True
    assert detect_php_project(["Composer.Json"]) is True


def test_detect_php_project_does_not_match_package_json():
    # The detect helper is PHP-specific: a sibling package.json must
    # not be reported as a PHP project.
    assert detect_php_project(["package.json"]) is False
    assert detect_php_project(["Cargo.lock", "pom.xml", "composer.lock"]) is False


def test_detect_php_project_handles_absolute_and_windows_paths():
    files = [
        "/home/user/proj/composer.json",
        "C:\\projects\\demo\\composer.json",
        "src\\nested\\composer.json",  # nested — still detected (basename match)
    ]
    assert detect_php_project(files) is True


def test_detect_php_project_ignores_non_string_entries():
    # Defensive: a buggy caller might pass mixed types; should not crash.
    detect_php_project([None, 42, b"composer.json", "composer.json"])  # type: ignore[list-item]


def test_detect_php_project_ignores_substring_matches():
    # "mycomposer.json" must NOT match — only an exact basename "composer.json".
    assert detect_php_project(["mycomposer.json", "composer.json.bak"]) is False


# ── parse_composer_json — happy path ─────────────────────────────────


def test_parse_composer_json_minimal():
    p = parse_composer_json('{"name": "acme/my-app", "require": {"php": ">=8.1"}}')
    assert isinstance(p, ComposerProject)
    assert p.valid is True
    assert p.name == "acme/my-app"
    assert p.require == {"php": ">=8.1"}
    assert p.require_dev == {}


def test_parse_composer_json_full_manifest():
    content = """{
        "name": "acme/my-app",
        "description": "Example",
        "require": {
            "php": ">=8.1",
            "symfony/console": "^6.0",
            "guzzlehttp/guzzle": "^7.8"
        },
        "require-dev": {
            "phpunit/phpunit": "^10.0",
            "phpstan/phpstan": "1.10.0"
        }
    }"""
    p = parse_composer_json(content)
    assert p.valid is True
    assert p.name == "acme/my-app"
    assert p.require == {
        "php": ">=8.1",
        "symfony/console": "^6.0",
        "guzzlehttp/guzzle": "^7.8",
    }
    assert p.require_dev == {
        "phpunit/phpunit": "^10.0",
        "phpstan/phpstan": "1.10.0",
    }


def test_parse_composer_json_multiple_dependencies():
    content = """{
        "name": "vendor/big-app",
        "require": {
            "php": "^8.0",
            "a/a": "1.0",
            "b/b": "2.0",
            "c/c": "3.0",
            "d/d": "4.0"
        }
    }"""
    p = parse_composer_json(content)
    assert p.valid is True
    assert len(p.require) == 5
    assert p.require["b/b"] == "2.0"


def test_parse_composer_json_to_dict_roundtrip():
    content = '{"name": "acme/x", "require": {"php": ">=8.1"}, "require-dev": {"phpunit/phpunit": "^10.0"}}'
    p = parse_composer_json(content)
    d = p.to_dict()
    assert d["name"] == "acme/x"
    assert d["require"] == {"php": ">=8.1"}
    assert d["require-dev"] == {"phpunit/phpunit": "^10.0"}
    assert d["valid"] is True


# ── parse_composer_json — error & edge cases ─────────────────────────


def test_parse_composer_json_empty_string():
    p = parse_composer_json("")
    assert p.valid is False
    assert p.name == ""
    assert p.require == {}


def test_parse_composer_json_whitespace_only():
    p = parse_composer_json("   \n\t  ")
    assert p.valid is False


def test_parse_composer_json_none_input():
    p = parse_composer_json(None)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_composer_json_non_string_input():
    p = parse_composer_json(12345)  # type: ignore[arg-type]
    assert p.valid is False


def test_parse_composer_json_malformed_returns_invalid():
    p = parse_composer_json("{ this is not json }")
    assert p.valid is False
    assert p.name == ""


def test_parse_composer_json_truncated_returns_invalid():
    p = parse_composer_json('{"name": "demo", "req')  # truncated
    assert p.valid is False


def test_parse_composer_json_array_not_object():
    # JSON spec allows top-level arrays; composer.json must be an object.
    p = parse_composer_json("[1, 2, 3]")
    assert p.valid is False


def test_parse_composer_json_missing_name_is_invalid():
    # Per the dataclass contract: valid=False when there is no "name".
    p = parse_composer_json('{"require": {"php": ">=8.1"}}')
    assert p.valid is False
    assert p.name == ""


def test_parse_composer_json_missing_require_is_invalid():
    # Per the dataclass contract: valid=False when "require" is missing
    # (a non-dict require also counts as missing).
    p = parse_composer_json('{"name": "acme/my-app"}')
    assert p.valid is False
    assert p.name == "acme/my-app"  # name itself parsed cleanly


def test_parse_composer_json_non_dict_require_is_invalid():
    p = parse_composer_json('{"name": "acme/my-app", "require": ["php"]}')
    assert p.valid is False
    assert p.require == {}


def test_parse_composer_json_skips_non_string_name():
    # A numeric "name" is non-conforming but must not crash the parser.
    p = parse_composer_json('{"name": 42, "require": {"php": ">=8.1"}}')
    assert p.valid is False  # _as_str coerces to "" -> invalid by contract


def test_parse_composer_json_coerces_non_string_versions():
    # Composer accepts strings, but a buggy manifest may produce ints —
    # keep the dependency entry instead of dropping it; the PoF
    # orchestrator decides.
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"php": 8, "symfony/console": "^6.0"}}'
    )
    assert p.valid is True
    assert p.require == {"php": "8", "symfony/console": "^6.0"}


def test_parse_composer_json_drops_empty_string_name():
    # Defensive: an empty key would make a useless dep entry.
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"": "1.0.0", "real/lib": "2.0.0"}}'
    )
    assert p.valid is True
    assert p.require == {"real/lib": "2.0.0"}


def test_parse_composer_json_strips_bom():
    content = '\ufeff{"name": "bom/demo", "require": {"php": ">=8.1"}}'
    p = parse_composer_json(content)
    assert p.valid is True
    assert p.name == "bom/demo"
    assert p.require == {"php": ">=8.1"}


def test_parse_composer_json_strips_line_comments():
    # Some legacy tools embed // comments in hand-edited composer.json files.
    # The tolerant preclean strips whole-line // comments; inline // after a
    # value is intentionally NOT handled (it would require a real
    # JSON-with-comments parser) — see gsc_pof_node_parser for the same limit.
    content = """// header comment
{
    // pick a real name later
    "name": "commented/app",
    "require": {
        "php": ">=8.1"
    }
}
"""
    p = parse_composer_json(content)
    assert p.valid is True
    assert p.name == "commented/app"
    assert p.require == {"php": ">=8.1"}


# ── ComposerProject.require_for() helper ─────────────────────────────


def test_composerproject_require_for_finds_in_require():
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"symfony/console": "^6.0"}}'
    )
    assert p.require_for("symfony/console") == "^6.0"


def test_composerproject_require_for_finds_in_require_dev():
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"php": ">=8.1"},'
        ' "require-dev": {"phpunit/phpunit": "^10.0"}}'
    )
    assert p.require_for("phpunit/phpunit") == "^10.0"


def test_composerproject_require_for_returns_none_when_missing():
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"php": ">=8.1"}}'
    )
    assert p.require_for("does/not-exist") is None


def test_composerproject_require_for_require_wins_over_require_dev():
    # Composer runtime semantics: a package declared in both maps is
    # resolved from ``require`` first.
    p = parse_composer_json(
        '{"name": "acme/x", "require": {"lib/x": "^1.0"},'
        ' "require-dev": {"lib/x": "^2.0"}}'
    )
    assert p.require_for("lib/x") == "^1.0"
