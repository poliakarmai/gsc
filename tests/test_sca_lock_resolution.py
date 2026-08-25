# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for SCA lockfile resolution (DD-06): exact version from
package-lock.json must override a manifest range lower bound."""

from gsc_sca import parse_package_lock, parse_package_json


def test_parse_package_lock_extracts_exact_versions():
    lock = (
        '{"packages": {'
        '"": {"name": "gsc-dashboard"}, '
        '"node_modules/next": {"version": "15.5.23"}, '
        '"node_modules/react": {"version": "19.2.8"}}}'
    )
    out = parse_package_lock(lock)
    assert out == {"next": "15.5.23", "react": "19.2.8"}


def test_parse_package_json_resolves_range_from_lock():
    manifest = '{"dependencies": {"next": "^15.5.16", "react": "^19.0.0"}}'
    lock = {"next": "15.5.23", "react": "19.2.8"}
    pkgs = parse_package_json("package.json", manifest, lock_versions=lock)
    by_name = {p.name: p.version for p in pkgs}
    assert by_name["next"] == "15.5.23"  # resolved from lock, not lower bound
    assert by_name["react"] == "19.2.8"


def test_parse_package_json_exact_version_not_overridden():
    # A pinned version (no range hint) stays as-is even if the lock differs.
    manifest = '{"dependencies": {"next": "15.5.23"}}'
    lock = {"next": "99.0.0"}
    pkgs = parse_package_json("package.json", manifest, lock_versions=lock)
    assert pkgs[0].version == "15.5.23"


def test_parse_package_json_no_lock_uses_lower_bound():
    manifest = '{"dependencies": {"next": "^15.5.16"}}'
    pkgs = parse_package_json("package.json", manifest)  # no lock
    assert pkgs[0].version == "15.5.16"


def test_parse_package_lock_skips_nested_transitive():
    # A nested transitive copy must not overwrite the hoisted top-level version.
    lock = (
        '{"packages": {'
        '"node_modules/next": {"version": "15.5.23"}, '
        '"node_modules/zod/node_modules/next": {"version": "16.0.0"}}}'
    )
    out = parse_package_lock(lock)
    assert out == {"next": "15.5.23"}  # top-level wins, nested skipped
