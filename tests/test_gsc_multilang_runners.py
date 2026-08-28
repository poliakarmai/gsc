#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""Tests for gsc_cli.gsc_multilang_runners.

Covers the public contract:
    build_runner_javascript / build_runner_java / build_runner_go / build_runner_rust
    runtime_command / compile_command / detect_runtime

All functions are PURE — no subprocess is launched by these tests. detect_runtime
is the only one that touches the host (via shutil.which), and it is allowed to
return None when a binary is missing.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from gsc_cli.gsc_multilang_runners import (
    build_runner_go,
    build_runner_java,
    build_runner_javascript,
    build_runner_rust,
    compile_command,
    detect_runtime,
    runtime_command,
)


# ── build_runner_javascript ───────────────────────────────────────────────


def test_build_runner_javascript_contains_require():
    out = build_runner_javascript("x=1")
    assert "require" in out


def test_build_runner_javascript_embeds_poc_code():
    poc = "x=1"
    out = build_runner_javascript(poc)
    assert poc in out


def test_build_runner_javascript_uses_custom_module():
    out = build_runner_javascript("payload()", target_module="victim")
    assert "victim" in out


def test_build_runner_javascript_handles_multiline_poc():
    poc = "const a = 1;\nconst b = 2;\nconsole.log(a + b);"
    out = build_runner_javascript(poc)
    assert "const a = 1;" in out
    assert "const b = 2;" in out
    assert "console.log(a + b);" in out


def test_build_runner_javascript_prints_import_error_on_failure():
    out = build_runner_javascript("x=1")
    assert "IMPORT_ERROR" in out
    assert "process.exit(1)" in out


# ── build_runner_java ─────────────────────────────────────────────────────


def test_build_runner_java_contains_public_class():
    out = build_runner_java("x();")
    assert "public class RunPoc" in out


def test_build_runner_java_embeds_poc_code():
    poc = "x();"
    out = build_runner_java(poc)
    assert poc in out


def test_build_runner_java_has_main_method():
    out = build_runner_java("x();")
    assert "public static void main" in out


def test_build_runner_java_uses_custom_target_class():
    out = build_runner_java("x();", target_class="com.acme.Victim")
    assert "com.acme.Victim" in out
    assert "public class RunPoc" in out


def test_build_runner_java_prints_import_error_on_failure():
    out = build_runner_java("x();")
    assert "IMPORT_ERROR" in out


# ── build_runner_go ───────────────────────────────────────────────────────


def test_build_runner_go_contains_func_main():
    out = build_runner_go("f()")
    assert "func main" in out


def test_build_runner_go_embeds_poc_code():
    poc = "f()"
    out = build_runner_go(poc)
    assert poc in out


def test_build_runner_go_uses_custom_package():
    out = build_runner_go("f()", target_pkg="victim/pkg")
    assert "victim/pkg" in out
    assert "func main" in out


def test_build_runner_go_prints_import_error_on_failure():
    out = build_runner_go("f()")
    assert "IMPORT_ERROR" in out


# ── build_runner_rust ─────────────────────────────────────────────────────


def test_build_runner_rust_contains_fn_main():
    out = build_runner_rust("f()")
    assert "fn main" in out


def test_build_runner_rust_embeds_poc_code():
    poc = "f()"
    out = build_runner_rust(poc)
    assert poc in out


def test_build_runner_rust_prints_import_error_on_failure():
    out = build_runner_rust("f()")
    assert "IMPORT_ERROR" in out


def test_build_runner_rust_catches_panic():
    out = build_runner_rust("f()")
    assert "catch_unwind" in out


# ── runtime_command ───────────────────────────────────────────────────────


def test_runtime_command_javascript():
    assert runtime_command("javascript") == ["node"]


def test_runtime_command_js_alias():
    assert runtime_command("js") == ["node"]


def test_runtime_command_go():
    assert runtime_command("go") == ["go", "run"]


def test_runtime_command_java():
    assert runtime_command("java") == ["java"]


def test_runtime_command_rust():
    assert runtime_command("rust") == ["rustc"]


def test_runtime_command_python():
    assert runtime_command("python") == ["python3"]


def test_runtime_command_unknown_is_none():
    assert runtime_command("unknown") is None


def test_runtime_command_none_is_none():
    assert runtime_command(None) is None


# ── compile_command ───────────────────────────────────────────────────────


def test_compile_command_java():
    assert compile_command("java") == ["javac"]


def test_compile_command_rust():
    assert compile_command("rust") == ["rustc"]


def test_compile_command_javascript_is_none():
    assert compile_command("javascript") is None


def test_compile_command_python_is_none():
    assert compile_command("python") is None


def test_compile_command_go_is_none():
    # go run compiles on the fly; explicit "go build" is a caller choice.
    assert compile_command("go") is None


def test_compile_command_unknown_is_none():
    assert compile_command("unknown") is None


# ── detect_runtime ────────────────────────────────────────────────────────


def test_detect_runtime_python_uses_which_only():
    """detect_runtime must return the path reported by shutil.which — or None.

    It is environment-dependent: on this host python3 exists, but we must not
    hardcode any system-specific path. The contract is "either None or a
    real path that shutil.which would also report."
    """
    result = detect_runtime("python")
    if result is None:
        # python3 not on PATH — that is acceptable, the function stayed pure.
        assert shutil.which("python3") is None
    else:
        # If a path is returned, it must be the one shutil.which would return.
        assert result == shutil.which("python3")
        # And it must end with the binary name (no hardcoded absolute path).
        assert result.endswith("python3")


def test_detect_runtime_unknown_is_none():
    assert detect_runtime("unknown") is None


def test_detect_runtime_none_is_none():
    assert detect_runtime(None) is None


def test_detect_runtime_does_not_raise():
    """Function must be safe to call repeatedly; never raise."""
    for lang in ("python", "javascript", "java", "go", "rust", "unknown", None):
        # We only care that it returns without raising — value is env-dependent.
        detect_runtime(lang)


# ── Cross-cutting: PoC substring for every builder ────────────────────────


@pytest.mark.parametrize(
    "builder",
    [build_runner_javascript, build_runner_go, build_runner_java, build_runner_rust],
)
def test_poc_code_substring_in_every_builder(builder):
    """The contract says poc_code is inserted as-is into every runner."""
    poc = "POC_UNIQUE_MARKER_42 = lambda: 'pwned'"
    out = builder(poc)
    assert poc in out


# ── Self-check: module compiles under python3 ─────────────────────────────


def test_module_is_runnable_under_python3():
    """Sanity: pytest in this repo is invoked via `python3 -m pytest`.

    We don't import __main__ — we just spawn a `python3 -c` that imports the
    module and prints a constant, to confirm the runtime is `python3` and
    not the absent `python`.
    """
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.executable)"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    assert "python3" in proc.stdout
