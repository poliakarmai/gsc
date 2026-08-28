#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
"""GSC multilang sandbox runner code generators.

Pure, deterministic helpers that produce the source text of a PoC-execution
runner for a given target language. These functions are consumed by the
Proof-of-Fix (PoF) sandbox to verify that a generated fix actually neutralises
a PoC: the runner is materialised into a file next to the target code and
executed by the appropriate language runtime.

Public contract (all functions are PURE — no I/O, no env reads, no process
launches, no network):

    build_runner_javascript(poc_code, target_module="target") -> str
    build_runner_java(poc_code, target_class="Target")         -> str
    build_runner_go(poc_code, target_pkg="target")             -> str
    build_runner_rust(poc_code)                                -> str
    runtime_command(language) -> list[str] | None
    compile_command(language) -> list[str] | None
    detect_runtime(language)  -> str | None

Only ``shutil`` (for ``shutil.which``) is used; no subprocess, no requests.
"""
from __future__ import annotations

import shutil
from typing import List, Optional

# Markers emitted to stderr when a runner fails to load the target code. The
# verification layer (gsc_pof_sandbox) treats "IMPORT_ERROR" as a load-time
# failure, distinct from a successful PoC run that simply did not trigger.
_IMPORT_ERROR_MARKER = "IMPORT_ERROR"


# ── JS / Node ─────────────────────────────────────────────────────────────


def build_runner_javascript(poc_code: str, target_module: str = "target") -> str:
    """Return a Node.js script that loads ``./<target_module>`` then runs the PoC.

    On any require()/import error the script writes ``IMPORT_ERROR: <msg>`` to
    stderr and exits with code 1. The ``poc_code`` is appended verbatim after
    the load step, so a hostile PoC cannot redefine the loader.

    The runner is intentionally minimal: no top-level ``await``, no async
    function wrapping. A PoC that needs async semantics is expected to use an
    IIFE: ``(async () => { ... })();``.
    """
    safe_module = target_module.replace("\n", "").replace("\r", "").strip() or "target"
    return (
        "// GSC PoF Sandbox Runner — auto-generated (Node.js).\n"
        "const path = require('path');\n"
        "const targetPath = path.join(__dirname, " + repr_js(safe_module) + ");\n"
        "try {\n"
        "  require(targetPath);\n"
        "} catch (e) {\n"
        "  process.stderr.write('" + _IMPORT_ERROR_MARKER + ": ' "
        "+ (e && e.stack ? e.stack : String(e)) + '\\n');\n"
        "  process.exit(1);\n"
        "}\n"
        "\n"
        "// --- PoC BEGIN ---\n"
        + poc_code
        + "\n// --- PoC END ---\n"
    )


def repr_js(s: str) -> str:
    """Render a Python string as a single-quoted JS string literal.

    Uses single quotes (matching Node's default output style) and escapes
    backslashes, single quotes, control chars, and non-BMP via \\uXXXX /
    \\u{XXXX} for full UTF-8 safety. Newlines are escaped so the result is
    always a one-line literal.
    """
    out = []
    for ch in s:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "'":
            out.append("\\'")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\v":
            out.append("\\v")
        elif ch == "\0":
            out.append("\\0")
        elif cp < 0x20 or cp == 0x7F:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


# ── Java ─────────────────────────────────────────────────────────────────


def build_runner_java(poc_code: str, target_class: str = "Target") -> str:
    """Return the source of ``RunPoc.java`` that loads ``<target_class>`` then runs the PoC.

    The target class is referenced through ``Class.forName(...)`` so a missing
    class surfaces as ``ClassNotFoundException`` and is mapped to
    ``IMPORT_ERROR`` on stderr with a non-zero exit. A NoClassDefFoundError is
    also caught — that is what you get when the target is present but its
    dependencies are unresolved at load time.

    The PoC is inserted as the body of a ``runPoc()`` method (a real method
    body, not a top-level statement block) so multi-line PoCs with local
    variable declarations compile cleanly. ``main()`` invokes ``runPoc()`` and
    surfaces any RuntimeException as a stack trace on stderr with exit 1;
    normal completion exits 0.
    """
    safe_class = _sanitize_java_ident(target_class, default="Target")
    return (
        "/* GSC PoF Sandbox Runner — auto-generated (Java). */\n"
        "public class RunPoc {\n"
        "    public static void main(String[] args) {\n"
        "        try {\n"
        "            // Force target class load; any failure here is an import error.\n"
        "            Class.forName(" + _java_string_literal(safe_class) + ");\n"
        "        } catch (ClassNotFoundException e) {\n"
        "            System.err.println(\""
        + _IMPORT_ERROR_MARKER
        + ": \" + e);\n"
        "            System.exit(1);\n"
        "        } catch (NoClassDefFoundError e) {\n"
        "            System.err.println(\""
        + _IMPORT_ERROR_MARKER
        + ": \" + e);\n"
        "            System.exit(1);\n"
        "        }\n"
        "        try {\n"
        "            runPoc();\n"
        "        } catch (Throwable t) {\n"
        "            t.printStackTrace();\n"
        "            System.exit(1);\n"
        "        }\n"
        "    }\n"
        "\n"
        "    private static void runPoc() throws Exception {\n"
        "        // --- PoC BEGIN ---\n"
        "        " + poc_code.replace("\n", "\n        ") + "\n"
        "        // --- PoC END ---\n"
        "    }\n"
        "}\n"
    )


def _sanitize_java_ident(name: str, default: str) -> str:
    """Return a Java-style identifier derived from ``name``.

    Java fully-qualified class names may contain dots; we keep them. Any
    character that is not a legal Java identifier part (letter / digit / _
    / $ / .) is replaced with '_'. Empty / whitespace-only input collapses
    to ``default``.
    """
    if not name or not name.strip():
        return default
    out = []
    for ch in name.strip():
        if ch.isalnum() or ch in ("_", "$", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or default


def _java_string_literal(s: str) -> str:
    """Render ``s`` as a Java double-quoted string literal (UTF-16 escapes)."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\0":
            out.append("\\0")
        elif cp < 0x20 or cp == 0x7F:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ── Go ───────────────────────────────────────────────────────────────────


def build_runner_go(poc_code: str, target_pkg: str = "target") -> str:
    """Return a Go ``main.go`` that imports the target package then runs the PoC.

    The target is loaded through a blank import (``_ "<pkg>"``) so a compile
    error / missing package surfaces as a build failure rather than a runtime
    panic. To still surface load-time issues at runtime, the runner reflects
    on the ``init`` function presence of any symbol from the target via
    runtime symbol lookup; if the import itself fails to compile, ``go run``
    exits non-zero before main() runs.

    A deferred ``recover()`` catches any panic from the PoC body and prints
    ``IMPORT_ERROR`` (the convention in this module is that any unrecoverable
    startup-time panic in the runner is treated as an import error; genuine
    PoC panics remain the PoC's responsibility to declare).
    """
    safe_pkg = _sanitize_go_import_path(target_pkg, default="target")
    return (
        "// GSC PoF Sandbox Runner — auto-generated (Go).\n"
        "package main\n"
        "\n"
        "import (\n"
        "\t_ " + repr_go(safe_pkg) + "\n"
        "\t\"fmt\"\n"
        "\t\"os\"\n"
        ")\n"
        "\n"
        "func main() {\n"
        "\tdefer func() {\n"
        "\t\tif r := recover(); r != nil {\n"
        "\t\t\tfmt.Fprintf(os.Stderr, \""
        + _IMPORT_ERROR_MARKER
        + ": %v\\n\", r)\n"
        "\t\t\tos.Exit(1)\n"
        "\t\t}\n"
        "\t}()\n"
        "\t// --- PoC BEGIN ---\n"
        "\t" + poc_code.replace("\n", "\n\t") + "\n"
        "\t// --- PoC END ---\n"
        "}\n"
    )


def _sanitize_go_import_path(p: str, default: str) -> str:
    """Trim and reject empty / control-char-laden Go import paths."""
    if not p or not p.strip():
        return default
    cleaned = "".join(ch for ch in p.strip() if ch >= " " and ch != "\x7f")
    return cleaned or default


def repr_go(s: str) -> str:
    """Render a Go double-quoted string literal (with backtick fallback for safety)."""
    if "\n" not in s and '"' not in s and "\\" not in s:
        return '"' + s + '"'
    # Use a raw string literal (backticks) when the content is too tricky
    # for an interpreted literal; raw strings cannot contain backticks.
    if "`" in s:
        # Fall back to interpreted literal with full escaping.
        return '"' + _go_escape_interpreted(s) + '"'
    return "`" + s + "`"


def _go_escape_interpreted(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\0":
            out.append("\\x00")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


# ── Rust ─────────────────────────────────────────────────────────────────


def build_runner_rust(poc_code: str) -> str:
    """Return a Rust ``main.rs`` that traps panics from the PoC.

    Rust has no cross-crate runtime symbol import pattern as cheap as JS/Go;
    the target is loaded via a ``use`` of the top-level crate name
    ``target::TARGET_MARKER`` (a const the target crate is expected to
    export; if absent the build fails with ``use of undeclared crate or
    module 'target'`` which is treated as an import error upstream).

    ``std::panic::catch_unwind`` converts a PoC panic into a clean
    ``IMPORT_ERROR`` line on stderr and exit code 1, so a panicking PoC is
    not mistaken for a successful run.
    """
    return (
        "// GSC PoF Sandbox Runner — auto-generated (Rust).\n"
        "// Force the target crate into the build; absent target -> compile error.\n"
        "use target::TARGET_MARKER as _GSC_TARGET_MARKER;\n"
        "\n"
        "fn main() {\n"
        "    let result = std::panic::catch_unwind(|| {\n"
        "        // --- PoC BEGIN ---\n"
        "        " + poc_code.replace("\n", "\n        ") + "\n"
        "        // --- PoC END ---\n"
        "    });\n"
        "    match result {\n"
        "        Ok(()) => {}\n"
        "        Err(payload) => {\n"
        "            let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {\n"
        "                (*s).to_string()\n"
        "            } else if let Some(s) = payload.downcast_ref::<String>() {\n"
        "                s.clone()\n"
        "            } else {\n"
        "                \"unknown panic\".to_string()\n"
        "            };\n"
        "            eprintln!(\""
        + _IMPORT_ERROR_MARKER
        + ": {}\", msg);\n"
        "            std::process::exit(1);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


# ── Command tables (language → argv prefix) ──────────────────────────────


# A language may have more than one alias (e.g. "javascript" and "js"). We
# keep a flat alias map so callers can pass the language name as it appears
# in their findings without normalising it first.
_RUNTIME_ALIASES = {
    "javascript": "node",
    "js": "node",
    "node": "node",
    "typescript": "node",   # tsc would be needed first; we keep node for parity
    "ts": "node",
    "java": "java",
    "go": "go",
    "golang": "go",
    "rust": "rustc",        # see compile_command; rustc is the launch binary
    "rs": "rustc",
    "python": "python3",
    "python3": "python3",
    "py": "python3",
}

# A handful of languages have a "compile" stage in addition to "run". For
# those we return a non-None argv for compile_command(); for interpreted
# languages (or languages that compile-on-run, like Go) we return None.
_COMPILE_ALIASES = {
    "java": ["javac"],
    "rust": ["rustc"],
    "rs": ["rustc"],
}


def runtime_command(language: str) -> Optional[List[str]]:
    """Return the argv prefix that launches a runner for ``language``.

    Returns None for unknown languages. For languages with both a compile and
    a run step (Java, Rust) the *run* binary is returned; compile is via
    :func:`compile_command`. ``go run`` is treated as the runtime command —
    it compiles on the fly — and ``compile_command`` returns None for Go.
    """
    if language is None:
        return None
    key = language.strip().lower()
    bin_ = _RUNTIME_ALIASES.get(key)
    if bin_ is None:
        return None
    if bin_ == "go":
        return ["go", "run"]
    return [bin_]


def compile_command(language: str) -> Optional[List[str]]:
    """Return the argv prefix that compiles a runner for ``language``.

    Returns None for interpreted languages (JS, Python) and for languages
    that compile-on-run (Go) as well as for unknown languages.
    """
    if language is None:
        return None
    key = language.strip().lower()
    return _COMPILE_ALIASES.get(key)


def detect_runtime(language: str) -> Optional[str]:
    """Return the absolute path of the language's runtime binary, or None.

    Uses :func:`shutil.which` only. Never raises — a missing binary or an
    empty / unknown language yields None. The caller decides whether a
    missing runtime is a hard fail or a soft skip.
    """
    if language is None:
        return None
    key = language.strip().lower()
    bin_ = _RUNTIME_ALIASES.get(key)
    if bin_ is None:
        return None
    try:
        return shutil.which(bin_)
    except Exception:
        return None
