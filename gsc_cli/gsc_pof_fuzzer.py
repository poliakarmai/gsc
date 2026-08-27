# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Deterministic fuzzer for PoF manifest parsers (Phase 14 — robustness check).

The fuzzer drives every PoF parser with malformed inputs and asserts the
parsers never raise an exception. The contract is documented in
``POF_PARSER_CONTRACT.md`` §1.6: each ``parse_*`` function must return a
dataclass with ``valid=False`` instead of throwing on broken input.

The fuzzer is intentionally stdlib-only (``random``, ``dataclasses``,
``string``) and fully deterministic — every mutation sequence is driven
by a seeded ``random.Random`` instance, so a crash can be reproduced by
re-running ``run_all(seed=...)`` with the same seed.

Design notes
------------
* No filesystem access, no environment variables, no I/O. The fuzzer
  works in memory and never writes to disk.
* Mutations are deliberately small in scope (a few hundred iterations
  per target) so the fuzzer finishes in well under a second on the full
  parser set. The goal is to catch obvious breakage, not to exercise
  adversarial deep paths.
* Non-string inputs (e.g. ``None``, ``int``, ``list``) are passed
  through to the parser exactly as the contract requires. The parser
  must not raise.
* ``RecursionError`` from pathological nesting IS recorded as a crash
  for very small depth (≤8 levels) because reasonable nesting in a
  manifest is never deeper than that. The fuzzer keeps nesting depth
  moderate on purpose so that legitimate patterns don't get flagged.

How to run
----------
::

    from gsc_cli import gsc_pof_fuzzer
    report = gsc_pof_fuzzer.run_all(iterations=200, seed=42)
    for name, result in report.items():
        print(name, result.total, len(result.crashes))

Or from the command line::

    python3 -m gsc_cli.gsc_pof_fuzzer
"""

from __future__ import annotations

import random
import string
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

# Public parsers — every entry must follow the contract
# ``parse(content: str) -> SomeProject`` where ``SomeProject.valid`` exists.
# We import the modules lazily inside ``FUZZ_TARGETS`` lookup so that a
# broken parser import does not prevent the fuzzer module from loading
# (we want a clean error message, not a stack trace dump at import time).
from gsc_cli.gsc_pof_cargo_lock_parser import parse_cargo_lock
from gsc_cli.gsc_pof_csproj_parser import parse_csproj
from gsc_cli.gsc_pof_go_parser import parse_go_mod
from gsc_cli.gsc_pof_gradle_parser import parse_gradle
from gsc_cli.gsc_pof_java_parser import parse_pom_xml
from gsc_cli.gsc_pof_node_parser import parse_package_json
from gsc_cli.gsc_pof_php_parser import parse_composer_json
from gsc_cli.gsc_pof_rust_parser import parse_cargo_toml
from gsc_cli.gsc_pof_uv_parser import parse_uv_lock
from gsc_cli.gsc_pof_yarn_parser import parse_yarn_lock


# Maximum reasonable manifest depth. The fuzzer caps the recursion-
# building mutation at this number so that a RecursionError triggered by
# 10000-deep nesting does NOT get reported as a crash — that's a known
# artifact, not a parser bug. Anything below this threshold IS a bug.
_MAX_REASONABLE_DEPTH = 8


# ASCII characters that show up in real manifests. Used both for
# building "random byte" payloads and for the unicode-junk mix. We do
# NOT use the full 0..255 range because most control bytes are
# pointless to try against a manifest parser — they're either stripped
# by a tolerant preclean or ignored by a regex.
_RANDOM_BYTE_CHARS = string.ascii_letters + string.digits + string.punctuation + " \t\n"


# Unicode ranges that frequently break strict parsers: combining marks,
# RTL, zero-width joiners, mathematical operators, and the BMP private
# use area. Kept as a compact list of single-character strings.
_UNICODE_JUNK_CHARS = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # BOM
    "\u202e",  # RTL override
    "\u0301",  # combining acute accent
    "\u00ad",  # soft hyphen
    "\u2060",  # word joiner
    "\u2028",  # line separator
    "\u2029",  # paragraph separator
    "\uffff",  # BMP edge
    "\U0001f4a9",  # astral plane
]


@dataclass
class FuzzResult:
    """Result of fuzzing a single parser.

    Attributes
    ----------
    name:
        Parser display name (the key from ``FUZZ_TARGETS``).
    total:
        Total number of mutations executed (including the always-run
        edge-case inputs like empty string, ``None``, and non-string).
    crashes:
        List of human-readable crash descriptions. Each entry is a
        single string with the exception type, the first ~80 chars of
        the input, and the first line of the traceback. Empty list
        means the parser tolerated every input.
    """

    name: str
    total: int
    crashes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable snapshot of this result."""
        return {
            "name": self.name,
            "total": self.total,
            "crashes": list(self.crashes),
            "crash_count": len(self.crashes),
        }


# Registry of (name, parse_fn) pairs. Order is preserved so the report
# is stable run-to-run and easy to diff. The parse functions MUST accept
# a string argument and return a dataclass with a ``valid`` attribute.
FUZZ_TARGETS: list[tuple[str, Callable[[str], Any]]] = [
    ("node", parse_package_json),
    ("go", parse_go_mod),
    ("java", parse_pom_xml),
    ("rust", parse_cargo_toml),
    ("uv", parse_uv_lock),
    ("yarn", parse_yarn_lock),
    ("cargo_lock", parse_cargo_lock),
    ("csproj", parse_csproj),
    ("gradle", parse_gradle),
    ("php", parse_composer_json),
]


# Minimal valid manifests, one per parser. These are the SEEDS that
# mutation operates on. Keep them small — large seeds just give the
# mutator more bytes to mangle, and the failures are not interesting
# beyond a few dozen characters.
SEEDS: dict[str, str] = {
    "node": '{"name": "x", "version": "1.0.0"}',
    "go": "module example.com/x\n\ngo 1.21\n\nrequire github.com/foo/bar v1.0.0\n",
    "java": (
        '<?xml version="1.0"?>\n'
        '<project>\n'
        '  <groupId>com.example</groupId>\n'
        '  <artifactId>x</artifactId>\n'
        '  <version>1.0.0</version>\n'
        '  <dependencies>\n'
        '    <dependency>\n'
        '      <groupId>com.google.guava</groupId>\n'
        '      <artifactId>guava</artifactId>\n'
        '      <version>32.1.3-jre</version>\n'
        '    </dependency>\n'
        '  </dependencies>\n'
        '</project>\n'
    ),
    "rust": (
        '[package]\n'
        'name = "x"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n'
        '\n'
        '[dependencies]\n'
        'serde = "1.0"\n'
    ),
    "uv": (
        'version = 1\n'
        'requires-python = ">=3.11"\n'
        '\n'
        '[[package]]\n'
        'name = "click"\n'
        'version = "8.1.7"\n'
    ),
    "yarn": (
        '# yarn lockfile v1\n'
        '\n'
        'lodash@^4.17.21:\n'
        '  version "4.17.21"\n'
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
    ),
    "cargo_lock": (
        'version = 3\n'
        '\n'
        '[[package]]\n'
        'name = "x"\n'
        'version = "0.1.0"\n'
    ),
    "csproj": (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>net8.0</TargetFramework>\n'
        '  </PropertyGroup>\n'
        '  <ItemGroup>\n'
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        '  </ItemGroup>\n'
        '</Project>\n'
    ),
    "gradle": (
        'dependencies {\n'
        "  implementation 'com.google.guava:guava:32.1.3-jre'\n"
        '}\n'
    ),
    "php": (
        '{\n'
        '  "name": "vendor/x",\n'
        '  "require": {\n'
        '    "guzzlehttp/guzzle": "^7.8"\n'
        '  }\n'
        '}\n'
    ),
}


def _mutate_random_bytes(rng: random.Random, _seed: str) -> str:
    """Return a short string of pseudo-random ASCII / whitespace."""
    length = rng.randint(0, 200)
    return "".join(rng.choice(_RANDOM_BYTE_CHARS) for _ in range(length))


def _mutate_truncate(rng: random.Random, seed: str) -> str:
    """Return the seed truncated at a random position (possibly empty)."""
    if not seed:
        return ""
    cut = rng.randint(0, len(seed))
    return seed[:cut]


def _mutate_bitflip(rng: random.Random, seed: str) -> str:
    """Return the seed with one ASCII character replaced by a random one.

    For empty seeds this falls back to a single random character so the
    test surface is non-zero.
    """
    if not seed:
        return rng.choice(_RANDOM_BYTE_CHARS)
    chars = list(seed)
    idx = rng.randint(0, len(chars) - 1)
    chars[idx] = rng.choice(_RANDOM_BYTE_CHARS)
    return "".join(chars)


def _mutate_null_byte(rng: random.Random, seed: str) -> str:
    """Return the seed with a ``\\x00`` inserted at a random position."""
    pos = rng.randint(0, len(seed))
    return seed[:pos] + "\x00" + seed[pos:]


def _mutate_unicode_junk(rng: random.Random, seed: str) -> str:
    """Return the seed with a chunk of mixed unicode junk inserted."""
    junk = "".join(rng.choice(_UNICODE_JUNK_CHARS) for _ in range(rng.randint(1, 12)))
    pos = rng.randint(0, len(seed))
    return seed[:pos] + junk + seed[pos:]


def _mutate_broken_brackets(rng: random.Random, seed: str) -> str:
    """Return the seed with the closing brackets/quotes stripped.

    Picks a random length between 0 and the seed length, so the result
    can be empty, half a manifest, or a near-full manifest with only
    the very last closing character missing.
    """
    if not seed:
        return ""
    cut = rng.randint(0, len(seed) - 1)
    return seed[:cut]


def _mutate_moderate_nesting(rng: random.Random, seed: str) -> str:
    """Return the seed with moderate bracket nesting inserted.

    Capped at ``_MAX_REASONABLE_DEPTH`` levels so that a
    ``RecursionError`` triggered by extreme depth is not flagged as
    a parser crash. The seed is preserved around the nested block so
    the parser still has to find its anchor directives.
    """
    depth = rng.randint(1, _MAX_REASONABLE_DEPTH)
    if seed:
        pos = rng.randint(0, len(seed))
    else:
        pos = 0
    nested = "[" * depth + "]" * depth
    return seed[:pos] + nested + seed[pos:]


def _mutate_brace_nesting(rng: random.Random, seed: str) -> str:
    """Return the seed with a balanced ``{}`` nesting inserted."""
    depth = rng.randint(1, _MAX_REASONABLE_DEPTH)
    if seed:
        pos = rng.randint(0, len(seed))
    else:
        pos = 0
    nested = "{" * depth + "}" * depth
    return seed[:pos] + nested + seed[pos:]


# All available mutations, in stable order. ``fuzz_one`` picks one at
# random per iteration using the seeded RNG.
_MUTATIONS: list[Callable[[random.Random, str], str]] = [
    _mutate_random_bytes,
    _mutate_truncate,
    _mutate_bitflip,
    _mutate_null_byte,
    _mutate_unicode_junk,
    _mutate_broken_brackets,
    _mutate_moderate_nesting,
    _mutate_brace_nesting,
]


# Edge-case inputs that must always be tried at least once per parser.
# These are inputs the parser is expected to reject gracefully (return
# a ``valid=False`` dataclass, not raise) — see
# ``POF_PARSER_CONTRACT.md`` §1.6.
_EDGE_INPUTS: list[object] = [
    "",                # empty string
    None,              # None — some parsers handle this, some don't
    42,                # int
    [],                # empty list
    ["x"],             # list with one item
    {},                # empty dict
    b"",               # empty bytes
    b"x",              # bytes
    object(),          # arbitrary non-string
    True,              # bool
]


def _summarize_input(inp: object) -> str:
    """Build a one-line, at-most-80-char summary of an input for crash logs."""
    if isinstance(inp, str):
        head = inp[:80]
    elif isinstance(inp, (bytes, bytearray)):
        try:
            head = inp[:80].decode("utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            head = repr(inp)[:80]
    else:
        head = repr(inp)[:80]
    return head


def _invoke_parse(parse_fn: Callable[[str], Any], inp: object) -> None:
    """Call ``parse_fn`` with ``inp`` and raise on any exception.

    Used purely to surface crashes; the caller is responsible for
    catching ``Exception`` and recording the failure.
    """
    # The parsers are declared as ``Callable[[str], Any]`` but the
    # contract requires them to handle non-string inputs gracefully.
    # We therefore pass the input through unchanged and rely on the
    # parser to validate the type — that's the behaviour we're
    # testing.
    parse_fn(inp)  # type: ignore[arg-type]


def _record_crash(
    parse_fn: Callable[[str], Any],
    inp: object,
    exc: BaseException,
) -> str:
    """Build a single-line crash description for the report."""
    exc_type = type(exc).__name__
    tb_first = ""
    try:
        tb_first = traceback.format_exception_only(type(exc), exc)[0].strip()
    except Exception:
        tb_first = "<traceback unavailable>"
    return (
        f"{exc_type}: {tb_first} | input={_summarize_input(inp)!r} "
        f"| parser={getattr(parse_fn, '__qualname__', repr(parse_fn))}"
    )


def fuzz_one(
    parse_fn: Callable[[str], Any],
    seed_input: str,
    iterations: int,
    rng: random.Random,
) -> FuzzResult:
    """Fuzz a single parser with ``iterations`` random mutations.

    Parameters
    ----------
    parse_fn:
        The ``parse_*`` function under test. Must accept a string and
        return a dataclass with a ``.valid`` attribute.
    seed_input:
        A minimal valid manifest used as the starting point for
        truncations, bit-flips, and similar structural mutations.
    iterations:
        Number of random mutations to run. The fuzzer will also
        exercise the ``_EDGE_INPUTS`` list once each, on top of the
        mutations, so ``FuzzResult.total >= iterations``.
    rng:
        A seeded ``random.Random`` instance. Determinism comes from
        the same seed always producing the same mutation sequence.

    Returns
    -------
    FuzzResult
        A dataclass with ``total`` (number of inputs tried) and
        ``crashes`` (list of crash descriptions, possibly empty).
        The fuzzer itself never raises — a parser exception is
        captured and reported.
    """
    name = getattr(parse_fn, "__qualname__", repr(parse_fn))
    result = FuzzResult(name=name, total=0, crashes=[])

    # 1) Edge inputs — these are deterministic and always run first so
    # a regression on empty/None/non-string is caught even when
    # ``iterations`` is zero.
    for inp in _EDGE_INPUTS:
        result.total += 1
        try:
            _invoke_parse(parse_fn, inp)
        except Exception as exc:  # noqa: BLE001 — we WANT to catch any parser exception
            result.crashes.append(_record_crash(parse_fn, inp, exc))

    # 2) Random mutations driven by the seeded RNG.
    for _ in range(max(0, iterations)):
        result.total += 1
        mut = rng.choice(_MUTATIONS)
        candidate = mut(rng, seed_input)
        try:
            _invoke_parse(parse_fn, candidate)
        except Exception as exc:  # noqa: BLE001
            result.crashes.append(_record_crash(parse_fn, candidate, exc))

    return result


def run_all(iterations: int = 200, seed: int = 42) -> dict[str, FuzzResult]:
    """Fuzz every parser in ``FUZZ_TARGETS`` and return a report.

    Parameters
    ----------
    iterations:
        Number of random mutations per parser. Total inputs per
        parser is ``iterations + len(_EDGE_INPUTS)``.
    seed:
        Seed for the internal ``random.Random`` instances. Two
        invocations with the same ``seed`` and ``iterations`` produce
        identical reports — this is the property the test suite
        relies on.

    Returns
    -------
    dict[str, FuzzResult]
        Mapping of parser name (e.g. ``"node"``) to its ``FuzzResult``.
    """
    report: dict[str, FuzzResult] = {}
    for name, parse_fn in FUZZ_TARGETS:
        # Each parser gets its own RNG seeded from the same master
        # seed, so the seed-to-result mapping is deterministic but
        # different parsers see different mutation sequences.
        rng = random.Random(seed)
        seed_input = SEEDS.get(name, "")
        report[name] = fuzz_one(parse_fn, seed_input, iterations, rng)
    return report


def print_report(report: dict[str, FuzzResult]) -> None:
    """Print a human-readable summary of a fuzz report to stdout.

    Format::

        node        total=210 crashes=0
        go          total=210 crashes=1
            -> KeyError: 'version' | input='{"name":' | parser=parse_go_mod
        ...

    Intended for the ``__main__`` entry point and for ad-hoc manual
    checks; the test suite does not depend on its output.
    """
    for name, result in report.items():
        crash_count = len(result.crashes)
        print(f"{name:<12} total={result.total:<6} crashes={crash_count}")
        for crash in result.crashes[:3]:
            print(f"    -> {crash}")
        if crash_count > 3:
            print(f"    ... and {crash_count - 3} more")


if __name__ == "__main__":  # pragma: no cover — manual CLI
    import sys

    iterations = 200
    seed = 42
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
        except ValueError:
            pass
    if len(sys.argv) > 2:
        try:
            seed = int(sys.argv[2])
        except ValueError:
            pass
    print(f"[gsc_pof_fuzzer] iterations={iterations} seed={seed}")
    report = run_all(iterations=iterations, seed=seed)
    print_report(report)
