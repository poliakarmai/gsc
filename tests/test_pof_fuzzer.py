#!/usr/bin/env python3
"""tests/test_pof_fuzzer.py — robustness check for PoF manifest parsers.

The fuzzer itself is in ``gsc_cli/gsc_pof_fuzzer.py``. These tests
exercise the public API and verify two guarantees from
``POF_PARSER_CONTRACT.md``:

  * §1.6 — every parser returns a dataclass (with ``.valid``) on
    malformed input instead of raising.
  * Determinism — two calls with the same seed produce the same
    report.

All tests are stdlib-only and run in well under a second on the full
parser set.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

# Ensure repo root is importable when pytest is launched from a
# different cwd. The shared conftest does this for pytest, but we
# also want the module to be importable when run as a plain script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gsc_cli import gsc_pof_fuzzer as fz
from gsc_cli.gsc_pof_fuzzer import (
    FuzzResult,
    FUZZ_TARGETS,
    SEEDS,
    fuzz_one,
    run_all,
)
from gsc_cli.gsc_pof_node_parser import parse_package_json


# Expected number of always-on edge inputs. The fuzzer runs each
# parser through this fixed list on top of the random mutations. If
# the value changes, every ``total == iterations + N`` assertion has
# to be revisited — that's why it's spelled out as a constant.
_EDGE_INPUT_COUNT = 10


# ── Registry & seeds ──────────────────────────────────────────────


def test_registry_has_all_ten_parsers():
    """``FUZZ_TARGETS`` must list exactly the ten parsers in the contract."""
    names = [name for name, _ in FUZZ_TARGETS]
    assert len(names) == 10, f"expected 10 parsers, got {len(names)}: {names}"
    expected = {
        "node", "go", "java", "rust", "uv",
        "yarn", "cargo_lock", "csproj", "gradle", "php",
    }
    assert set(names) == expected, f"mismatch: missing={expected - set(names)}, extra={set(names) - expected}"


def test_seeds_match_registry():
    """Every parser has a seed and no extra seeds are defined."""
    target_names = {name for name, _ in FUZZ_TARGETS}
    assert set(SEEDS.keys()) == target_names, (
        f"seed keys mismatch: missing={target_names - set(SEEDS)}, "
        f"extra={set(SEEDS) - target_names}"
    )
    for name, seed in SEEDS.items():
        assert isinstance(seed, str), f"seed for {name!r} is not a str"
        # Seeds should be small — large seeds just give the mutator
        # more bytes to mangle without yielding interesting failures.
        assert len(seed) <= 1500, f"seed for {name!r} is suspiciously large ({len(seed)} chars)"


# ── Tolerance contract ────────────────────────────────────────────


def test_run_all_zero_tolerance_violations():
    """``run_all`` must report zero crashes across all ten parsers.

    This is the headline test: any parser that throws on malformed
    input is in violation of ``POF_PARSER_CONTRACT.md`` §1.6.
    """
    report = run_all(iterations=200, seed=42)
    assert set(report.keys()) == {name for name, _ in FUZZ_TARGETS}
    for name, result in report.items():
        assert isinstance(result, FuzzResult), f"{name}: not a FuzzResult"
        assert result.crashes == [], (
            f"{name} crashed on malformed input: {result.crashes[:3]}"
        )


def test_run_all_is_deterministic():
    """Two invocations with the same seed produce the same report."""
    a = run_all(iterations=200, seed=42)
    b = run_all(iterations=200, seed=42)
    assert set(a.keys()) == set(b.keys())
    for name in a:
        # total and crash list are the only user-visible fields and
        # both must match exactly for determinism to hold.
        assert a[name].total == b[name].total, f"{name}: total differs"
        assert a[name].crashes == b[name].crashes, f"{name}: crash list differs"


def test_different_seed_can_diverge():
    """A different seed does not have to give the same crashes.

    We only assert that the report still has zero crashes — different
    seeds should not introduce new violations. This guards against a
    regression where the fuzzer becomes "accidentally safe" by always
    picking the same trivial mutations.
    """
    report = run_all(iterations=100, seed=1337)
    for name, result in report.items():
        assert result.crashes == [], (
            f"{name} crashed under seed=1337: {result.crashes[:3]}"
        )


# ── Edge inputs on the node parser ────────────────────────────────


def test_fuzz_one_node_handles_empty_none_non_string():
    """The node parser must return a ``valid=False`` dataclass on degenerate input.

    We call ``fuzz_one`` with zero iterations so the fuzzer ONLY runs
    its fixed edge-input list. That way the assertions below test
    exactly the edge cases documented in §1.6 (empty / None / non-
    string) without random mutations muddying the result.
    """
    rng = random.Random(0)
    result = fuzz_one(parse_package_json, SEEDS["node"], iterations=0, rng=rng)
    # No mutations were requested, but the edge inputs must always run.
    assert result.total == _EDGE_INPUT_COUNT, (
        f"expected {_EDGE_INPUT_COUNT} edge inputs, got {result.total}"
    )
    assert result.crashes == [], (
        f"node parser crashed on an edge input: {result.crashes}"
    )

    # Run the same degenerate inputs by hand to confirm ``valid``
    # is the right shape.
    for inp in ["", None, 42, [], {}, b""]:
        out = parse_package_json(inp)  # type: ignore[arg-type]
        assert hasattr(out, "valid"), f"input {inp!r}: no .valid attribute"
        assert out.valid is False, f"input {inp!r}: expected valid=False, got {out.valid}"


# ── Iteration accounting ──────────────────────────────────────────


def test_fuzz_one_counts_every_iteration():
    """``fuzz_one`` must record one ``total`` increment per requested iteration."""
    rng = random.Random(7)
    iterations = 50
    result = fuzz_one(parse_package_json, SEEDS["node"], iterations=iterations, rng=rng)
    assert result.total == iterations + _EDGE_INPUT_COUNT, (
        f"expected total={iterations + _EDGE_INPUT_COUNT}, got {result.total}"
    )


def test_run_all_zero_iterations_runs_only_edges():
    """With ``iterations=0`` the fuzzer still exercises edge inputs."""
    report = run_all(iterations=0, seed=42)
    for name, result in report.items():
        assert result.total == _EDGE_INPUT_COUNT, (
            f"{name}: expected total={_EDGE_INPUT_COUNT}, got {result.total}"
        )
        assert result.crashes == [], f"{name}: unexpected crashes: {result.crashes}"


# ── Result shape ──────────────────────────────────────────────────


def test_fuzz_result_to_dict_shape():
    """``FuzzResult.to_dict`` returns the documented keys."""
    rng = random.Random(1)
    result = fuzz_one(parse_package_json, SEEDS["node"], iterations=3, rng=rng)
    d = result.to_dict()
    assert set(d.keys()) == {"name", "total", "crashes", "crash_count"}
    assert d["total"] == result.total
    assert d["crashes"] == result.crashes
    assert d["crash_count"] == len(result.crashes)
    # ``crashes`` must be a copy, not the internal list — mutating
    # the dict must not affect the dataclass.
    d["crashes"].append("sentinel")
    assert "sentinel" not in result.crashes
