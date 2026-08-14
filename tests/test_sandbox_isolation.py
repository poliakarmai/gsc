# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""tests/test_sandbox_isolation.py — GSC-002: PoC execution isolation.

The sandbox must (1) detect a container runtime, (2) label every result with
the isolation level actually used, and (3) deny egress when a container is
present. Non-web PoCs must never silently run without isolation.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from gsc_pof_sandbox import (
    PoFSandbox,
    SANDBOX_ROOT,
    _isolation_backend,
    _run_isolated,
)


def test_isolation_backend_label():
    assert _isolation_backend() in ("docker", "podman", "rlimit")


def test_is_container_isolation_helper():
    from gsc_pof_sandbox import _is_container_isolation
    assert _is_container_isolation("docker") is True
    assert _is_container_isolation("podman") is True
    assert _is_container_isolation("rlimit") is False
    assert _is_container_isolation("") is False
    assert _is_container_isolation("timeout") is False


def test_python_poc_reports_isolation():
    sb = PoFSandbox()
    r = sb._execute('print("EXPLOITED")', "x = 1\n", fmt="python")
    assert r.success is True
    assert r.isolation, "isolation level must be recorded"


def test_shell_poc_reports_isolation():
    sb = PoFSandbox()
    r = sb._execute("echo VULNERABLE", "", fmt="curl")
    assert r.success is True
    assert r.isolation, "isolation level must be recorded"


@pytest.mark.skipif(
    _isolation_backend() == "rlimit",
    reason="no container runtime available — egress isolation not testable",
)
def test_container_egress_denied():
    # A curl to a public IP must fail inside the sandbox (network=none).
    sb = PoFSandbox()
    r = sb._execute(
        "curl -s -m 2 http://1.1.1.1 >/dev/null 2>&1 && echo NET_OPEN || echo NET_DENIED",
        "", fmt="curl",
    )
    assert "NET_DENIED" in r.stdout, f"egress not denied: stdout={r.stdout!r}"


@pytest.mark.skipif(
    _isolation_backend() == "rlimit",
    reason="no container runtime available",
)
def test_container_runs_via_backend():
    wd = SANDBOX_ROOT / f"iso_{int(time.time())}"
    wd.mkdir(parents=True, exist_ok=True)
    try:
        proc, iso = _run_isolated(["python3", "-c", "print('EXPLOITED')"], str(wd))
        assert proc is not None, "container run returned None (unexpected fallback)"
        assert iso in ("docker", "podman")
        assert "EXPLOITED" in proc.stdout
    finally:
        import shutil
        shutil.rmtree(wd, ignore_errors=True)


@pytest.mark.skipif(
    _isolation_backend() != "rlimit",
    reason="container runtime present — fail-closed path not exercised",
)
def test_verify_fix_fail_closed_without_container():
    """GSC-001: без docker/podman verify_fix НЕ должен давать verified=True.

    rlimit-fallback — деградация, а не доказательство; «verified» резервируется
    за OS-isolated выполнением (docker/podman)."""
    sb = PoFSandbox()
    vuln = "def f(x):\n    return eval(x)\n"
    patched = "def f(x):\n    return x\n"
    poc = "assert target.f('1+1') == 2\nprint('EXPLOITED')\n"
    v = sb.verify_fix(vuln, patched, poc)
    assert v.verified is False, f"fail-closed violated: reason={v.reason!r}"
    assert "container runtime" in v.reason
