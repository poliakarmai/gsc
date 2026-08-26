# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""DD-05 (fail-fast container isolation) + DD-03 (reconcile onepager) coverage."""

import subprocess
import sys
from pathlib import Path

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))


def test_warn_no_container_isolation_warns_on_rlimit(monkeypatch):
    import gsc_pof_sandbox as sandbox
    from gsc_proofoffix import _warn_no_container_isolation
    monkeypatch.setattr(sandbox, "_isolation_backend", lambda: "rlimit")
    warn = _warn_no_container_isolation()
    assert warn and "docker" in warn and "podman" in warn


def test_warn_no_container_isolation_none_with_docker(monkeypatch):
    import gsc_pof_sandbox as sandbox
    from gsc_proofoffix import _warn_no_container_isolation
    monkeypatch.setattr(sandbox, "_isolation_backend", lambda: "docker")
    assert _warn_no_container_isolation() is None


def test_reconcile_reports_onepager_sync():
    # DD-03: after fixing onepager numbers, reconcile must exit 0 (ALL MATCH).
    r = subprocess.run(
        [sys.executable, str(GSC / "scripts" / "gsc_reconcile.py")],
        capture_output=True, text=True, timeout=90,
    )
    assert r.returncode == 0, (r.stdout or "") + (r.stderr or "")
