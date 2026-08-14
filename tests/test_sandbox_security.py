"""tests/test_sandbox_security.py — GSC roadmap 3.10: sandbox escape tests.

Проверяем, что hostile PoC внутри контейнера НЕ может:
  - писать вне смонтированного workspace (rootfs read-only + non-root);
  - открывать сетевые соединения (--network none);
  - читать host-файлы за пределами workspace.

Тесты требуют container runtime (docker/podman); при rlimit — skip, т.к.
rlimit не является security boundary (это честно зафиксировано в threat model).
"""
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from gsc_pof_sandbox import SANDBOX_ROOT, _isolation_backend, _run_isolated

pytestmark = pytest.mark.sandbox


def _run_escape(code: str):
    wd = SANDBOX_ROOT / f"sec_{int(time.time() * 1000)}"
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "escape.py").write_text(code)
    try:
        return _run_isolated(["python3", "escape.py"], str(wd))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


@pytest.mark.skipif(_isolation_backend() == "rlimit", reason="no container runtime")
def test_poc_cannot_write_outside_workspace():
    code = ("try:\n"
            "    open('/etc/gsc_pwned', 'w').write('pwned')\n"
            "    print('WROTE_OUTSIDE')\n"
            "except Exception:\n"
            "    print('BLOCKED')\n")
    proc, iso = _run_escape(code)
    assert proc is not None and iso in ("docker", "podman")
    assert "WROTE_OUTSIDE" not in proc.stdout, f"escape! stdout={proc.stdout}"


@pytest.mark.skipif(_isolation_backend() == "rlimit", reason="no container runtime")
def test_poc_cannot_open_socket():
    code = ("import socket\n"
            "try:\n"
            "    s = socket.socket(); s.settimeout(2)\n"
            "    s.connect(('8.8.8.8', 53))\n"
            "    print('SOCKET_OPEN')\n"
            "except Exception:\n"
            "    print('BLOCKED')\n")
    proc, iso = _run_escape(code)
    assert proc is not None and iso in ("docker", "podman")
    assert "SOCKET_OPEN" not in proc.stdout, f"escape! stdout={proc.stdout}"


@pytest.mark.skipif(_isolation_backend() == "rlimit", reason="no container runtime")
def test_poc_cannot_read_host_etc():
    # В контейнере /etc/passwd — это контейнерный (не host). Проверяем, что
    # PoC не может достучаться до host-данных: записываем маркер host-side и
    # проверяем, что в контейнере его нет (изолированная rootfs).
    marker = f"/tmp/gsc_host_marker_{int(time.time())}"
    Path(marker).write_text("HOST_SECRET")
    try:
        code = (f"import os\n"
                f"print('HOST_SECRET_VISIBLE' if os.path.exists({marker!r}) else 'ISOLATED')\n")
        proc, iso = _run_escape(code)
        assert proc is not None and iso in ("docker", "podman")
        assert "HOST_SECRET_VISIBLE" not in proc.stdout, f"host fs visible! stdout={proc.stdout}"
    finally:
        Path(marker).unlink(missing_ok=True)
