"""Tests for gsc_runtime_validator — IAST-lite Phase 1 (in-process instrumentation).

Детерминированные, без eBPF/--privileged. e2e-тест поднимает реальный venv,
устанавливает sitecustomize и проверяет, что open/subprocess/socket логируются.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_runtime_validator import (
    RuntimeEvent,
    RuntimeValidator,
    SITECUSTOMIZE_TEMPLATE,
    _address_host,
    _parse_strace_line,
    strace_validate,
)


# ── unit: модель и классификация ─────────────────────────────────────────────

def _ev(category, **kw):
    return RuntimeEvent(category=category, ts=0.0, **kw)


def test_classify_three_categories():
    events = [
        _ev("file_open", path="/etc/passwd", mode="w"),
        _ev("process_exec", argv=["bash", "-c", "id"]),
        _ev("network_connect", address=("93.184.216.34", 80)),
    ]
    cats = RuntimeValidator.classify(events)
    assert len(cats["file_write"]) == 1
    assert len(cats["process_exec"]) == 1
    assert len(cats["network_connect"]) == 1
    assert len(cats["other"]) == 0


def test_classify_localhost_connect_is_other():
    events = [_ev("network_connect", address=("127.0.0.1", 8080))]
    cats = RuntimeValidator.classify(events)
    assert cats["network_connect"] == []
    assert len(cats["other"]) == 1


def test_classify_read_open_is_other():
    events = [_ev("file_open", path="/tmp/x.py", mode="r")]
    cats = RuntimeValidator.classify(events)
    assert cats["file_write"] == []
    assert len(cats["other"]) == 1


def test_dangerous_events_filters_workdir():
    workdir = "/tmp/gsc_run_123"
    events = [
        _ev("file_open", path=f"{workdir}/serve.py", mode="w"),   # служебная запись
        _ev("file_open", path="/etc/cron.d/x", mode="w"),          # опасная запись
        _ev("file_open", path="/tmp/out.txt", mode="a"),           # опасная запись
    ]
    dangerous = RuntimeValidator.dangerous_events(events, workdir=workdir)
    paths = [e.path for e in dangerous]
    assert f"{workdir}/serve.py" not in paths
    assert "/etc/cron.d/x" in paths
    assert "/tmp/out.txt" in paths


def test_read_log_missing_file():
    assert RuntimeValidator.read_log("/nonexistent/events.jsonl") == []


def test_read_log_skips_malformed(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_text('{"category":"process_exec","argv":["id"]}\nNOT_JSON\n')
    events = RuntimeValidator.read_log(log)
    assert len(events) == 1
    assert events[0].category == "process_exec"


# ── e2e: реальная инструментация в venv ──────────────────────────────────────

@pytest.fixture(scope="module")
def instrumented_venv(tmp_path_factory):
    root = tmp_path_factory.mktemp("runtime_validator")
    venv_dir = root / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    rv = RuntimeValidator(venv_dir)
    hook_dir = rv.install()
    assert hook_dir.exists()
    return venv_dir, hook_dir


def test_install_writes_sitecustomize(instrumented_venv):
    _, hook_dir = instrumented_venv
    assert (hook_dir / "sitecustomize.py").exists()
    assert "GSC_RUNTIME_LOG" in (hook_dir / "sitecustomize.py").read_text()


def test_e2e_logs_open_subprocess_socket(instrumented_venv, tmp_path):
    venv_dir, hook_dir = instrumented_venv
    log = tmp_path / "events.jsonl"
    poc = tmp_path / "poc.py"
    poc.write_text(textwrap.dedent("""
        import subprocess, socket
        open("written.txt", "w").write("pwned")
        subprocess.Popen(["echo", "hello"])
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect(("127.0.0.1", 1))  # мгновенный ECONNREFUSED
        except Exception:
            pass
    """))
    py = str(venv_dir / "bin" / "python3")
    env = dict(os.environ)
    env.update(RuntimeValidator.runtime_env(log, finding_key="abc123", hook_dir=hook_dir))
    r = subprocess.run([py, str(poc)], env=env, capture_output=True, text=True,
                       cwd=str(tmp_path), timeout=60)
    assert r.returncode == 0, f"stderr={r.stderr}"

    events = RuntimeValidator.read_log(log)
    assert events, "нет событий в логе"
    assert all(e.finding_key == "abc123" for e in events), "finding_key не привязан"

    cats = RuntimeValidator.classify(events)
    assert cats["file_write"], "нет file_write (open w)"
    assert cats["process_exec"], "нет process_exec (Popen)"
    # network_connect логируется как сырое событие (classify отфильтровывает localhost)
    assert any(e.category == "network_connect" for e in events), "нет network_connect в логе"


# ── Phase 2: strace ──────────────────────────────────────────────────────────

def test_parse_strace_line_execve():
    ev = _parse_strace_line('12345 execve("/bin/sh", ["sh", "-c", "id"], 0x7fff) = 0')
    assert ev is not None and ev.category == "process_exec"
    assert ev.argv == ["sh", "-c", "id"]


def test_parse_strace_line_open_write():
    ev = _parse_strace_line('12345 openat(AT_FDCWD, "/etc/passwd", O_WRONLY|O_CREAT) = 3')
    assert ev is not None and ev.category == "file_open"
    assert ev.mode == "w" and ev.path == "/etc/passwd"


def test_parse_strace_line_open_read():
    ev = _parse_strace_line('12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3')
    assert ev is not None and ev.mode == "r"


def test_parse_strace_line_connect():
    ev = _parse_strace_line(
        '12345 connect(3, {sa_family=AF_INET, sin_port=htons(80), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = 0'
    )
    assert ev is not None and ev.category == "network_connect"
    assert _address_host(ev.address) == "93.184.216.34"


def test_parse_strace_line_garbage():
    assert _parse_strace_line("+++ exited with 0 +++") is None


def test_strace_validate_e2e(tmp_path):
    import shutil
    if not shutil.which("strace"):
        pytest.skip("strace отсутствует")
    target = tmp_path / "out.txt"
    events = strace_validate(["sh", "-c", f"echo hi > {target}"], workdir=str(tmp_path))
    cats = RuntimeValidator.classify(events)
    assert cats["process_exec"], "нет execve под strace"
    assert cats["file_write"], "нет openat write под strace"
