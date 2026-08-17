#!/usr/bin/env python3
"""Runtime Exploit Validator — IAST-lite Phase 1 (in-process instrumentation).

Реализует вариант **D** из `docs/EXPERTISE_01_IAST_RUNTIME_VALIDATOR.md`:
оборачиваем `builtins.open`, `subprocess.Popen` и `socket.socket.connect` через
`sitecustomize.py` внутри sandbox-venv, логируем факт вызова с аргументами в JSONL.

Ключевые свойства (acceptance §6):
- Без eBPF / `--privileged` / CAP_BPF — изоляция F-05 не регрессирует.
- Чистый stdlib — sitecustomize не тянет внешних зависимостей.
- Событие привязано к `finding_key` (env `GSC_FINDING_KEY`).
- False-positive фильтр: file-write вне workdir, connect на внешний IP, execve —
  это сигналы эксплуатации; служебный I/O (serve.py, localhost) отсекается.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── sitecustomize.py (авто-устанавливается в venv; только stdlib) ───────────
SITECUSTOMIZE_TEMPLATE = r'''\
"""GSC runtime validator — IAST-lite Phase 1 (in-process instrumentation).

Monkeypatches open/subprocess/socket to log facts of dangerous calls.
Pure stdlib, best-effort: never fails the target process.
"""
import builtins
import json
import os
import socket
import subprocess
import threading
import time

_LOG = os.environ.get("GSC_RUNTIME_LOG")
_KEY = os.environ.get("GSC_FINDING_KEY", "")
_LOCK = threading.Lock()

# сохраняем originals ДО monkeypatch, чтобы логирование не рекурсировало
_orig_open = builtins.open
_orig_popen = subprocess.Popen
_orig_connect = socket.socket.connect

if _LOG:
    def _emit(category, **fields):
        rec = {"category": category, "ts": time.time(), "finding_key": _KEY}
        rec.update(fields)
        try:
            with _LOCK:
                with _orig_open(_LOG, "a") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass

    def _open(file, mode="r", *a, **kw):
        try:
            _emit("file_open", path=str(file), mode=str(mode))
        except Exception:
            pass
        return _orig_open(file, mode, *a, **kw)
    builtins.open = _open

    def _popen(args, *a, **kw):
        try:
            argv = args if isinstance(args, (list, tuple)) else [str(args)]
            _emit("process_exec", argv=[str(x) for x in argv])
        except Exception:
            pass
        return _orig_popen(args, *a, **kw)
    subprocess.Popen = _popen
    # subprocess.call/run/check_* идут через Popen — уже покрыто.

    def _connect(self, address, *a, **kw):
        try:
            _emit("network_connect", address=address)
        except Exception:
            pass
        return _orig_connect(self, address, *a, **kw)
    socket.socket.connect = _connect
'''


# ── Event model ──────────────────────────────────────────────────────────────

@dataclass
class RuntimeEvent:
    category: str
    ts: float
    finding_key: str = ""
    path: Optional[str] = None
    mode: Optional[str] = None
    argv: Optional[list] = None
    address: Optional[object] = None

    @classmethod
    def from_json(cls, line: str) -> "RuntimeEvent":
        d = json.loads(line)
        return cls(
            category=d.get("category", "unknown"),
            ts=float(d.get("ts", 0.0)),
            finding_key=d.get("finding_key", ""),
            path=d.get("path"),
            mode=d.get("mode"),
            argv=d.get("argv"),
            address=d.get("address"),
        )


# ── Validator ────────────────────────────────────────────────────────────────

DANGEROUS_FILE_MODES = re.compile(r"[wax+]")
LOCALHOST = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::ffff:127.0.0.1"}


def _address_host(address: object) -> str:
    if isinstance(address, (list, tuple)) and address:
        return str(address[0])
    return str(address)


class RuntimeValidator:
    """IAST-lite Phase 1: установка инструментации, чтение и классификация событий."""

    def __init__(self, venv_dir: Path):
        self.venv_dir = Path(venv_dir)

    # -- установка ------------------------------------------------------------
    def install(self) -> Path:
        """Записать sitecustomize.py в hook-каталог внутри venv. Возвращает каталог
        для добавления в PYTHONPATH — это обходит конфликт с системным
        sitecustomize.py (на хостах, где он есть, он грузится раньше venv'шного)."""
        hook_dir = self.venv_dir / "gsc_runtime_hook"
        hook_dir.mkdir(parents=True, exist_ok=True)
        dest = hook_dir / "sitecustomize.py"
        dest.write_text(SITECUSTOMIZE_TEMPLATE, encoding="utf-8")
        return hook_dir

    # -- env для дочернего PoC ------------------------------------------------
    @staticmethod
    def runtime_env(log_path: Path, finding_key: str = "",
                    hook_dir: Path | None = None) -> dict:
        """Env-переменные, включающие инструментацию в дочернем PoC.

        hook_dir добавляется в PYTHONPATH, чтобы наш sitecustomize.py загружался
        раньше системного (критично на хостах с системным sitecustomize.py).
        """
        import os
        env = {
            "GSC_RUNTIME_LOG": str(log_path),
            "GSC_FINDING_KEY": finding_key,
        }
        if hook_dir is not None:
            existing = os.environ.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                f"{hook_dir}{os.pathsep}{existing}" if existing else str(hook_dir)
            )
        return env

    # -- чтение / классификация -------------------------------------------------
    @staticmethod
    def read_log(log_path) -> list[RuntimeEvent]:
        log_path = Path(log_path)
        if not log_path.exists():
            return []
        events = []
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(RuntimeEvent.from_json(line))
            except Exception:
                continue
        return events

    @staticmethod
    def classify(events: list[RuntimeEvent]) -> dict[str, list[RuntimeEvent]]:
        """Разбить события на категории (acceptance §6.2: ≥3 категории)."""
        out: dict[str, list[RuntimeEvent]] = {
            "file_write": [], "network_connect": [], "process_exec": [], "other": [],
        }
        for e in events:
            if e.category == "process_exec":
                out["process_exec"].append(e)
            elif e.category == "network_connect":
                host = _address_host(e.address)
                out["network_connect" if host not in LOCALHOST else "other"].append(e)
            elif e.category == "file_open":
                if e.mode and DANGEROUS_FILE_MODES.search(e.mode):
                    out["file_write"].append(e)
                else:
                    out["other"].append(e)
            else:
                out["other"].append(e)
        return out

    @staticmethod
    def dangerous_events(events: list[RuntimeEvent], workdir: str = "") -> list[RuntimeEvent]:
        """Сигналы реальной эксплуатации: запись вне workdir, внешний connect, execve."""
        workdir = str(workdir)
        dangerous = []
        for e in events:
            if e.category == "process_exec":
                dangerous.append(e)
            elif e.category == "network_connect":
                if _address_host(e.address) not in LOCALHOST:
                    dangerous.append(e)
            elif e.category == "file_open":
                if e.mode and DANGEROUS_FILE_MODES.search(e.mode):
                    if workdir and str(e.path).startswith(workdir):
                        continue  # служебная запись внутри песочницы
                    dangerous.append(e)
        return dangerous


# ── Phase 2: strace (для JS/Go/бинарников) ──────────────────────────────────

_STRACE_OPEN = re.compile(r'\bopenat?\([^,]*,\s*"([^"]+)"\s*,\s*([^)]*)\)')
_STRACE_CONNECT = re.compile(r'\bsin_addr=inet_addr\("([^"]+)"\)')
_STRACE_EXECVE = re.compile(r'\bexecve\("([^"]+)"\s*,\s*(\[[^\]]*\])')
_WRITE_FLAGS = ("WRONLY", "RDWR", "APPEND", "CREAT", "TRUNC")


def _flags_to_mode(flags: str) -> str:
    return "w" if any(f in flags for f in _WRITE_FLAGS) else "r"


def _parse_strace_line(line: str) -> Optional[RuntimeEvent]:
    """Разобрать одну строку strace (-e trace=openat,connect,execve) в событие."""
    line = line.strip()
    if not line:
        return None
    m = _STRACE_EXECVE.search(line)
    if m:
        try:
            import ast
            argv = ast.literal_eval(m.group(2))
            argv_list = [str(x) for x in argv] if isinstance(argv, list) else []
        except Exception:
            argv_list = []
        return RuntimeEvent(category="process_exec", ts=0.0, argv=argv_list)
    m = _STRACE_CONNECT.search(line)
    if m:
        return RuntimeEvent(category="network_connect", ts=0.0, address=(m.group(1), 0))
    m = _STRACE_OPEN.search(line)
    if m:
        path, flags = m.group(1), m.group(2)
        return RuntimeEvent(category="file_open", ts=0.0, path=path, mode=_flags_to_mode(flags))
    return None


def strace_validate(cmd: list, workdir: str = "", timeout: int = 30,
                    strace_bin: str = "strace", finding_key: str = "") -> list[RuntimeEvent]:
    """Phase 2: запустить команду под `strace -f -e trace=openat,connect,execve`.

    Для языков без in-process (JS/Go/бинарники). Возвращает события той же формы,
    что и Phase 1 (in-process). Если strace отсутствует — пустой список.
    """
    import shutil
    import subprocess
    import tempfile
    if not shutil.which(strace_bin):
        return []
    with tempfile.NamedTemporaryFile(suffix=".strace", delete=False) as fh:
        log_path = Path(fh.name)
    argv = [strace_bin, "-f", "-e", "trace=openat,connect,execve",
            "-o", str(log_path), "--"] + [str(c) for c in cmd]
    try:
        subprocess.run(argv, cwd=workdir or None, timeout=timeout,
                       capture_output=True, text=True)
    except Exception:
        pass
    events = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            ev = _parse_strace_line(line)
            if ev is not None:
                ev.finding_key = finding_key
                events.append(ev)
    try:
        log_path.unlink()
    except Exception:
        pass
    return events

