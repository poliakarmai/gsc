"""Secret store — one canonical, file-backed store for GSC credentials.

Ported from openworker (MIT, ``coworker/secrets.py``). Design: secrets **never enter the
model's context, prompts, or traces**. The store holds profiles keyed by
``connector[:account]``; values may be literals OR ``${ENV_VAR}`` references resolved at
read time from the process env / ``~/.config/gsc/.env``.

The backing file is a ``0600`` JSON file behind this interface; the interface is what
callers depend on, so a Keychain / age-encrypted backend can swap in later without
touching them.

Atomic private write: the temp file is created with ``tempfile.mkstemp`` (0600 + O_EXCL)
*before* any byte is written, so plaintext never sits on disk at the umask default, and
the fixed ``<name>.tmp`` filename (which a local attacker could pre-create as a symlink)
is gone.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_IS_WINDOWS = sys.platform == "win32"


def state_dir() -> Path:
    """Where GSC keeps its state — the one cross-platform source of truth."""
    base = os.environ.get("GSC_STATE_DIR")
    if base:
        return Path(base).expanduser()
    if _IS_WINDOWS:
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "gsc"
    return Path.home() / ".config" / "gsc"


def _load_dotenv(path: Path) -> dict:
    env = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _restrict_to_user(path: Path, *, is_dir: bool) -> None:
    if _IS_WINDOWS:
        # Windows has no meaningful mode bits; leave ACLs to the caller (best-effort).
        return
    os.chmod(path, 0o700 if is_dir else 0o600)


def _atomic_private_write(target: Path, content: str) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        _restrict_to_user(target.parent, is_dir=True)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        _restrict_to_user(tmp, is_dir=False)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return target


class SecretStore:
    """File-backed secret store. Reads resolve ``${VAR}`` refs; status never leaks values."""

    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path).expanduser() if path else state_dir() / "secrets.json"
        self._dotenv_path = self.path.parent / ".env"
        self._lock = threading.Lock()

    # -- reads ------------------------------------------------------------------
    def get(self, profile: str) -> Optional[dict]:
        data = self._read().get(profile)
        if data is None:
            return None
        return self.resolve(data)

    def resolve(self, value: Any) -> Any:
        env = _load_dotenv(self._dotenv_path)

        def _walk(v):
            if isinstance(v, str):
                return _REF.sub(
                    lambda m: os.environ.get(m.group(1)) or env.get(m.group(1)) or m.group(0),
                    v,
                )
            if isinstance(v, dict):
                return {k: _walk(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_walk(x) for x in v]
            return v

        return _walk(value)

    def status(self) -> list:
        """Profile metadata only — **never** the secret values themselves."""
        out = []
        for profile, data in self._read().items():
            data = data if isinstance(data, dict) else {}
            expires = data.get("expires")
            expired = isinstance(expires, (int, float)) and expires < time.time()
            out.append(
                {
                    "profile": profile,
                    "type": data.get("type"),
                    "account": data.get("account_id"),
                    "expired": bool(expired),
                }
            )
        return out

    # -- writes -----------------------------------------------------------------
    def put(self, profile: str, data: dict) -> None:
        with self._lock:
            store = self._read()
            store[profile] = data
            self._write(store)

    def delete(self, profile: str) -> bool:
        with self._lock:
            store = self._read()
            if profile not in store:
                return False
            del store[profile]
            self._write(store)
            return True

    # -- internals --------------------------------------------------------------
    def _read(self) -> dict:
        if not self.path.is_file():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, store: dict) -> None:
        _atomic_private_write(self.path, json.dumps(store, indent=2))
