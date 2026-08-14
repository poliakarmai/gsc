"""tests/conftest.py — общие fixtures (GSC roadmap 6.10).

Раньше каждый тестовый файл дублировал sys.path-бутстрап, временную БД и
skip-логику для sandbox. Здесь — единые fixtures:
  - `repo_root` / sys.path setup (авто, через rootdir);
  - `tmp_sqlite_backend` — временный SQLite backend с чистой схемой;
  - `sandbox_backend` — skip-aware container backend для PoF-тестов.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Гарантируем, что репозиторий в sys.path (иначе `import gsc_*` падает при
# запуске pytest из другого cwd).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture
def repo_root() -> Path:
    """Абсолютный путь к корню репозитория."""
    return _ROOT


@pytest.fixture
def tmp_sqlite_backend(tmp_path):
    """Чистый временный SqliteBackend (изолированный от реального audit DB)."""
    from gsc_db_backend import SqliteBackend
    db = SqliteBackend(str(tmp_path / "test.db"))
    try:
        yield db
    finally:
        db.close()


def _container_backend() -> str:
    """'docker'/'podman' если runtime доступен, иначе 'rlimit'."""
    from gsc_pof_sandbox import _isolation_backend
    return _isolation_backend()


@pytest.fixture
def sandbox_backend():
    """Skip-aware container backend для sandbox-тестов.

    Возвращает backend-имя ('docker'/'podman'), либо пропускает тест при rlimit.
    """
    backend = _container_backend()
    if backend == "rlimit":
        pytest.skip("no container runtime (docker/podman) — sandbox boundary N/A")
    return backend


@pytest.fixture(autouse=True)
def _isolate_gsc_db(tmp_path, monkeypatch):
    """Изолировать GSC DB от реальной ~/.hermes/state/gsc_audit.db (autouse).

    corpus-тесты запускают `gsc.py scan` через subprocess, который читает
    GSC_DB_PATH. Без этой изоляции поведение различается: dev-машина имеет
    засеянную DB (393 patterns), чистый CI runner — нет. Форсируем чистую среду
    везде: GSC_DB_PATH → temp-файл (scan остаётся self-contained через
    load_patterns fallback → generate_seed_patterns).

    Уважаем явный GSC_DB_PATH из env (CI может задать свой).
    """
    if "GSC_DB_PATH" not in os.environ:
        monkeypatch.setenv("GSC_DB_PATH", str(tmp_path / "gsc_audit.db"))
