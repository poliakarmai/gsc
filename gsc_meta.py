"""Single source of truth for GSC metadata (refactor #4)."""
from pathlib import Path

GSC = Path(__file__).parent
# DD-06: DB path is NOT defined here anymore — the single source of truth is
# gsc_db.DB_PATH (reads GSC_DB_PATH env). Import `from gsc_db import DB_PATH`
# when a DB path is actually needed.

# GSC-006: 4 standalone engines run OUTSIDE the per-file registry — they are
# real detectors with a different interface (repo/scan-level, not per-file):
#   GS028 Invariant Engine, GS029 Secrets, GS030 SCA (OSV.dev), GS031 IaC.
STANDALONE_ENGINE_MODULES = (
    "gsc_invariant_engine",  # GS028
    "gsc_secrets_core",      # GS029
    "gsc_sca",               # GS030
    "gsc_iac",               # GS031
)


def _count_standalone_engines() -> int:
    """GSC roadmap 2.7: динамический подсчёт standalone-движков, не hardcoded 4.

    Считаем реально импортируемые движки-модули — если один сломан/удалён, число
    честно уменьшится, а не останется завышенным.
    """
    count = 0
    for mod in STANDALONE_ENGINE_MODULES:
        try:
            __import__(mod)
            count += 1
        except Exception:
            pass
    return count

def get_meta() -> dict:
    registry = None
    try:
        from gsc_detectors.registry import get_detectors
        registry = len(get_detectors())
    except Exception as e:
        # GSC-011: молчаливый hardcoded fallback (37) маскировал сломанный импорт
        # registry и расходился с фактическим числом детекторов (grep 'DetectorEntry'
        # даёт ~34 статических — часть rules динамические/LLM). Честно помечаем None.
        import sys
        print(f"⚠️ gsc_meta: get_detectors() failed — detectors_total unknown ({e})",
              file=sys.stderr)
    # GSC-006: 4 standalone engines run OUTSIDE the per-file registry — they are
    # real detectors with a different interface (repo/scan-level, not per-file).
    # GSC roadmap 2.7: подсчёт динамический (_count_standalone_engines), не hardcoded.
    standalone = _count_standalone_engines()
    return {
        "version": _read_version(),
        "detectors_registry": registry,
        "detectors_standalone": standalone,
        # Total = registry + standalone engines. This is the single source of
        # truth — README/server/CLI must read this, never hardcode a count.
        "detectors_total": (registry + standalone) if registry is not None else None,
        "schema": _read_schema(),
        "modules": _count_modules(),
    }

def _read_version() -> str:
    vf = GSC / "VERSION"
    if vf.exists():
        return vf.read_text().strip()
    # Fallback: pyproject.toml [project].version
    try:
        import tomllib
        data = tomllib.loads((GSC / "pyproject.toml").read_text())
        return data.get("project", {}).get("version", "unknown")
    except Exception:
        return "unknown"

def _read_schema() -> int:
    # Target schema = gsc_db.TARGET_VERSION (SSOT). Live DB may lag until migration.
    try:
        from gsc_db import TARGET_VERSION
        return TARGET_VERSION
    except Exception:
        return -1

def _is_shim(path: Path) -> bool:
    """Shim-модуль (alias на gsc_core) не считается отдельным модулем."""
    try:
        head = path.read_text(encoding="utf-8")[:300]
    except Exception:
        return False
    return "Shim:" in head


def _count_modules() -> int:
    # Трек 0.5 (packages split): реальные модули = корневые (без shim-алиасов)
    # + gsc_core (движки) + gsc_core/gsc_detectors (детекторы)
    # + gsc_cli (CLI-слой) + enterprise.
    root = [f for f in GSC.glob("gsc_*.py") if f.is_file() and not _is_shim(f)]
    core = [f for f in (GSC / "gsc_core").glob("gsc_*.py") if f.is_file()]
    det = [f for f in (GSC / "gsc_core" / "gsc_detectors").glob("*.py") if f.is_file()]
    cli = [f for f in (GSC / "gsc_cli").glob("*.py")
           if f.is_file() and f.name != "__init__.py"]
    ent = [f for f in (GSC / "enterprise").glob("*.py") if f.is_file()]
    return len(root) + len(core) + len(det) + len(cli) + len(ent)


if __name__ == "__main__":
    import json
    print(json.dumps(get_meta(), indent=2, ensure_ascii=False))
