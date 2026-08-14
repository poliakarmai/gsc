"""Single source of truth for GSC metadata (refactor #4)."""
import sqlite3, subprocess
from pathlib import Path

GSC = Path(__file__).parent
DB = Path.home() / ".hermes/state/gsc_audit.db"

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

def _count_modules() -> int:
    return len([f for f in GSC.glob("gsc_*.py") if f.is_file()]) + len(
        [f for f in (GSC/"gsc_detectors").glob("*.py") if f.is_file()]) + len(
        [f for f in (GSC/"enterprise").glob("*.py") if f.is_file()])


if __name__ == "__main__":
    import json
    print(json.dumps(get_meta(), indent=2, ensure_ascii=False))
