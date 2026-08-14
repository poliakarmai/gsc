"""Single source of truth for GSC metadata (refactor #4)."""
import sqlite3, subprocess
from pathlib import Path

GSC = Path(__file__).parent
DB = Path.home() / ".hermes/state/gsc_audit.db"

def get_meta() -> dict:
    try:
        from gsc_detectors.registry import get_detectors
        registry = len(get_detectors())
    except Exception:
        registry = 37
    # GSC-006: 4 standalone engines run OUTSIDE the per-file registry — they are
    # real detectors with a different interface (repo/scan-level, not per-file):
    #   GS028 Invariant Engine, GS029 Secrets, GS030 SCA (OSV.dev), GS031 IaC.
    standalone = 4
    return {
        "version": _read_version(),
        "detectors_registry": registry,
        "detectors_standalone": standalone,
        # Total = registry + standalone engines. This is the single source of
        # truth — README/server/CLI must read this, never hardcode a count.
        "detectors_total": registry + standalone,
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
