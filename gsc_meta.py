"""Single source of truth for GSC metadata (refactor #4)."""
import sqlite3, subprocess
from pathlib import Path

GSC = Path(__file__).parent
DB = Path.home() / ".hermes/state/gsc_audit.db"

def get_meta() -> dict:
    try:
        from gsc_detectors.registry import get_detectors
        plugin = len(get_detectors())
    except Exception:
        plugin = 28
    return {
        "version": _read_version(),
        "detectors_plugin": plugin,
        "detectors_total": plugin + 1,  # + GS024 LLM
        "schema": _read_schema(),
        "modules": _count_modules(),
    }

def _read_version() -> str:
    vf = GSC / "VERSION"
    return vf.read_text().strip() if vf.exists() else "unknown"

def _read_schema() -> int:
    if not DB.exists(): return -1
    try:
        conn = sqlite3.connect(str(DB))
        r = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return r[0] if r and r[0] else -1
    except: return -1

def _count_modules() -> int:
    return len([f for f in GSC.glob("gsc_*.py") if f.is_file()]) + len(
        [f for f in (GSC/"gsc_detectors").glob("*.py") if f.is_file()]) + len(
        [f for f in (GSC/"enterprise").glob("*.py") if f.is_file()])
