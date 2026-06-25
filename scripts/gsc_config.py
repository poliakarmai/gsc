#!/usr/bin/env python3
"""GSC Config — manage settings."""
import sys, os, json
from pathlib import Path

CONFIG_FILE = Path.home() / ".gsc" / "config.json"
DEFAULTS = {
    "obsidian_vault": str(Path.home() / "obsidian-vault" / "audits"),
    "openrouter_key": "",
    "exclude_dirs": ["tests", "vendor", "node_modules", ".git", "__pycache__", "venv", ".venv"],
    "llm_provider": "openrouter",
    "llm_model": "google/gemini-2.5-flash",
    "auto_deactivate_threshold": 0.3,
    "min_ratings_for_deactivate": 10,
}

def load() -> dict:
    if CONFIG_FILE.exists():
        return {**DEFAULTS, **json.loads(CONFIG_FILE.read_text())}
    return DEFAULTS

def save(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def cmd_show():
    cfg = load()
    print("GSC Config:\n")
    for k, v in cfg.items():
        masked = v[:8] + "..." if k.endswith("_key") and v else str(v)
        print(f"  {k}: {masked}")

def cmd_set(key: str, value: str):
    cfg = load()
    if key not in DEFAULTS:
        print(f"Unknown key: {key}")
        return
    # Auto-convert types
    if isinstance(DEFAULTS[key], bool):
        value = value.lower() in ("true", "1", "yes")
    elif isinstance(DEFAULTS[key], int):
        value = int(value)
    elif isinstance(DEFAULTS[key], float):
        value = float(value)
    elif isinstance(DEFAULTS[key], list):
        value = [v.strip() for v in value.split(",")]
    cfg[key] = value
    save(cfg)
    print(f"✅ {key} = {value}")

def cmd_init():
    save(DEFAULTS)
    print(f"✅ Config initialized: {CONFIG_FILE}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        cmd_show()
    elif sys.argv[1] == "set" and len(sys.argv) >= 4:
        cmd_set(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "init":
        cmd_init()
    elif sys.argv[1] == "show":
        cmd_show()
    else:
        print("Usage: gsc config [show|set <key> <value>|init]")
        print(f"Config file: {CONFIG_FILE}")
