"""Общий парсер /gsc-команд (v0.24 → S2).

Используется: gsc-feedback.yml (Actions) и cloud/pr_commands.py (webhook).
"""
import re

COMMAND_RE = re.compile(
    r"^\s*/gsc\s+(tp|fp|fixed|override)\s+([a-f0-9]{12})(?:\s+(.*))?$",
    re.IGNORECASE)
ALLOWED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
MAX_REASON_LEN = 500


def parse_commands(body: str) -> list[dict]:
    commands = []
    for line in (body or "").splitlines():
        m = COMMAND_RE.match(line.strip())
        if not m:
            continue
        commands.append({
            "finding_key": m.group(2).lower(),
            "verdict": m.group(1).lower(),
            "reason": (m.group(3) or "").strip()[:MAX_REASON_LEN],
        })
    return commands