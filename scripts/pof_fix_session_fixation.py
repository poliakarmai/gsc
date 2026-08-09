#!/usr/bin/env python3
"""
Fix for Session Fixation in aiohttp-security demo handlers (CWE-384).

Both demo handlers call `remember()` without first calling `forget()`,
allowing session fixation attacks:
  Attacker fixes session ID → victim logs in → attacker hijacks session.

Fix: regenerate session before authentication by calling `forget()` first.
"""
import sys

# Fixes for two demo handlers
FIXES = {
    "demo/database_auth/handlers.py": {
        "line": 53,
        "old": "            await remember(request, response, login)",
        "new": "            await forget(request, response)\n            await remember(request, response, login)",
    },
    "demo/dictionary_auth/handlers.py": {
        "line": 55,
        "old": "        await remember(request, response, username)",
        "new": "        await forget(request, response)\n        await remember(request, response, username)",
    },
}

if __name__ == "__main__":
    print("Session Fixation fix for aiohttp-security demo handlers")
    print("CWE-384: Session Fixation")
    print()
    for path, fix in FIXES.items():
        print(f"--- {path}:{fix['line']}")
        print(f"- {fix['old']}")
        print(f"+ {fix['new']}")
        print()
