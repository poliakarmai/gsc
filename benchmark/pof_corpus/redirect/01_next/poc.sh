#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
loc=$(curl -s -o /dev/null -w "%{redirect_url}" "$BASE/go?next=http://evil.example.com")
if echo "$loc" | grep -q "evil.example.com"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
