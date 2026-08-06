#!/usr/bin/env python3
"""Точка входа `gsc` для контейнеров и PATH."""
import sys
import gsc

if __name__ == "__main__":
    sys.exit(gsc.main(sys.argv[1:]))