#!/usr/bin/env bash
# Генерирует precision-брифы для всех детекторов GSC, у которых ещё нет брифа.
# Usage: bash scripts/gen_all_briefs.sh [model]
set -u
cd "$(dirname "$0")/.." || exit 1
MODEL="${1:-deepseek-chat}"
count=0
for f in gsc_core/gsc_detectors/gs*.py; do
  rid=$(grep -oP '(RULE_ID|rule_id)\s*=\s*"\K[^"]+' "$f" | head -1)
  [ -z "$rid" ] && { echo "SKIP (no rule_id): $f"; continue; }
  out="docs/DETECTOR_BRIEF_${rid}.md"
  if [ -f "$out" ]; then echo "EXISTS: $rid"; continue; fi
  echo "=== [$((++count))] $rid  <-  $(basename "$f") ==="
  python3 scripts/gsc_brief_generator.py "$rid" --detector "$f" --out "$out" --model "$MODEL" 2>&1 \
    | grep -E 'ОШИБКА|Traceback|\[✓\]' || echo "  ! FAILED: $rid"
done
echo "=== ГОТОВО: сгенерировано $count брифов ==="
