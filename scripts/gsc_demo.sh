#!/usr/bin/env bash
# GSC roadmap 1.3 — demo video каркас (asciinema).
#
# Запись:  asciinema rec -c "bash scripts/gsc_demo.sh" demo.cast
# Просмотр: asciinema play demo.cast
# Экспорт:  asciinema convert demo.cast demo.gif
#
# Скрипт ведёт по ключевому flow: init → scan → pof generate (доказательство).
# Перед записью соберите sandbox-образ:  docker build -t gsc-sandbox:latest sandbox/
set -euo pipefail

REPO="https://github.com/poliakarmai/gsc"   # или свой демо-репозиторий
DEMO_DIR="$(mktemp -d)"

say() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }

say "1. Устанавливаем GSC"
pip install -e . >/dev/null 2>&1 || true

say "2. Сканируем репозиторий (с авто-PoC)"
gsc scan "$REPO" --profile audit --with-poc --json | head -c 2000
echo

say "3. Генерируем PoC-доказательство для находки"
# pof generate <finding_key> — подставьте реальный key из шага 2
gsc pof --help 2>/dev/null | head -20

say "4. Proof-of-Fix: верификация фикса"
gsc pof batch --help 2>/dev/null | head -15

say "Готово. Полный цикл: detect → prove → fix → verify."
rm -rf "$DEMO_DIR"
