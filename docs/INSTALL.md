# Установка GSC

## Требования

| Компонент | Версия | Проверка |
|-----------|--------|----------|
| Python | 3.10+ | `python3 --version` |
| ripgrep | 13+ | `rg --version` |
| Git | 2.30+ | `git --version` |

## macOS

```bash
brew install ripgrep
git clone https://github.com/poliakarmai/gsc.git
cd gsc
pip install .
gsc doctor
```

## Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install ripgrep python3-pip git
git clone https://github.com/poliakarmai/gsc.git
cd gsc
pip install .
gsc doctor
```

## Linux (Arch)

```bash
sudo pacman -S ripgrep python-pip git
git clone https://github.com/poliakarmai/gsc.git
cd gsc && pip install . && gsc doctor
```

## Без установки

```bash
git clone https://github.com/poliakarmai/gsc.git
cd gsc
python3 gsc.py doctor
python3 gsc.py scan my-project
```

## Проверка

```bash
gsc doctor
# Ожидаемый вывод:
# ✅ Python 3.11.5
# ✅ ripgrep 14.1.0
# ✅ Git 2.43.0
# ✅ GSC Database — 277 patterns, 358 findings
# ✅ Seed patterns — 6 language packs
```

## Следующий шаг

[Использование](USAGE.md) → [Паттерны](PATTERNS.md) → [Конфигурация](CONFIG.md)
