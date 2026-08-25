# Репродукция: `external-scan` слеп к CI / IaC / SCA

Дата: 25.08.2026 · Цель: `CyberNilsen/CyberSentry` (⭐0)

## Суть

`python3 gsc.py external-scan <repo>` сканирует **только python-код**. CI-воркфлоу
(`.github/workflows/*.yml`), IaC (`*.tf`, `Dockerfile*`), SCA-манифесты
(`requirements.txt`, `package.json`) — вне покрытия, даже с `--profile audit`.

---

## Шаги воспроизведения

### 1. Клонируем целевой репо
```bash
git clone --depth 1 https://github.com/CyberNilsen/CyberSentry /tmp/gsc_target2
```

### 2. В CI-воркфлоу две реальные supply-chain проблемы
```bash
cat /tmp/gsc_target2/.github/workflows/security.yml
```

**`security.yml` (полностью):**
```yaml
name: 🛡️ CyberSentry Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
    - name: 🔍 Checkout code
      uses: actions/checkout@v4          # ← строка 16: action без digest-SHA

    - name: 🐍 Setup Python
      uses: actions/setup-python@v5      # ← строка 19: action без digest-SHA
      with:
        python-version: '3.11'

    - name: 📦 Install TruffleHog
      run: |
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
        # ↑ строка 25: remote script exec без проверки SHA (curl | sh из ветки main)

    - name: 📦 Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt

    - name: 🛡️ Run CyberSentry
      run: python cybersentry.py

    - name: 📊 Upload Security Report
      uses: actions/upload-artifact@v4   # ← строка 36: без digest-SHA
      if: always()
      with:
        name: cybersentry-report
        path: SECURITY_REPORT.md

    - name: 📝 Comment PR (if PR)
      uses: actions/github-script@v7     # ← строка 43: без digest-SHA
      if: github.event_name == 'pull_request'
      with:
        script: |
          const fs = require('fs');
          if (fs.existsSync('SECURITY_REPORT.md')) {
            const report = fs.readFileSync('SECURITY_REPORT.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## 🛡️ CyberSentry Security Report\\n\\n' + report
            });
          }
```

### 3. Гоняем external-scan
```bash
cd ~/gsc
export DEEPSEEK_API_KEY=$(grep '^DEEPSEEK_API_KEY=' ~/.hermes/.env | cut -d= -f2- | tr -d '"')
python3 gsc.py external-scan /tmp/gsc_target2 --profile audit --max-llm 25 -o /tmp/gsc_report3
```

### 4. Смотрим факт из вывода
```
📁 6/36 files (2 dirs excluded)
🔤 Languages: python
📋 Profile: audit | Mode: full
🔍 Scanning...
   Raw findings: 15
   LLM revalidated: 13
   Results: 0 blocking, 0 confirmed, 0 likely
```

---

## Факт vs ожидание

| | Ожидание | Факт |
|---|---|---|
| Покрытие | CI/IaC/SCA входят в скан AppSec-платформы | 6/36 файлов, только python |
| `curl \| sh` | найдено (supply-chain) | **пропущено** |
| action без SHA (S-05/S-06) | найдено | **пропущено** |
| Отчёт | честно говорит, что CI/IaC/SCA не покрыто | молчаливые «6/36 files» |

## Что пропущено (конкретика)

1. **`curl -sSfL <url> | sh`** — `security.yml:25`. Непроверенный удалённый скрипт из
   ветки `main` trufflehog. Remote code exec при деплое, если репозиторий скомпрометирован
   или curl перехвачен. Классический supply-chain риск.
2. **4 GitHub Action без digest-SHA** — `security.yml:16,19,36,43`:
   - `actions/checkout@v4`
   - `actions/setup-python@v5`
   - `actions/upload-artifact@v4`
   - `actions/github-script@v7`
   Pin по тегу (mutable), а не по SHA. Соответствует GSC-контролам S-05/S-06
   (GitHub Action pin по SHA) — они существуют в supply-chain модуле, но не вызываются.

---

## Root cause

`external-scan` (модуль `gsc_external`) собирает файлы по **языковому фильтру профиля**
(в данном случае `python`). CI-воркфлоу (`.yml`), IaC (`*.tf`, `Dockerfile*`), SCA-манифесты —
не входят в языковой фильтр. Модули `gsc_iac` и supply-chain (S-05/S-06 action pin)
существуют в GSC отдельно, но `external-scan` их не запускает, даже в `--profile audit`.

---

## Как проверить, что починено

```bash
python3 gsc.py external-scan /tmp/gsc_target2 --profile audit -o /tmp/gsc_report_fixed
```

Ожидаемые признаки фикса:
- [ ] `files_scanned` > 6 (включая `.github/workflows/security.yml`)
- [ ] в `findings` есть S-05/S-06 (unpinned GitHub Action) для `security.yml:16,19,36,43`
- [ ] в `findings` есть supply-chain-находка `curl | sh` для `security.yml:25`
- [ ] summary явно указывает, какие классы покрыты (CI/IaC/SCA), а не молчаливые «6/36 files»

---

## Данные для воспроизведения

- Отчёт скана: `/tmp/gsc_report3/scan.json`, `/tmp/gsc_report3/summary.json`
- Целевой воркфлоу: `/tmp/gsc_target2/.github/workflows/security.yml`
- Целевой репо: https://github.com/CyberNilsen/CyberSentry
