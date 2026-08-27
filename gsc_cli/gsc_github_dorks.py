#!/usr/bin/env python3
"""
GSC GitHub Dorks Scanner — поиск секретов в публичных репозиториях.
Использует GitHub Search API для поиска по доркам.

Usage:
    python3 gsc_github_dorks.py <org_or_company> [--limit 5] [--days 7]
    python3 gsc_github_dorks.py --list-dorks

Требуется: GITHUB_TOKEN в env или gh auth.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

# ── Dorks ──────────────────────────────────────────────────────────────────────

DORKS = {
    "env_files": {
        "query": 'filename:.env NOT "example" NOT "sample"',
        "desc": ".env файлы с паролями/токенами",
        "severity": "CRITICAL",
    },
    "docker_config": {
        "query": 'filename:config.json docker "auth"',
        "desc": "Docker config.json с аутентификацией",
        "severity": "CRITICAL",
    },
    "private_keys": {
        "query": 'extension:pem "BEGIN RSA PRIVATE KEY" language:shell OR language:yaml',
        "desc": "Приватные RSA-ключи",
        "severity": "CRITICAL",
    },
    "aws_keys": {
        "query": '"AKIA" language:python OR language:javascript OR language:go',
        "desc": "AWS Access Key ID в коде",
        "severity": "CRITICAL",
    },
    "api_keys": {
        "query": '"api_key" OR "api_secret" OR "api_token" language:python OR language:javascript NOT "example" NOT "test" NOT "sample"',
        "desc": "API-ключи и токены в коде",
        "severity": "HIGH",
    },
    "database_urls": {
        "query": '"DATABASE_URL" OR "DB_PASSWORD" OR "MONGO_URI" OR "REDIS_URL" language:python OR language:javascript',
        "desc": "Строки подключения к БД",
        "severity": "HIGH",
    },
    "jwt_secrets": {
        "query": '"JWT_SECRET" OR "JWT_KEY" OR "SECRET_KEY" NOT "example" language:python OR language:javascript',
        "desc": "JWT секреты в коде",
        "severity": "HIGH",
    },
    "passwords": {
        "query": '"password" OR "passwd" filename:config OR filename:credentials NOT "example"',
        "desc": "Пароли в конфигах",
        "severity": "HIGH",
    },
    "backup_files": {
        "query": 'filename:backup extension:sql OR extension:zip OR extension:tar.gz',
        "desc": "Бекапы БД в репозиториях",
        "severity": "MEDIUM",
    },
    "internal_hosts": {
        "query": '"10." OR "172.16." OR "192.168." language:python OR language:yaml OR language:json',
        "desc": "Внутренние IP-адреса в коде",
        "severity": "MEDIUM",
    },
    "slack_tokens": {
        "query": '"xoxb-" OR "xoxp-" OR "hooks.slack.com" language:python OR language:javascript',
        "desc": "Slack токены и вебхуки",
        "severity": "CRITICAL",
    },
    "google_keys": {
        "query": '"GOOGLE_API_KEY" OR "GCP_API_KEY" OR "google_application_credentials" language:python OR language:json',
        "desc": "Google Cloud API ключи",
        "severity": "HIGH",
    },
}


def get_token():
    """Получить GitHub токен из env или gh CLI."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        import subprocess
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def search_github(query: str, org: str, token: str, days: int = 7, per_page: int = 5) -> list:
    """Поиск по GitHub Search API."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    full_query = f"{query} org:{org} created:>={since}"
    url = f"https://api.github.com/search/code?q={urllib.parse.quote(full_query)}&per_page={per_page}"

    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "GSC-GitHub-Dorks/1.0",
    })

    try:
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        return data.get("items", [])
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  ⚠️ Rate limited. Жди {e.headers.get('Retry-After', '60')}с")
        elif e.code == 422:
            print("  ⚠️ Query too complex, skipping")
        else:
            print(f"  ❌ HTTP {e.code}: {e.reason}")
        return []
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []


def scan_org(org: str, token: str, limit: int = 5, days: int = 7):
    """Сканировать организацию по всем доркам."""
    print(f"\n🔍 GSC GitHub Dorks — {org}")
    print(f"   Период: последние {days} дней | Лимит: {limit} результатов\n")

    total = 0
    findings = []

    for name, dork in DORKS.items():
        query = dork["query"]
        desc = dork["desc"]
        sev = dork["severity"]

        print(f"  [{sev}] {desc}...", end=" ", flush=True)

        items = search_github(query, org, token, days=days, per_page=limit)
        count = len(items)
        total += count

        if count:
            print(f"🔴 {count}")
            for item in items:
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                url = item.get("html_url", "")
                findings.append({
                    "dork": name, "severity": sev, "repo": repo,
                    "path": path, "url": url, "description": desc,
                })
                print(f"       📄 {repo}/{path}")
        else:
            print("—")

        time.sleep(3)  # Rate limit: 30 запросов/мин = 3с между (с запасом)

    print(f"\n  Итого: {total} находок по {len(DORKS)} доркам")

    return findings


def list_dorks():
    """Показать список дорков."""
    print("\n📋 GitHub Dorks:\n")
    for name, dork in DORKS.items():
        print(f"  [{dork['severity']}] {name}")
        print(f"       {dork['desc']}")
        print(f"       {dork['query']}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--list-dorks":
        list_dorks()
        sys.exit(0)

    org = sys.argv[1]
    limit = 5
    days = 7

    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
        elif arg == "--days" and i + 1 < len(sys.argv):
            days = int(sys.argv[i + 1])

    token = get_token()
    if not token:
        print("❌ Нет GitHub токена. Установи GITHUB_TOKEN в env или gh auth login.")
        sys.exit(1)

    findings = scan_org(org, token, limit=limit, days=days)

    if findings:
        # Вывод JSON
        print("\n" + json.dumps(findings, indent=2, ensure_ascii=False))
