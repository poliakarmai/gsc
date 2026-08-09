#!/usr/bin/env python3
"""
GSC Educational Layer — enriches security findings with learning context.

AntiVibe-inspired: "Understand any code, not just accept it."
For each vulnerability: WHAT is it, WHY it matters, WHEN it happens, HOW to fix.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional

# ── Knowledge base: CWE → educational context ────────────────────────────────

EDU_KB: Dict[str, Dict[str, str]] = {
    # SQL Injection
    "GS005": {
        "what": (
            "SQL-инъекция возникает когда пользовательский ввод попадает в SQL-запрос "
            "без параметризации. Атакующий может читать/изменять/удалять данные БД."
        ),
        "why": (
            "SQLi — #3 в OWASP Top 10. Одна успешная инъекция может скомпрометировать "
            "всю базу данных. Частая причина утечек: 2023 MOVEit, 2024 Cleo — оба SQLi."
        ),
        "when": (
            "Проявляется когда: (1) строка запроса строится конкатенацией с пользовательским "
            "вводом, (2) нет параметризации через ?/%s или ORM, (3) нет валидации типов."
        ),
        "how": (
            "1. Заменить f-строки/конкатенацию на параметризованные запросы (cursor.execute(sql, params))\n"
            "2. Использовать ORM с правильной фильтрацией (.filter(), .where())\n"
            "3. Валидировать типы: int() для чисел, экранирование для строк"
        ),
        "prerequisite": "Понимание разницы между строкой запроса и параметрами запроса",
        "resources": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "analogy": (
            "Представь что ты даёшь официанту бланк заказа. Если ты просто говоришь "
            "\"напиши в бланке что я хочу\", а кто-то кричит \"и убери все со счёта!\", "
            "официант выполнит. Параметризация — это когда ты заполняешь только поля "
            "формы, а не переписываешь весь бланк."
        ),
    },

    # XSS
    "GS020": {
        "what": (
            "Cross-Site Scripting: атакующий внедряет JavaScript в страницу, "
            "которую видят другие пользователи. Кража сессий, фишинг, дефейс."
        ),
        "why": (
            "XSS — самый распространённый тип веб-уязвимостей. Даже в 2026 году "
            "находят XSS в продуктах Atlassian, Salesforce, GitHub. Один script-тег "
            "может угнать сессию админа."
        ),
        "when": (
            "Проявляется когда: (1) пользовательский ввод рендерится в HTML без экранирования, "
            "(2) используются innerHTML/dangerouslySetInnerHTML, (3) нет Content-Security-Policy."
        ),
        "how": (
            "1. Всегда экранировать вывод: html.escape(), {{ }} в шаблонах\n"
            "2. Использовать textContent вместо innerHTML\n"
            "3. Настроить Content-Security-Policy: default-src 'self'\n"
            "4. Валидировать ввод по белому списку"
        ),
        "prerequisite": "Разница между HTML-контентом и HTML-разметкой",
        "resources": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html",
        ],
        "analogy": (
            "Как доска объявлений в подъезде. Ты вешаешь объявление \"продам диван\", "
            "а сосед дописывает мелким шрифтом \"отдам ключи от квартиры\". "
            "Экранирование — это ламинация: нельзя дописать поверх."
        ),
    },

    # Session Fixation
    "GS019": {
        "what": (
            "Session Fixation: атакующий фиксирует ID сессии до аутентификации, "
            "жертва логинится с этим ID, атакующий получает доступ к сессии жертвы."
        ),
        "why": (
            "Критично для любого приложения с аутентификацией. Позволяет обойти "
            "все механизмы защиты учётной записи — 2FA, пароль, биометрию. "
            "Одна из причин почему OWASP требует регенерацию сессии при логине."
        ),
        "when": (
            "Проявляется когда: (1) при логине не вызывается session_regenerate_id() "
            "или forget(), (2) сессия принимается из URL-параметра, (3) нет привязки "
            "сессии к IP/User-Agent."
        ),
        "how": (
            "1. Вызывать forget()/session_regenerate_id() ПЕРЕД remember()/set_user()\n"
            "2. Сбрасывать сессию при logout\n"
            "3. Привязывать сессию к fingerprint (IP + User-Agent)"
        ),
        "prerequisite": "Как работают сессии: cookie → session_id → server-side storage",
        "resources": [
            "https://owasp.org/www-community/attacks/Session_fixation",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
        "analogy": (
            "Как номерок в гардеробе. Если ты можешь взять номерок №42, отдать его "
            "VIP-клиенту, а потом прийти и сказать \"я №42, отдайте мне пальто VIPа\" — "
            "это session fixation. Регенерация = новый номерок при каждой сдаче пальто."
        ),
    },

    # SSRF
    "GS025": {
        "what": (
            "Server-Side Request Forgery: сервер делает HTTP-запрос по URL, "
            "контролируемому атакующим. Доступ к внутренней сети, облачным метаданным."
        ),
        "why": (
            "SSRF — ворота во внутреннюю сеть. Через SSRF атакующий может: "
            "читать AWS/GCP метаданные (169.254.169.254), атаковать внутренние "
            "сервисы, обходить файрволы. Капитал One утечка 2019 — через SSRF."
        ),
        "when": (
            "Проявляется когда: (1) сервер фетчит URL от пользователя, (2) нет проверки "
            "на внутренние IP (127.0.0.1, 10.x, 172.16.x, 192.168.x), (3) нет белого "
            "списка разрешённых хостов."
        ),
        "how": (
            "1. Проверять IP перед запросом: блокировать RFC 1918, loopback, link-local\n"
            "2. Использовать белый список доменов, а не чёрный список IP\n"
            "3. Запускать запросы в отдельном network namespace без доступа к internal сети"
        ),
        "prerequisite": "Разница между публичными и приватными IP-адресами (RFC 1918)",
        "resources": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        "analogy": (
            "Ты — секретарь. Кто-то говорит \"позвони по этому номеру и прочитай что "
            "там скажут\". Если ты не проверяешь номер, тебе скажут позвонить во "
            "внутренний отдел кадров и прочитать зарплаты всех сотрудников."
        ),
    },

    # Hardcoded secrets
    "GS029": {
        "what": (
            "Hardcoded secret: пароль, API-ключ или токен хранится прямо в коде. "
            "Любой кто видит код (включая GitHub) получает доступ к сервису."
        ),
        "why": (
            "Самая частая причина утечек: 2024 — 12.8M секретов найдено в "
            "публичных GitHub репозиториях. Один закоммиченный AWS-ключ может "
            "стоить $50K+ за ночь майнинга крипты."
        ),
        "when": (
            "Хардкод везде: (1) config.py с паролями, (2) примеры кода с реальными "
            "ключами, (3) DEBUG=True с SECRET_KEY в settings.py, (4) CI/CD переменные "
            "в коде вместо secrets."
        ),
        "how": (
            "1. Вынести в переменные окружения: os.getenv('API_KEY')\n"
            "2. Использовать .env + .gitignore\n"
            "3. Секрет-менеджер: HashiCorp Vault, AWS Secrets Manager\n"
            "4. git-secrets или pre-commit хук для блокировки коммитов с секретами"
        ),
        "prerequisite": "Разница между кодом и конфигурацией (12-factor app, пункт III)",
        "resources": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://12factor.net/config",
        ],
        "analogy": (
            "Написать пароль от сейфа на стикере и приклеить к двери. Даже если "
            "дверь закрыта — любой кто войдёт увидит пароль. .env = хранить стикер "
            "в кармане, а не на двери."
        ),
    },

    # Hardcoded passwords (GS001)
    "GS001": {
        "what": "Жёстко закодированные пароли/ключи/токены в исходном коде.",
        "why": "При утечке кода (GitHub, ноутбук, бекап) злоумышленник получает доступ ко всем сервисам.",
        "when": "config.py, settings.py, примеры кода, тестовые фикстуры с реальными данными.",
        "how": "os.getenv() + .env + .gitignore. Никаких паролей в репозитории.",
        "prerequisite": "12-factor app config",
        "resources": ["https://12factor.net/config"],
        "analogy": "Ключ от квартиры под ковриком. Даже если никто не видит — однажды кто-то проверит.",
    },

    # Debug prints (GS003)
    "GS003": {
        "what": "Отладочный print()/console.log в production-коде. Может раскрыть чувствительные данные в логах.",
        "why": "Логи читают не только разработчики — support, DevOps, иногда клиенты. print(password) в логах = утечка.",
        "when": "Когда разработчик забыл убрать отладку перед деплоем. Особенно часто в Python/JS.",
        "how": "Использовать logging.debug() вместо print(). Настроить уровень логирования: INFO в production.",
        "prerequisite": "logging vs print",
        "resources": ["https://docs.python.org/3/howto/logging.html"],
        "analogy": "Оставить черновик с паролями на столе в переговорной. Любой кто зайдёт — прочитает.",
    },

    # Default: generic educational context
    "_default": {
        "what": "Потенциальная уязвимость безопасности в коде.",
        "why": "Может быть использована для компрометации приложения или данных.",
        "when": "При определённых условиях (проверьте код-ревью).",
        "how": "Следуйте рекомендациям OWASP и принципу наименьших привилегий.",
        "prerequisite": "Базовое понимание безопасности веб-приложений",
        "resources": ["https://owasp.org/www-project-top-ten/"],
        "analogy": "",
    },
}


def get_edu_context(rule_id: str) -> dict:
    """Get educational context for a rule. Falls back to _default."""
    return EDU_KB.get(rule_id, EDU_KB["_default"])


def enrich_finding(finding: dict) -> dict:
    """Add educational context to a finding."""
    rule_id = finding.get("rule_id", finding.get("rule", ""))
    # Normalize: GS029-secret_type → GS029
    base_rule = rule_id.split("-")[0] if "-" in rule_id else rule_id
    edu = get_edu_context(base_rule)

    finding["education"] = {
        "what": edu["what"],
        "why": edu["why"],
        "when": edu["when"],
        "how": edu["how"],
        "prerequisite": edu["prerequisite"],
        "resources": edu["resources"],
        "analogy": edu.get("analogy", ""),
    }
    return finding


def add_edu_section_to_pr(pr_body: str, rule_id: str) -> str:
    """Append educational section to PR description."""
    base_rule = rule_id.split("-")[0] if "-" in rule_id else rule_id
    edu = get_edu_context(base_rule)

    section = "\n\n## 📚 Understanding This Vulnerability\n\n"
    section += f"### Что это?\n{edu['what']}\n\n"
    section += f"### Почему это важно?\n{edu['why']}\n\n"
    section += f"### Когда проявляется?\n{edu['when']}\n\n"
    section += f"### Как исправить правильно?\n{edu['how']}\n\n"

    if edu.get("analogy"):
        section += f"### 🧠 Аналогия\n> {edu['analogy']}\n\n"

    section += "### 📖 Дополнительно\n"
    for r in edu["resources"]:
        section += f"- [{r}]({r})\n"

    section += f"\n---\n🐛 Found by [GSC](https://github.com/poliakarmai/gsc) — понимай код, а не принимай."
    return pr_body + section


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json, sys
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        for rid in sorted(EDU_KB):
            if rid != "_default":
                print(f"  {rid}: {EDU_KB[rid]['what'][:80]}...")
    elif len(sys.argv) > 1:
        edu = get_edu_context(sys.argv[1])
        print(json.dumps(edu, ensure_ascii=False, indent=2))
    else:
        print("Usage: gsc_edu.py <rule_id> | --list")
