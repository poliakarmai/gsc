# Cyberbro XSS — First Public Case Study

> Август 2026. Первый публичный proof-of-concept GSC на реальном проекте.

## Проект

| Параметр | Значение |
|----------|----------|
| Репозиторий | stanfrbd/cyberbro |
| Звёзды | 122 ⭐ |
| Языки | Python (97), HTML (86), JS (12) |
| Размер | 46,677 LOC, 281 файл |
| Тип | OSINT threat intelligence platform |

## Уязвимость

| Параметр | Значение |
|----------|----------|
| CWE | CWE-79 — Cross-Site Scripting |
| Детектор | **GS020** (gs020_xss_injection) |
| Файл | `static/history.js:148` |
| Суть | `p.innerHTML = p.title.replace(...)` — XSS через поисковый highlight |
| Severity | HIGH (CVSS 7.5) |

## Фикс

| Параметр | Значение |
|----------|----------|
| Строк в патче | 9 |
| Файлов изменено | 1 (`static/history.js`) |
| Подход | `p.innerHTML` → `span.textContent` (safe DOM) |
| PR | [#212](https://github.com/stanfrbd/cyberbro/pull/212) |
| Статус | ✅ Merged (2026-08-10) |

## Отзыв автора

> «Thank you so much for bringing that out! I will merge it ASAP & release new version.»
> — stanfrbd, maintainer of Cyberbro

## Метрики продажи

| Метрика | Значение |
|---------|----------|
| Время от скана до фикса | Минуты (автоматически) |
| Стоимость ручного фикса* | ~$200 (senior engineer, 30 min) |
| Стоимость GSC-фикса | $0 |
| Другие находки в проекте | 18 GS020 (XSS) + остальные |

\* Оценка: поиск уязвимости + ручной аудит + написание фикса + тестирование

## Публикации

- DEV.to Bug Smash: [Clear the Lineup submission](https://dev.to/alexey_polyakov_cfe2095e3/clear-the-lineup-xss-via-innerhtml-in-cyberbro-found-and-fixed-by-gsc-14mg)
- GitHub PR: [stanfrbd/cyberbro#212](https://github.com/stanfrbd/cyberbro/pull/212)
