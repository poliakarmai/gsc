# THREAT_MODEL.md — GSC

> Дополняет `README.md` (позиционирование) и `docs/DUE_DILIGENCE_v2.md` (аудит).
> Версия модели: v1 (single-tenant pilot + SaaS MVP). Обновляется при смене trust boundaries.

## 1. Назначение

GSC сканирует репозитории и исполняет **недоверенный код** (target-код уязвимости,
PoC-эксплойты) для доказательства находок (Proof-of-Fix). Threat model фиксирует,
кому мы доверяем, кому нет, и какие runtime-гарантии это требует.

## 2. Акторы

| Актор | Доверие | Что исполняем |
|-------|---------|---------------|
| Оператор GSC (self-hosted) | trusted | конфигурация, верификационные вердикты |
| Код собственного проекта (pilot) | semi-trusted | сканируется, но авторы известны |
| **Код сканируемого репозитория** | **hostile** | клонируется и исполняется в PoF |
| PoC-эксплойт (автосгенерированный) | **hostile** | исполняется против target |
| Внешний API (GitHub, OSV.dev) | untrusted network | только исходящие HTTPS-запросы |

Ключевое различие: **trusted = код, который мы сами написали и контролируем;
hostile = любой код из сканируемого репозитория или сгенерированный эксплойт** —
он считается вредоносным до доказательства обратного.

## 3. Trust boundaries

```
оператор ──[управление]──► GSC control plane (server.py / CLI)
                              │
                              ├── clone (subprocess) ──► hostile repo
                              │
                              └── PoF sandbox ──────────► hostile code (isolated)
```

1. **Control plane ↔ БД** — tenant-scoped запросы (`tenant_id`), request-scoped
   backend (`get_db()`), enterprise-схема с `FORCE ROW LEVEL SECURITY`.
2. **Control plane ↔ сеть** — только исходящий HTTPS, allowlist git-хостов
   (`GSC_ALLOWED_GIT_HOSTS`), SSRF-guard (`_validate_target`).
3. **Sandbox ↔ host** — главная граница. Hostile код исполняется **только** в
   контейнере (docker/podman) с `--network none`, read-only rootfs, `--cap-drop ALL`,
   `no-new-privileges`, non-root user. rlimit **не является** security boundary.

## 4. Угрозы и контрмеры

| # | Угроза | Контрмера | Статус |
|---|--------|-----------|--------|
| T1 | Sandbox escape: hostile PoC читает host-fs / пишет вне workspace | container-изоляция + read-only rootfs + non-root; регрессия `tests/test_sandbox_security.py` | ✅ implemented |
| T2 | Egress: hostile code эксфильтрует данные / SSRF внутрь сети | `--network none` в sandbox; SSRF-guard на git-таргетах | ✅ implemented |
| T3 | Ложный «verified» при отсутствии изоляции | fail-closed: `verified=True` только при docker/podman; rlimit/timeout → `NOT verified` | ✅ implemented |
| T4 | Web PoC обслуживается на host | container-first: target server + PoC в одном container (`_run_web_poc_container`) | ✅ implemented |
| T5 | Cross-tenant доступ к чужим findings | `WHERE tenant_id=?` везде + `UNIQUE(tenant_id, finding_key)` + RLS; тест `test_tenant_isolation.py` | ✅ implemented |
| T6 | API key утекает в access-log (query param) | ключ только в header (`Authorization`/`X-API-Key`) | ✅ implemented |
| T7 | Отсутствующий JWT secret → молчаливый ephemeral | fail-closed: production без `JWT_SECRET` → exit(1) | ✅ implemented |
| T8 | Open redirect / OAuth replay | redirect только same-origin; state consumed atomically (one-time) | ✅ implemented |

## 5. Runtime-требования (обязательные)

- **Hostile code (PoF / Web PoC / DAST) требует container runtime** (Docker или
  Podman) и sandbox-образ `gsc-sandbox:latest` (см. `sandbox/Dockerfile`). Без них
  PoF-верификация помечается как **NOT verified** — продукт не врёт о силе
  доказательства.
- **Production (multi-tenant) требует PostgreSQL** через `GSC_DATABASE_URL` —
  SQLite не является concurrent multi-writer store.
- **Production требует `JWT_SECRET`** в env (иначе fail-closed exit).

## 6. Допущения (assumptions)

- Self-hosted pilot: оператор доверяет собственной инфраструктуре (host, Docker
  daemon). Компрометация Docker daemon = компрометация sandbox boundary.
- Язык PoF-пайплайна — Python-first. JS/TS PoC — roadmap (не заявлены как работающие).
- Сеть между control plane и внешними API считается враждебной; только HTTPS + pinned digest-образы.

## 7. Вне scope (сейчас)

Активная защита от supply-chain-атак на сам GSC (SBOM-подпись в CI, reproducible
builds) — частично в `scripts/gsc_release_sbom.py`/`gsc_release_manifest.py`, но
полный attestation-цикл — roadmap (Волна после D).
