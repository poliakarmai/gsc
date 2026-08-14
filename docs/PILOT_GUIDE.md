# PILOT_GUIDE.md — GSC single-tenant pilot

Развёртывание limited single-tenant pilot (self-hosted). Цель — валидировать
ценность PoF (Proof-of-Fix) на **собственном** коде до перехода на multi-tenant.

## 1. Предусловия

- Python ≥ 3.10, `pip`.
- **Docker или Podman** (обязателен для PoF-верификации — см. threat model).
- Для SaaS-режима — PostgreSQL (опционально на этапе pilot; SQLite достаточно).

## 2. Установка

```bash
git clone https://github.com/poliakarmai/gsc.git && cd gsc
pip install -e .
# sandbox-образ для PoF
docker build -t gsc-sandbox:latest sandbox/
```

## 3. Первый аудит

```bash
gsc scan <repo> --profile audit --with-poc --with-chains
```

Генерация PoC и доказательство уязвимостей происходит в изолированном контейнере.
Если container runtime недоступен — PoF помечается **NOT verified** (это by design,
не ошибка).

## 4. Proof-of-Fix цикл

```bash
# найти уязвимость и сгенерировать PoC
gsc pof generate <finding_key>
# после фикса — верификация (tests + DAST)
gsc pof verify <finding_key>
# PR открывается только при positive signal (tests PASSED ИЛИ dast PASSED)
```

## 5. SaaS-режим (self-hosted API)

```bash
GSC_DEV_MODE=1 python3 server.py            # dev (SQLite)
# production
export JWT_SECRET=$(openssl rand -base64 32)
export GSC_DATABASE_URL=postgresql://...
psql "$GSC_DATABASE_URL" -f cloud/schema_s1.sql
python3 server.py
```

Endpoints: `POST /api/v2/auth/signup` → API key → `POST /api/v2/scan`.
Workers: `python3 -m gsc_scan_worker --loop 5` (или server спавнит их сам).
Полный список: `docs/openapi.json`.

## 6. Границы pilot (что можно честно заявлять)

**Заявляйте:**
- SAST (37 registry-детекторов) + 4 движка (Secrets/SCA/IaC/Invariants).
- Auto-PoC и Proof-of-Fix **с OS-изоляцией** (docker/podman) — full before/after evidence.
- Self-healing CI, SBOM (CycloneDX/SPDX).

**Не заявляйте** (см. `KNOWN_LIMITATIONS.md`):
- Точность «X%» без вашего собственного замера на ваших проектах.
- PoF для JS/TS-проектов (Python-first).
- Верификацию как «verified», если она выполнялась на host (rlimit).

## 7. Критерии успеха pilot

1. ≥ 1 реальный PoF-цикл (нашли → PoC → fix → verify PASSED) на вашем коде.
2. Precision-замер на 5+ ваших репозиториев (CRITICAL/HIGH).
3. False-positive обратная связь → self-learning деактивация отработала.
