# DEPLOYMENT.md — GSC

Развёртывание cloud-контура (server.py + workers). Для локального CLI-аудита
деплой не нужен (`pip install . && gsc scan <repo>`).

## 1. Быстрый старт (docker-compose, dev)

```bash
cd ~/gsc
docker compose up -d          # postgres:16 + api
# PostgreSQL включается автоматически через GSC_DATABASE_URL в compose
curl -s localhost:8000/health
```

## 2. Kubernetes (production)

```bash
# локально (minikube/kind)
kubectl apply -k k8s/base/

# production overlay (3 API + 4 workers) — зафиксировать digest!
kubectl apply -k k8s/overlays/prod/
```

Структура `k8s/base/`: namespace+config+secret, postgres (StatefulSet), redis,
api (HPA 2→10), worker (2 реплики), dashboard+ingress. В `k8s/overlays/prod/`
ОБЯЗАТЕЛЬНО зафиксируйте immutable image digest (не `:latest`) — шаблон в
`kustomization.yaml` (images → `newTag: <release>@sha256:<digest>`).

### Helm

```bash
helm install gsc ./helm \
  --set image.tag=v1.3.0 \
  --set gsc.projects='["https://github.com/you/repo"]' \
  --set sso.enabled=false
```

## 3. Переменные окружения

| Переменная | Назначение | Default |
|-----------|------------|---------|
| `GSC_DB` | путь SQLite (dev) | `~/.gsc/gsc_cloud.db` |
| `GSC_DATABASE_URL` | PostgreSQL DSN (production) | — (SQLite) |
| `GSC_DEV_MODE` | `1` = dev (разрешает persist JWT secret) | `0` |
| `GSC_INVITE_ONLY` | `1` = закрытая регистрация (403 для open signup) | `0` |
| `JWT_SECRET` | **обязателен в prod**; без него — fail-closed exit | — |
| `GSC_SANDBOX_IMAGE` | образ для PoF sandbox | `gsc-sandbox:latest` |
| `GSC_SANDBOX_NETWORK` | сетевой режим sandbox | `none` (egress deny) |
| `GSC_ALLOWED_GIT_HOSTS` | allowlist git-хостов (SSRF guard) | `github.com,gitlab.com,bitbucket.org` |
| `GSC_AUDIT_DB` | локальный audit DB для dashboard-агрегатов | — |
| `GSC_CORS_ORIGINS` | CORS allowlist | — |
| `GITHUB_CLIENT_ID` / `_SECRET` / `GITHUB_REDIRECT_URI` | OAuth (иначе `/auth/github` → 500) | — |

## 4. PostgreSQL (production multi-tenant)

```bash
# применить enterprise-схему (RLS FORCE, FK, composite UNIQUE)
psql "$GSC_DATABASE_URL" -f cloud/schema_s1.sql

# мигрировать данные SQLite → PostgreSQL (идемпотентно)
python3 scripts/gsc_pg_migrate.py
```

Затем запустить с `GSC_DATABASE_URL` — server.py автоматически переключится на
`PgBackend` (request-scoped, tenant-scoped). SQLite остаётся только для dev.

## 5. Sandbox-образ (обязателен для PoF)

```bash
docker build -t gsc-sandbox:latest sandbox/
```

Без образа (или без flask в нём) PoF-верификация честно помечает результат
**NOT verified** — container isolation не эмулируется. См. `THREAT_MODEL.md`.

## 6. Workers

Сканы обрабатываются out-of-process worker'ом:

```bash
# daemon-режим: поллит очередь scan_jobs
python3 -m gsc_scan_worker --loop 5
```

`server.py` сам спавнит worker на каждый queued job (detached subprocess), с
in-process fallback для dev. В k8s worker развёрнут отдельно (`04-worker.yaml`).

## 7. Health / readiness

- `GET /health` — liveness (без проверки БД).
- `GET /ready` — readiness (реальная DB connectivity, 503 при недоступности).

## 8. Security checklist (production)

- [ ] `JWT_SECRET` задан (иначе не стартует)
- [ ] `GSC_INVITE_ONLY=1` (если не нужен open signup)
- [ ] image digest зафиксирован (не `:latest`)
- [ ] PostgreSQL + `schema_s1.sql` (RLS)
- [ ] sandbox-образ собран; container runtime доступен на worker-нодах
- [ ] `GSC_CORS_ORIGINS` — явный allowlist (без wildcard)
