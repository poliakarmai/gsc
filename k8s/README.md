# GSC Cloud — Kubernetes Deployment

## Структура

```
k8s/
├── base/                          # Базовые манифесты (kustomize)
│   ├── 00-namespace-config.yaml   # Namespace + ConfigMap + Secret
│   ├── 01-postgres.yaml           # PostgreSQL StatefulSet (20Gi PVC)
│   ├── 02-redis.yaml              # Redis Deployment
│   ├── 03-api.yaml                # FastAPI (HPA 2→10)
│   ├── 04-worker.yaml             # Scan workers (2 реплики)
│   ├── 05-dashboard-ingress.yaml  # Next.js + Ingress (TLS)
│   └── kustomization.yaml         # Kustomize config
└── overlays/
    └── prod/                      # Production overlay (3 API, 4 workers)
        └── kustomization.yaml
```

## Быстрый старт (локально)

```bash
# Minikube / Kind / Docker Desktop
kubectl apply -k k8s/base/

# Проверка
kubectl -n gsc get pods
kubectl -n gsc get ingress

# Локально без Ingress — port-forward
kubectl -n gsc port-forward svc/api 8000:8000
kubectl -n gsc port-forward svc/dashboard 3000:3000
```

## Production (Hetzner / AWS / GCP)

```bash
# 1. Установить cert-manager + nginx-ingress
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml

# 2. Заменить домены в 05-dashboard-ingress.yaml на свои

# 3. Создать SealedSecret для продакшен-секретов
kubectl create secret generic gsc-secrets \
  -n gsc \
  --from-literal=GSC_DATABASE_URL='postgresql://...' \
  --from-literal=DEEPSEEK_API_KEY='sk-...' \
  --from-literal=STRIPE_SECRET_KEY='sk_live_...' \
  --dry-run=client -o yaml | \
  kubeseal --format yaml > k8s/overlays/prod/sealed-secrets.yaml

# 4. Деплой
kubectl apply -k k8s/overlays/prod/
```

## Образы

Сборка и пуш:
```bash
# Cloud API + Worker (один образ)
docker build -t ghcr.io/poliakarmai/gsc-cloud:latest -f cloud/Dockerfile .

# Dashboard
docker build -t ghcr.io/poliakarmai/gsc-dashboard:latest apps/dashboard/

docker push ghcr.io/poliakarmai/gsc-cloud:latest
docker push ghcr.io/poliakarmai/gsc-dashboard:latest
```

## Ресурсы (на под)

| Сервис | CPU req/limit | Mem req/limit | Реплик |
|---|---|---|---|
| PostgreSQL | 250m/1000m | 256Mi/1Gi | 1 (StatefulSet) |
| Redis | 100m/500m | 64Mi/256Mi | 1 |
| API | 250m/1000m | 256Mi/512Mi | 2→10 (HPA) |
| Worker | 500m/2000m | 512Mi/2Gi | 2 |
| Dashboard | 100m/500m | 128Mi/512Mi | 1 |