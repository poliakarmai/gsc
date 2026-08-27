# PROJECT.md — GSC: Git Security Checker

> Обзор для AI-агентов и контрибьюторов. Числа не хардкодятся — источник правды `python3 gsc_meta.py`.
> Репозиторий: github.com/poliakarmai/gsc · Версия: v1.4.0

## 1. Что это

GSC — самообучающаяся AppSec-платформа. Полный цикл:
**detect → prove → fix → verify → heal → learn**.

Поверхность покрытия:

- **SAST** — plugin-детекторы + LLM-ревалидация (confidence scoring)
- **SCA** — OSV.dev, точная резолвция lock-файлов (npm / Go / yarn)
- **Secrets** — fingerprinting + cross-repo корреляция (только хеши)
- **IaC** — Terraform / Kubernetes / Dockerfile
- **DAST** — nuclei-интеграция
- **Supply chain** — SBOM (CycloneDX / SPDX) + VEX + подпись

Эксклюзивы (нет у Semgrep / Snyk / CodeQL): PoC auto-generation + Proof-of-Fix,
self-healing CI, security archaeology, predictive forecasting, NL policy,
federated self-learning.

## 2. Архитектура

```
gsc_core/   — движок (детекторы, SCA, secrets, IaC, compliance, AST/taint)
gsc_cli/    — CLI и сканеры (orchestrator, PoF, archaeology, forecast, adapters)
gsc_cloud/  — SaaS API (multi-tenant, SSO, workers)
```

Корневые `gsc_*.py` — shim'ы (re-export через `sys.modules`) для обратной совместимости.

## 3. Ключевые команды

```bash
gsc external-scan <repo> --profile audit     # полный скан
gsc sca --repo .                             # SCA
gsc iac --repo .                             # IaC
gsc sbom --repo . --with-vex                 # SBOM + уязвимости
gsc pof generate <key>                       # Proof-of-Fix
gsc archaeology trace <key> --repo .         # история уязвимости
gsc forecast heatmap --repo .                # прогноз рисков
gsc reconcile                                # сверка доков с кодом
```

## 4. Дорожная карта

См. [docs/ROADMAP.md](docs/ROADMAP.md).
