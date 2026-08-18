# GSC — Git Security Checker

**AppSec-платформа с авто-PoC и Proof-of-Fix.** Находит уязвимости, *доказывает* их
рабочим эксплойтом в изолированном контейнере и — опционально — чинит сам.

---

## Ключевые возможности

- **PoC Auto-Generation** — для находки генерируется и исполняется PoC в OS-изоляции
  (Docker/Podman: `--network none`, read-only, cap-drop). Доказательство, а не «вероятно».
- **Proof-of-Fix** — фикс проверяется полным before/after циклом (tests + DAST).
  PR открывается только при положительном сигнале верификации.
- **Self-Healing CI** — на CRITICAL/HIGH GSC сам открывает verified PR с исправлением.

## Цифры (SSOT `gsc_meta.py`)

- **42 детектора** (38 registry + 4 движка: Secrets/SCA/IaC/Invariants)
- **Schema v32** · SAST + DAST + SCA + IaC + SBOM + Supply-Chain
- **Precision CRITICAL ~8–12%** (замер на 10 реальных проектах, честный disclosure)

## Use cases

1. **CI/CD gate** — блокировка merge при новых CRITICAL/HIGH, комментарии в PR.
2. **Self-healing** — автоматические verified PR с фиксами.
3. **Audit с доказательством** — before/after PoC для compliance/пентеста.

## Быстрый старт

```bash
pip install gsc-security
gsc scan <repo> --profile audit --with-poc
gsc pof generate <finding_key>
```

## Контакты

- GitHub: [poliakarmai/gsc](https://github.com/poliakarmai/gsc)
- License: Apache-2.0 + Commercial dual
- Документация: `THREAT_MODEL.md` · `ARCHITECTURE.md` · `PILOT_GUIDE.md`
