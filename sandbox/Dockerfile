# GSC sandbox image — OS-isolated PoC execution (gsc_pof_sandbox.py).
#
# GSC roadmap 3.2: web PoC в container требует, чтобы образ умел поднимать
# Flask/FastAPI target server + curl для PoC. Без flask контейнерный web PoC
# недоступен и gsc_pof_sandbox честно уходит в host-side rlimit fallback.
#
# Сборка:
#   docker build -t gsc-sandbox:latest sandbox/
# Переопределение образа:
#   GSC_SANDBOX_IMAGE=my-sandbox:tag
FROM python:3.12-slim

# curl нужен для curl/bash PoC; ca-certificates — для HTTPS
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Web target frameworks (single-file + multi-module) — версии закреплены
# для воспроизводимости sandbox-среды.
RUN pip install --no-cache-dir "flask==3.0.3" "fastapi==0.115.6" "uvicorn==0.34.0"

# Запускается как nobody через --user 65534 (см. _run_isolated); rootfs read-only,
# writable только смонтированный workspace + tmpfs /tmp.
WORKDIR /work
