# GSC due-diligence шаг 5 (supply chain): immutable digest вместо mutable tag.
# Multi-stage: deps в builder-слое → финальный образ не тащит pip-мусор.

# --- Stage 1: builder (Python deps) ---------------------------------------
FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65 AS builder

WORKDIR /build

# Python deps — pinned versions (requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Stage 2: runtime -----------------------------------------------------
FROM python:3.12-slim@sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65

# System deps (git нужен для сканеров GitHub-репозиториев, curl — для HEALTHCHECK)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python deps из builder-слоя (без кеша pip в финальном образе)
COPY --from=builder /install /usr/local

# Non-root user (audit F-03)
RUN groupadd -r gsc && useradd -r -g gsc -m -d /app gsc

WORKDIR /app

# GSC source (owned by gsc)
COPY --chown=gsc:gsc . /app/

# Data volume
RUN mkdir -p /data && chown gsc:gsc /data
VOLUME /data

USER gsc

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Production ASGI server (audit F-03/A-07): SQLite is single-writer, so a
# single worker avoids write-lock contention. Scale to PostgreSQL + multiple
# workers for multi-tenant production.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
