FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (audit F-03)
RUN groupadd -r gsc && useradd -r -g gsc -m -d /app gsc

WORKDIR /app

# Python deps — pinned versions (requirements.txt), installed as root first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
