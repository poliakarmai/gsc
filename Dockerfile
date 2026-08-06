FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m gsc
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# CLI-обёртка gsc в PATH (нужна worker'у для subprocess)
RUN printf '#!/bin/sh\nexec python3 /app/gsc_cli.py "$@"\n' \
      > /usr/local/bin/gsc && chmod +x /usr/local/bin/gsc

COPY gsc.py gsc_external.py gsc_db.py gsc_revalidate.py gsc_blocking.py \
     gsc_poc_generator.py gsc_chain_composer.py gsc_mutation_tracker.py \
     gsc_invariant_engine.py gsc_ast_dataflow.py gsc_github_adapter.py \
     gsc_cli.py ./
COPY gsc_detectors/ ./gsc_detectors/
COPY calibration/ ./calibration/
COPY tests/ ./tests/

# Секреты НЕ в образе: DEEPSEEK_API_KEY только через env в рантайме
ENV HOME=/home/gsc \
    GSC_DB_PATH=/tmp/gsc/worker.db \
    PYTHONDONTWRITEBYTECODE=1

RUN mkdir -p /tmp/gsc && chown -R gsc:gsc /app /tmp/gsc
USER gsc

# Образ умеет и сканировать, и работать как API/worker (entrypoint в compose)
ENTRYPOINT ["gsc"]