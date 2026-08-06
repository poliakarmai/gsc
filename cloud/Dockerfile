# Контекст сборки: корень репозитория (см. compose)
FROM gsc-scanner:0.27

USER root
COPY cloud/requirements.txt /app/cloud/requirements.txt
RUN pip install --no-cache-dir -r /app/cloud/requirements.txt

# Copy cloud backend modules (not in base image)
COPY gsc_db_backend.py /app/gsc_db_backend.py
RUN chown gsc:gsc /app/gsc_db_backend.py

COPY cloud/ /app/cloud/
RUN chown -R gsc:gsc /app/cloud/
USER gsc

# Override base image ENTRYPOINT (gsc CLI)
ENTRYPOINT []
CMD ["uvicorn", "cloud.api:app", "--host", "0.0.0.0", "--port", "8000"]