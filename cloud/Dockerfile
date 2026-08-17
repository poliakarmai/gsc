# Контекст сборки: корень репозитория (см. compose)
FROM gsc-scanner:0.27

USER root
COPY cloud/requirements.txt /app/cloud/requirements.txt
RUN pip install --no-cache-dir -r /app/cloud/requirements.txt

# Copy cloud backend modules (not in base image)
COPY gsc_cloud/ /app/gsc_cloud/

COPY cloud/ /app/cloud/

# Override base image ENTRYPOINT (gsc CLI)
ENTRYPOINT []
CMD ["uvicorn", "gsc_cloud.api:app", "--host", "0.0.0.0", "--port", "8000"]