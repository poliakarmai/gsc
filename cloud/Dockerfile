# Контекст сборки: корень репозитория (см. compose)
FROM gsc-scanner:0.27

COPY cloud/requirements.txt /app/cloud/requirements.txt
RUN pip install --no-cache-dir -r /app/cloud/requirements.txt

COPY cloud/ /app/cloud/
USER gsc
# По умолчанию API; worker переопределяется в compose
CMD ["uvicorn", "cloud.api:app", "--host", "0.0.0.0", "--port", "8000"]