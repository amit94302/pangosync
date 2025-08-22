FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" app && \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    pip install --no-cache-dir requests docker && \
    rm -rf /var/lib/apt/lists/*

USER app
WORKDIR /app
COPY sync.py /app/sync.py

ENTRYPOINT ["python", "/app/sync.py"]