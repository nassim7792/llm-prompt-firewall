FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY promptfw ./promptfw
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 promptfw \
    && mkdir -p /app/logs && chown promptfw:promptfw /app/logs

COPY config ./config
# Audit log and audit key live here. A named volume inherits this ownership; a host bind
# mount must be writable by uid 10001, otherwise the proxy refuses to start.
VOLUME ["/app/logs"]
USER promptfw
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"

# PROMPTFW_UPSTREAM_URL unset = offline mock agent.
ENV PROMPTFW_POLICY=/app/config/policy.example.yaml
CMD ["uvicorn", "promptfw.proxy:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8080"]
