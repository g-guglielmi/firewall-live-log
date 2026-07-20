FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/g-guglielmi/firewall-live-log" \
      org.opencontainers.image.description="Multi-device (UniFi + Sophos) firewall syslog live dashboard" \
      org.opencontainers.image.licenses="MIT"

# Stdlib only — no pip install layer.
WORKDIR /app
COPY app/ /app/
COPY test_harness.py /app/

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin fll \
    && mkdir -p /data && chown fll:fll /data

USER fll

ENV DB_PATH=/data/events.db \
    DEVICES_CONFIG=/data/devices.json \
    AUTH_DB_PATH=/data/auth.db \
    HTTP_PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8080/tcp
# Syslog collection ports are per-device (see devices.json). Publish the
# range you use, or run with --network host (recommended for a collector).

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python3", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('HTTP_PORT','8080')+'/healthz',timeout=4)"]

CMD ["python3", "/app/main.py"]
