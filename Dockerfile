# Pinned by digest (multi-arch index) so a build is reproducible and a
# compromised or moved tag can't slip in; Dependabot opens a PR to bump it.
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

LABEL org.opencontainers.image.source="https://github.com/g-guglielmi/firewall-live-log" \
      org.opencontainers.image.description="Multi-device (UniFi + Sophos) firewall syslog live dashboard" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Stdlib only — no pip install layer.
WORKDIR /app
COPY app/ /app/
COPY test_harness.py /app/

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin fll \
    && mkdir -p /data && chown fll:fll /data

# No USER directive: the entrypoint starts as root just long enough to chown
# the data directories to the runtime user (PUID/PGID, default 10001), then
# drops privileges and execs the app — so a root-owned host data folder (the
# classic Unraid appdata first-run trap) fixes itself. Run with --user to
# skip the fix-up and enforce never-root instead.

# PYTHONDONTWRITEBYTECODE: nothing under /app is ever written at runtime, so
# the container works with --read-only (only /data needs to be writable).
ENV DB_PATH=/data/events.db \
    DEVICES_CONFIG=/data/devices.json \
    AUTH_DB_PATH=/data/auth.db \
    HTTP_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080/tcp
# Syslog collection ports are per-device (see devices.json). Publish the
# range you use, or run with --network host (recommended for a collector).

# A script rather than a -c one-liner, so the same command works verbatim
# when pasted into a container UI that runs it via sh -c (Dockhand, Portainer).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python3", "/app/healthcheck.py"]

ENTRYPOINT ["python3", "/app/docker-entrypoint.py"]
