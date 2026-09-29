#!/usr/bin/env python3
"""Container health probe: exit 0 when the dashboard answers /healthz.

Used by the image's HEALTHCHECK, and safe to paste into any container UI's
"health check command" field as plain

    python3 /app/healthcheck.py

with no quoting to get right (a one-liner with ``-c`` breaks when a UI runs
it through ``sh -c``, because of the ``;`` and parentheses).

Honours HTTP_PORT and HTTP_BIND, so a dashboard bound to a specific address
is probed there rather than on loopback.
"""
import os
import sys
import urllib.request


def target():
    port = os.environ.get("HTTP_PORT", "8080")
    bind = os.environ.get("HTTP_BIND", "0.0.0.0")
    host = "127.0.0.1" if bind in ("", "0.0.0.0", "::") else bind
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"                  # IPv6 literal
    return f"http://{host}:{port}/healthz"


def main():
    url = target()
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            if r.status == 200:
                return 0
            print(f"unhealthy: {url} answered {r.status}", file=sys.stderr)
    except Exception as e:                       # noqa: BLE001 - any failure = unhealthy
        print(f"unhealthy: {url}: {e}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
