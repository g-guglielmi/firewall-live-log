#!/usr/bin/env python3
"""firewall-live-log — multi-device firewall syslog live dashboard.

One process:
  * one UDP listener thread per configured device/port,
  * one SQLite writer thread (batch insert + retention prune),
  * one HTTP server (dashboard + live/history API).

Configuration:
  DEVICES_CONFIG   path to devices.json      (default /data/devices.json)
  DB_PATH          SQLite file               (default /data/events.db)
  HTTP_PORT        dashboard port            (default 8080)
  HTTP_BIND        dashboard bind address    (default 0.0.0.0)
  RETENTION_DAYS   overrides config value    (default 14)
  MAX_EVENTS       row-count safety cap, 0=off (overrides config)
  PRUNE_INTERVAL_SEC  retention sweep period (default 3600)
  QUEUE_MAX        max in-flight events before drop (default 100000)

Per-device vendor is auto|unifi|sophos (see devices.json).
"""

import os
import queue
import signal
import sys
import threading

import config
import listener
import store
import webserver
import writer


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def main():
    cfg_path = env("DEVICES_CONFIG", "/data/devices.json")
    db_path = env("DB_PATH", "/data/events.db")
    http_port = int(env("HTTP_PORT", "8080"))
    http_bind = env("HTTP_BIND", "0.0.0.0")
    prune_interval = int(env("PRUNE_INTERVAL_SEC", "3600"))
    queue_max = int(env("QUEUE_MAX", "100000"))

    try:
        cfg = config.load(cfg_path)
    except config.ConfigError as e:
        print(f"[config] {e}", file=sys.stderr)
        sys.exit(2)

    if env("RETENTION_DAYS"):
        cfg.retention_days = int(env("RETENTION_DAYS"))
    if env("MAX_EVENTS"):
        cfg.max_events = int(env("MAX_EVENTS"))

    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    # Create the schema synchronously so the web server's read-only
    # connection can never open before the file exists.
    store.open_writer(db_path).close()
    print(f"[main] {len(cfg.devices)} devices, retention={cfg.retention_days}d, "
          f"max_events={cfg.max_events or 'off'}, db={db_path}")

    q = queue.Queue(maxsize=queue_max)
    drops = {"n": 0, "lock": threading.Lock()}
    stop_event = threading.Event()

    def on_signal(signum, frame):
        stop_event.set()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, on_signal)

    # Writer first, so listeners never block on a full queue at startup.
    writer_thread = threading.Thread(
        target=writer.run, name="writer",
        args=(stop_event, db_path, q, drops, cfg, prune_interval))
    writer_thread.start()

    listener_threads = []
    for device in cfg.devices:
        t = threading.Thread(target=listener.run, name=f"listen-{device.name}",
                             args=(stop_event, device, q, drops), daemon=True)
        t.start()
        listener_threads.append(t)

    state = webserver.AppState(db_path, cfg.devices, cfg)
    httpd = webserver.serve(state, http_bind, http_port)
    threading.Thread(target=httpd.serve_forever, name="web",
                     daemon=True).start()

    writer_died = False
    while not stop_event.is_set():
        stop_event.wait(1.0)
        if not writer_thread.is_alive() and not stop_event.is_set():
            print("[main] writer thread died unexpectedly — exiting",
                  file=sys.stderr)
            writer_died = True
            stop_event.set()

    print("[main] shutting down...")
    httpd.shutdown()
    writer_thread.join(timeout=20)
    print("[main] bye")
    if writer_died:
        sys.exit(1)


if __name__ == "__main__":
    main()
