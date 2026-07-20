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
import secrets
import signal
import sys
import threading
import time

import auth as auth_mod
import config
import listener
import store
import webserver
import writer


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def setup_auth():
    """Open the auth DB and, on an empty user table, bootstrap an admin.

    Returns the AuthManager (or None when auth is disabled)."""
    if not env_bool("AUTH_ENABLED", True):
        print("[auth] AUTH_ENABLED=false — dashboard is UNPROTECTED; only do "
              "this behind an authenticating reverse proxy", file=sys.stderr)
        return None

    auth_db = env("AUTH_DB_PATH", "/data/auth.db")
    os.makedirs(os.path.dirname(auth_db) or ".", exist_ok=True)
    manager = auth_mod.AuthManager(auth_db)

    if manager.user_count() == 0:
        username = env("ADMIN_USERNAME", "admin")
        supplied = env("ADMIN_PASSWORD")
        password = supplied or secrets.token_urlsafe(18)
        try:
            manager.create_user(username, password, role="admin",
                                must_change_pw=not supplied)
        except auth_mod.AuthError as e:
            print(f"[auth] could not create default admin: {e}",
                  file=sys.stderr)
            sys.exit(2)
        if supplied:
            print(f"[auth] created default admin {username!r} from "
                  f"ADMIN_PASSWORD")
        else:
            print("[auth] " + "=" * 60)
            print(f"[auth] created default admin user {username!r} with a "
                  f"generated password:")
            print(f"[auth]     {password}")
            print("[auth] Log in and change it now — it will not be shown "
                  "again.")
            print("[auth] " + "=" * 60)
        sys.stdout.flush()
    return manager


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

    auth_enabled = env_bool("AUTH_ENABLED", True)
    force_secure = env_bool("AUTH_FORCE_SECURE_COOKIE", False)
    auth_manager = setup_auth()

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
    httpd = webserver.serve(state, http_bind, http_port,
                            auth_manager=auth_manager,
                            auth_enabled=auth_enabled,
                            force_secure_cookie=force_secure)
    threading.Thread(target=httpd.serve_forever, name="web",
                     daemon=True).start()

    writer_died = False
    last_auth_prune = 0.0
    while not stop_event.is_set():
        stop_event.wait(1.0)
        if not writer_thread.is_alive() and not stop_event.is_set():
            print("[main] writer thread died unexpectedly — exiting",
                  file=sys.stderr)
            writer_died = True
            stop_event.set()
        # Periodically sweep expired sessions and stale login attempts.
        if auth_manager is not None:
            now = time.monotonic()
            if now - last_auth_prune >= 3600:
                try:
                    auth_manager.prune()
                except Exception as e:      # never let housekeeping kill main
                    print(f"[auth] prune error: {e}", file=sys.stderr)
                last_auth_prune = now

    print("[main] shutting down...")
    httpd.shutdown()
    writer_thread.join(timeout=20)
    if auth_manager is not None:
        auth_manager.close()
    print("[main] bye")
    if writer_died:
        sys.exit(1)


if __name__ == "__main__":
    main()
