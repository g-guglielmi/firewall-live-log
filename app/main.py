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
import re
import secrets
import signal
import sys
import threading
import time

import auth as auth_mod
import config
import listener
import mailer as mailer_mod
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


def _admin_password():
    """Return (password, supplied). Uses ADMIN_PASSWORD if set, otherwise a
    strong generated one the caller should print."""
    supplied = env("ADMIN_PASSWORD")
    return (supplied or secrets.token_urlsafe(18)), bool(supplied)


def _print_generated_password(action, username, password):
    print("[auth] " + "=" * 60)
    print(f"[auth] {action} {username!r} with a generated password:")
    print(f"[auth]     {password}")
    print("[auth] Log in and change it now — it will not be shown again.")
    print("[auth] " + "=" * 60)


def _bootstrap_admin(manager):
    username = env("ADMIN_USERNAME", "admin")
    password, supplied = _admin_password()
    try:
        manager.create_user(username, password, role="admin",
                            must_change_pw=not supplied,
                            email=env("ADMIN_EMAIL"))
    except auth_mod.AuthError as e:
        print(f"[auth] could not create default admin: {e}", file=sys.stderr)
        sys.exit(2)
    if supplied:
        print(f"[auth] created default admin {username!r} from ADMIN_PASSWORD")
    else:
        _print_generated_password("created default admin user", username,
                                  password)
    sys.stdout.flush()


def _reset_admin(manager):
    """ADMIN_RESET recovery: (re)set the admin account even when users exist,
    clearing any lockout and revoking its sessions. Used to recover a
    forgotten admin password without another account."""
    username = env("ADMIN_USERNAME", "admin")
    password, supplied = _admin_password()
    admin_email = env("ADMIN_EMAIL")
    existing = manager.get_user_by_name(username)
    try:
        if existing:
            manager.set_password(existing["id"], password,
                                must_change_pw=not supplied)
            manager.set_role(existing["id"], "admin")
            if admin_email:
                manager.set_email(existing["id"], admin_email)
            action = "reset password for admin"
        else:
            manager.create_user(username, password, role="admin",
                                must_change_pw=not supplied, email=admin_email)
            action = "created admin"
        manager.clear_lockout(username)
    except auth_mod.AuthError as e:
        print(f"[auth] ADMIN_RESET failed: {e}", file=sys.stderr)
        sys.exit(2)
    if supplied:
        print(f"[auth] ADMIN_RESET: {action} {username!r} from ADMIN_PASSWORD")
    else:
        _print_generated_password(f"ADMIN_RESET: {action}", username, password)
    print("[auth] IMPORTANT: unset ADMIN_RESET now, or it re-runs on every "
          "restart.")
    sys.stdout.flush()


def normalize_public_url(url):
    """Return a clean base URL (scheme + host, no trailing slash) for building
    email links, or None. Accepts a bare FQDN (assumes https)."""
    if not url:
        return None
    url = url.strip().rstrip("/")
    if not url:
        return None
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def setup_auth():
    """Open the auth DB and bootstrap or reset the admin as needed.

    Returns the AuthManager (or None when auth is disabled)."""
    if not env_bool("AUTH_ENABLED", True):
        print("[auth] AUTH_ENABLED=false — dashboard is UNPROTECTED; only do "
              "this behind an authenticating reverse proxy", file=sys.stderr)
        return None

    auth_db = env("AUTH_DB_PATH", "/data/auth.db")
    os.makedirs(os.path.dirname(auth_db) or ".", exist_ok=True)
    manager = auth_mod.AuthManager(auth_db)

    if env_bool("ADMIN_RESET", False):
        _reset_admin(manager)
    elif manager.user_count() == 0:
        _bootstrap_admin(manager)
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
    mailer = mailer_mod.from_env(env)
    public_url = normalize_public_url(env("PUBLIC_URL"))
    if auth_manager is not None:
        if mailer.configured and public_url:
            print(f"[mail] password-reset email enabled (links via "
                  f"{public_url})")
        elif mailer.configured and not public_url:
            print("[mail] SMTP configured but PUBLIC_URL is not set — reset "
                  "links can't be built, so reset email stays off",
                  file=sys.stderr)

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
                            force_secure_cookie=force_secure,
                            mailer=mailer, public_url=public_url)
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
