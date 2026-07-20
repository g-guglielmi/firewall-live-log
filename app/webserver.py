"""HTTP server: dashboard + live/history JSON API, gated by session auth.

Read-only against the events DB (the writer thread is the sole writer);
user/session state lives in a separate auth DB owned by ``auth.AuthManager``.

Auth model: a login sets an HttpOnly, SameSite=Strict session cookie whose
token is stored only as a hash. Every route except the login page, the
favicon, and ``POST /api/login`` requires a valid session. State-changing
requests additionally require a session-bound CSRF token in the
``X-CSRF-Token`` header. Setting ``AUTH_ENABLED=false`` disables the gate
for deployments that already sit behind an authenticating reverse proxy.
"""

import http.cookies
import json
import os
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth as auth_mod
import store

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "static")
_MAX_BODY = 64 * 1024


class AppState:
    def __init__(self, db_path, devices, cfg):
        self.db_path = db_path
        self.devices = devices          # list of config.Device
        self.cfg = cfg
        self.lock = threading.Lock()
        self._db = None

    def _db_ro(self):
        if self._db is None:
            self._db = store.open_reader(self.db_path)
        return self._db

    def query(self, fn):
        with self.lock:
            return fn(self._db_ro())


def _clamp(params, key, default, hi, lo=1):
    """Parse an int query param, clamped to [lo, hi]. Raises ValueError on
    non-integer input so the handler can return 400 (never a negative limit,
    which SQLite would treat as unbounded)."""
    return max(lo, min(int(params.get(key, [str(default)])[0]), hi))


def _filters_from(params):
    def one(key):
        v = params.get(key, [""])[0].strip()
        return v or None
    port = one("port")
    if port is not None and not (port[1:] if port.startswith("=")
                                 else port).isdigit():
        raise ValueError("port filter must be numeric "
                         "(optionally prefixed with = for exact match)")
    return {"device": one("device"), "vendor": one("vendor"),
            "ip": one("ip"), "port": port, "action": one("action")}


def _stats(state):
    def run(db):
        now = int(time.time())
        # Scan-free: per-device totals/last-seen come from the writer's
        # incrementally-maintained meta; only the current-rate query touches
        # the events table, and it's an indexed range over the last 60 s.
        dev_stats = json.loads(store.meta_get(db, "dev_stats", "{}"))
        recent = {r[0]: r[1] for r in db.execute(
            "SELECT device, COUNT(*) FROM events WHERE ts >= ? GROUP BY device",
            (now - 60,))}
        span = db.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        unparsed = db.execute("SELECT COUNT(*) FROM unparsed").fetchone()[0]
        devices = []
        for d in state.devices:
            ds = dev_stats.get(d.name, {})
            devices.append({**d.as_dict(),
                            "events": ds.get("total", 0),
                            "last_seen": ds.get("last_seen"),
                            "events_last_min": recent.get(d.name, 0)})
        return {
            "events_last_min": sum(recent.values()),
            "oldest": span[0], "newest": span[1],
            "retention_days": state.cfg.retention_days,
            "max_events": state.cfg.max_events,
            "unparsed": unparsed,
            "parsed": int(store.meta_get(db, "stat_parsed", "0")),
            "dropped": int(store.meta_get(db, "stat_dropped", "0")),
            "devices": devices,
            "now": now,
        }
    return state.query(run)


class Handler(BaseHTTPRequestHandler):
    server_version = "firewall-live-log"
    state = None
    auth = None                 # auth.AuthManager, or None when disabled
    auth_enabled = True
    force_secure_cookie = False

    def log_message(self, *a):
        pass

    # -- response helpers --------------------------------------------------
    def _security_headers(self, nonce=None):
        h = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
        if nonce is not None:
            h["Content-Security-Policy"] = (
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; "
                "style-src 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        else:
            h["Content-Security-Policy"] = (
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return h

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              headers=None, csp_nonce=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        headers = dict(headers or {})
        for k, v in self._security_headers(csp_nonce).items():
            headers.setdefault(k, v)
        if "Cache-Control" not in headers:
            self.send_header("Cache-Control", "no-store")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj), headers=headers)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        for k, v in self._security_headers().items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve_html(self, filename):
        # Fixed filename only — never derived from the request path, so no
        # path traversal is possible.
        nonce = secrets.token_urlsafe(16)
        with open(os.path.join(_STATIC_DIR, filename), "r",
                  encoding="utf-8") as f:
            html = f.read()
        html = html.replace("<script>", f'<script nonce="{nonce}">')
        html = html.replace("__CSP_NONCE__", nonce)
        self._send(200, html, "text/html; charset=utf-8", csp_nonce=nonce)

    # -- auth helpers ------------------------------------------------------
    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()[:64]
        return self.client_address[0]

    def _cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        c = jar.get("session")
        return c.value if c else None

    def current_user(self):
        """Return (user, csrf) for a valid session, else None. When auth is
        disabled every request is treated as an admin."""
        if not self.auth_enabled:
            return ({"id": 0, "username": "auth-disabled", "role": "admin",
                     "must_change_pw": False}, "")
        if getattr(self, "_user_cache", "unset") != "unset":
            return self._user_cache
        result = self.auth.get_session(self._cookie_token())
        self._user_cache = result
        return result

    def _cookie_secure(self):
        return (self.force_secure_cookie
                or self.headers.get("X-Forwarded-Proto", "").lower() == "https")

    def _set_session_cookie(self, token, max_age):
        parts = [f"session={token}", "Path=/", "HttpOnly", "SameSite=Strict",
                 f"Max-Age={max_age}"]
        if self._cookie_secure():
            parts.append("Secure")
        return {"Set-Cookie": "; ".join(parts)}

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("bad Content-Length")
        if length < 0 or length > _MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        if raw and "application/x-www-form-urlencoded" in ctype:
            return {k: v[0] for k, v in
                    urllib.parse.parse_qs(raw.decode("utf-8")).items()}
        if not raw:
            return {}
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("body must be a JSON object")
        return obj

    def _check_csrf(self, csrf):
        got = self.headers.get("X-CSRF-Token", "")
        return bool(csrf) and secrets.compare_digest(got, csrf)

    # -- GET ---------------------------------------------------------------
    def do_GET(self):
        self._user_cache = "unset"
        path, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query)
        try:
            # Public routes (no session required).
            if path == "/healthz":
                self._json({"status": "ok"})
                return
            if path == "/login":
                if self.current_user():
                    self._redirect("/")
                else:
                    self._serve_html("login.html")
                return
            if path in ("/favicon.ico", "/favicon.png"):
                with open(os.path.join(_STATIC_DIR, "favicon.png"), "rb") as f:
                    self._send(200, f.read(), "image/png",
                               {"Cache-Control": "public, max-age=86400"})
                return

            authed = self.current_user()
            if not authed:
                if path.startswith("/api/"):
                    self._json({"error": "authentication required"}, 401)
                else:
                    self._redirect("/login")
                return
            user = authed[0]

            if path in ("/", "/index.html"):
                self._serve_html("index.html")
                return
            if path == "/api/me":
                self._json({"user": {k: user[k] for k in
                                     ("id", "username", "role",
                                      "must_change_pw")},
                            "csrf_token": authed[1]})
                return
            if path == "/api/users":
                if user["role"] != "admin":
                    self._json({"error": "admin required"}, 403)
                    return
                self._json({"users": self.auth.list_users()})
                return
            if path == "/api/stats":
                self._json(_stats(self.state))
                return
            if path == "/api/devices":
                self._json([d.as_dict() for d in self.state.devices])
                return
            if path == "/api/live":
                try:
                    since = int(params.get("since", ["0"])[0])
                    limit = _clamp(params, "limit", 500, 2000, lo=1)
                    filters = _filters_from(params)
                except ValueError as e:
                    self._json({"error": str(e)}, 400)
                    return
                cursor, events = self.state.query(
                    lambda db: store.query_live(db, since, filters, limit))
                self._json({"cursor": cursor, "events": events})
                return
            if path == "/api/events":
                try:
                    window = _clamp(params, "window", 3600, 30 * 86400, lo=1)
                    limit = _clamp(params, "limit", 1000, 5000, lo=1)
                    filters = _filters_from(params)
                except ValueError as e:
                    self._json({"error": str(e)}, 400)
                    return
                events = self.state.query(
                    lambda db: store.query_window(db, window, filters, limit))
                self._json({"events": events})
                return
            if path == "/api/events.csv":
                try:
                    window = _clamp(params, "window", 86400, 30 * 86400, lo=1)
                    limit = _clamp(params, "limit", 100000, 500000, lo=1)
                    filters = _filters_from(params)
                except ValueError as e:
                    self._json({"error": str(e)}, 400)
                    return
                events = self.state.query(
                    lambda db: store.query_window(db, window, filters, limit))
                self._send(200, _to_csv(events), "text/csv; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="'
                            + time.strftime("firewall-log-%Y%m%d-%H%M.csv")
                            + '"'})
                return
            self._json({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:
            self._safe_500(e)

    # -- POST --------------------------------------------------------------
    def do_POST(self):
        self._user_cache = "unset"
        path = self.path.partition("?")[0]
        try:
            if path == "/api/login":
                self._handle_login()
                return

            authed = self.current_user()
            if not authed:
                self._json({"error": "authentication required"}, 401)
                return
            user, csrf = authed
            if self.auth_enabled and not self._check_csrf(csrf):
                self._json({"error": "invalid or missing CSRF token"}, 403)
                return

            if path == "/api/logout":
                if self.auth_enabled:
                    self.auth.delete_session(self._cookie_token())
                self._json({"ok": True},
                           headers=self._set_session_cookie("", 0))
                return
            if path == "/api/change_password":
                self._handle_change_password(user)
                return
            if path == "/api/users":
                self._handle_create_user(user)
                return
            if path == "/api/users/reset_password":
                self._handle_reset_password(user)
                return
            self._json({"error": "not found"}, 404)
        except auth_mod.AuthError as e:
            self._json({"error": str(e)}, e.code)
        except ValueError as e:
            self._json({"error": str(e)}, 400)
        except BrokenPipeError:
            pass
        except Exception as e:
            self._safe_500(e)

    # -- DELETE ------------------------------------------------------------
    def do_DELETE(self):
        self._user_cache = "unset"
        path = self.path.partition("?")[0]
        try:
            authed = self.current_user()
            if not authed:
                self._json({"error": "authentication required"}, 401)
                return
            user, csrf = authed
            if self.auth_enabled and not self._check_csrf(csrf):
                self._json({"error": "invalid or missing CSRF token"}, 403)
                return
            prefix = "/api/users/"
            if path.startswith(prefix):
                if user["role"] != "admin":
                    self._json({"error": "admin required"}, 403)
                    return
                tail = path[len(prefix):]
                if not tail.isdigit():
                    self._json({"error": "user id must be numeric"}, 400)
                    return
                target = int(tail)
                if target == user["id"]:
                    self._json({"error": "cannot delete your own account"},
                               400)
                    return
                self.auth.delete_user(target)
                self._json({"ok": True})
                return
            self._json({"error": "not found"}, 404)
        except auth_mod.AuthError as e:
            self._json({"error": str(e)}, e.code)
        except BrokenPipeError:
            pass
        except Exception as e:
            self._safe_500(e)

    # -- POST handlers -----------------------------------------------------
    def _handle_login(self):
        if not self.auth_enabled:
            self._json({"ok": True, "user": {"username": "auth-disabled",
                                             "role": "admin"}})
            return
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "invalid request body"}, 400)
            return
        username = body.get("username", "")
        password = body.get("password", "")
        user, err, retry = self.auth.verify_login(
            username, password, self._client_ip())
        if user is None:
            headers = {"Retry-After": str(retry)} if retry else None
            self._json({"error": err}, 429 if retry else 401, headers=headers)
            return
        token, csrf, expires = self.auth.create_session(user["id"])
        self._json(
            {"ok": True, "csrf_token": csrf,
             "user": {"id": user["id"], "username": user["username"],
                      "role": user["role"],
                      "must_change_pw": user["must_change_pw"]}},
            headers=self._set_session_cookie(
                token, auth_mod.SESSION_TTL_SEC))

    def _handle_change_password(self, user):
        body = self._read_json_body()
        current = body.get("current_password", "")
        new = body.get("new_password", "")
        full = self.auth.get_user_by_id(user["id"])
        if not full or not auth_mod.verify_password(current, full["_pw_hash"]):
            self._json({"error": "current password is incorrect"}, 403)
            return
        if current == new:
            self._json({"error": "new password must differ from the current "
                        "one"}, 400)
            return
        # Revokes other sessions; the client re-logs in afterwards.
        self.auth.set_password(user["id"], new, must_change_pw=False)
        self._json({"ok": True})

    def _handle_create_user(self, user):
        if user["role"] != "admin":
            self._json({"error": "admin required"}, 403)
            return
        body = self._read_json_body()
        uid = self.auth.create_user(
            body.get("username", ""), body.get("password", ""),
            role=body.get("role", "user"),
            must_change_pw=bool(body.get("must_change_pw", False)))
        self._json({"ok": True, "id": uid}, 201)

    def _handle_reset_password(self, user):
        if user["role"] != "admin":
            self._json({"error": "admin required"}, 403)
            return
        body = self._read_json_body()
        target = body.get("id")
        new = body.get("new_password", "")
        if not isinstance(target, int):
            self._json({"error": "id must be an integer"}, 400)
            return
        self.auth.set_password(target, new, must_change_pw=True)
        self._json({"ok": True})

    def _safe_500(self, e):
        try:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        except Exception:
            pass


def _to_csv(events):
    import csv
    import io
    buf = io.StringIO()
    cols = ["ts", "device", "vendor", "src", "dst", "proto", "dst_port",
            "action", "rule"]
    w = csv.writer(buf)
    w.writerow(["time"] + cols[1:])
    for e in events:
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(e["ts"]))]
                   + [e[c] for c in cols[1:]])
    return buf.getvalue()


def serve(state, bind, port, auth_manager=None, auth_enabled=True,
          force_secure_cookie=False):
    Handler.state = state
    Handler.auth = auth_manager
    Handler.auth_enabled = auth_enabled
    Handler.force_secure_cookie = force_secure_cookie
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    mode = "enabled" if auth_enabled else "DISABLED"
    print(f"[web] dashboard on http://{bind}:{port} (auth {mode})")
    return httpd
