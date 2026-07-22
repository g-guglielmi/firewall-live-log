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
import mailer as mailer_mod
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


MAX_RANGE_SEC = 366 * 86400          # widest custom range we'll accept


def _range_from(params, default_window):
    """Resolve the time window for a history query into (start_ts, end_ts).

    Either an explicit custom range (``from``/``to`` as epoch seconds, end
    optional) or one of the fixed ``window`` presets (seconds-ago up to now,
    end_ts None). Raises ValueError on bad input so the handler returns 400."""
    if "from" in params:
        start = int(params.get("from", ["0"])[0])
        to = params.get("to", [""])[0].strip()
        end = int(to) if to else None
        if start < 0 or (end is not None and end < 0):
            raise ValueError("from/to must be non-negative epoch seconds")
        if end is not None and end <= start:
            raise ValueError("'to' must be later than 'from'")
        if end is not None and end - start > MAX_RANGE_SEC:
            raise ValueError("custom range is too wide")
        return start, end
    window = _clamp(params, "window", default_window, 30 * 86400, lo=1)
    return int(time.time()) - window, None


def _filters_from(params):
    def one(key):
        v = params.get(key, [""])[0].strip()
        return v or None
    port = one("port")
    if port is not None:
        # Strip optional "!" (negate) then "=" (exact) before the digit check.
        p = port[1:] if port.startswith("!") else port
        p = p[1:] if p.startswith("=") else p
        if p == "":
            port = None                      # just a sigil so far — no filter
        elif not p.isdigit():
            raise ValueError("port filter must be numeric (optionally ! to "
                             "exclude, = for an exact match)")
    return {"device": one("device"), "vendor": one("vendor"),
            "ip": one("ip"), "src": one("src"), "dst": one("dst"),
            "rule": one("rule"), "proto": one("proto"), "port": port,
            "action": one("action")}


def _stats(state):
    def run(db):
        now = int(time.time())
        # Scan-free: per-device totals/last-seen come from the writer's
        # incrementally-maintained meta; only the current-rate query touches
        # the events table, and it's an indexed range over the last 60 s.
        dev_stats = json.loads(store.meta_get(db, "dev_stats", "{}"))
        # Force the ts index: left to itself the planner uses idx_events_dev
        # to skip the GROUP BY sort and then scans the *whole* table to apply
        # the ts filter (seconds on a multi-GB DB, every stats poll). INDEXED
        # BY makes it range-scan just the last 60 s and group those few rows.
        recent = {r[0]: r[1] for r in db.execute(
            "SELECT device, COUNT(*) FROM events INDEXED BY idx_events_ts "
            "WHERE ts >= ? GROUP BY device", (now - 60,))}
        # MIN and MAX in one SELECT can't both use the ts index, so SQLite
        # scans the whole table (seconds on a multi-GB DB, and it blocks the
        # shared read connection). Two scalar subqueries each do an O(log n)
        # index seek instead.
        span = db.execute("SELECT (SELECT MIN(ts) FROM events), "
                          "(SELECT MAX(ts) FROM events)").fetchone()
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
    mailer = None               # mailer.Mailer, or None
    public_url = None           # e.g. https://firewall.example.com

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
            if path == "/forgot":
                self._serve_html("forgot.html")
                return
            if path == "/reset":
                # The token travels in the query string and is read by the
                # page's JS; it is never interpolated into the HTML.
                self._serve_html("reset.html")
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
                idle_min = (self.auth.idle_sec // 60) if self.auth else 0
                max_hrs = (self.auth.max_ttl_sec / 3600) if self.auth else 0
                self._json({"user": {k: user.get(k) for k in
                                     ("id", "username", "role",
                                      "must_change_pw", "email")},
                            "csrf_token": authed[1],
                            "session": {"idle_minutes": idle_min,
                                        "max_hours": max_hrs}})
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
                    start_ts, end_ts = _range_from(params, 3600)
                    limit = _clamp(params, "limit", 1000, 5000, lo=1)
                    before = int(params.get("before", ["0"])[0])
                    filters = _filters_from(params)
                except ValueError as e:
                    self._json({"error": str(e)}, 400)
                    return
                events = self.state.query(
                    lambda db: store.query_range(db, start_ts, end_ts, filters,
                                                 limit, before=before))
                self._json({"events": events})
                return
            if path == "/api/events.csv":
                try:
                    start_ts, end_ts = _range_from(params, 86400)
                    limit = _clamp(params, "limit", 100000, 500000, lo=1)
                    filters = _filters_from(params)
                except ValueError as e:
                    self._json({"error": str(e)}, 400)
                    return
                events = self.state.query(
                    lambda db: store.query_range(db, start_ts, end_ts, filters,
                                                 limit))
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
            if path == "/api/forgot_password":
                self._handle_forgot_password()
                return
            if path == "/api/reset_password":
                self._handle_reset_password()
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
            if path == "/api/session/touch":
                # Sent by the client on real user activity to slide the idle
                # timeout. Background polling deliberately does NOT call this.
                if self.auth_enabled:
                    self.auth.touch_session(self._cookie_token())
                self._json({"ok": True})
                return
            if path == "/api/change_password":
                self._handle_change_password(user)
                return
            if path == "/api/users":
                self._handle_create_user(user)
                return
            if path == "/api/users/reset_password":
                self._handle_admin_reset_password(user)
                return
            if path == "/api/users/set_email":
                self._handle_set_email(user)
                return
            if path == "/api/users/set_role":
                self._handle_set_role(user)
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
                token, self.auth.max_ttl_sec))

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
            must_change_pw=bool(body.get("must_change_pw", False)),
            email=body.get("email"))
        self._json({"ok": True, "id": uid}, 201)

    def _handle_admin_reset_password(self, user):
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

    def _handle_set_email(self, user):
        body = self._read_json_body()
        target = body.get("id")
        if not isinstance(target, int):
            self._json({"error": "id must be an integer"}, 400)
            return
        # A user may set their own email; only an admin may set another's.
        if target != user["id"] and user["role"] != "admin":
            self._json({"error": "admin required"}, 403)
            return
        self.auth.set_email(target, body.get("email"))
        self._json({"ok": True})

    def _handle_set_role(self, user):
        if user["role"] != "admin":
            self._json({"error": "admin required"}, 403)
            return
        body = self._read_json_body()
        target = body.get("id")
        role = body.get("role")
        if not isinstance(target, int):
            self._json({"error": "id must be an integer"}, 400)
            return
        # Don't let an admin demote themselves mid-session and get locked out
        # of user management. set_role() also guards the last admin globally.
        if target == user["id"] and role != "admin":
            self._json({"error": "you can't change your own admin role"}, 400)
            return
        self.auth.set_role(target, role)
        self._json({"ok": True})

    # -- public self-service password reset --------------------------------
    def _handle_forgot_password(self):
        # Always answer the same way regardless of whether the account exists
        # or mail is configured — no account enumeration. Any real work
        # (lookup, rate-limit, send) happens on a background thread so
        # response timing can't be used to probe for valid accounts either.
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError):
            body = {}
        identifier = (body.get("username_or_email") or body.get("username")
                      or body.get("email") or "")
        ip = self._client_ip()
        if (self.auth_enabled and self.auth and self.mailer
                and self.mailer.configured and self.public_url
                and isinstance(identifier, str) and identifier.strip()):
            threading.Thread(target=self._process_forgot,
                             args=(identifier.strip(), ip),
                             daemon=True).start()
        elif self.auth_enabled and identifier and not (
                self.mailer and self.mailer.configured and self.public_url):
            print("[mail] password-reset requested but email/PUBLIC_URL is "
                  "not configured — no email sent", flush=True)
        self._json({"ok": True, "message": "If an account with that username "
                    "or email exists, a reset link has been sent."})

    def _process_forgot(self, identifier, ip):
        try:
            u = self.auth.find_user_for_reset(identifier)
            if not u:
                print(f"[mail] reset requested for unknown account "
                      f"{identifier!r} — nothing sent", flush=True)
                return
            if not u.get("email"):
                print(f"[mail] reset requested for user {u['username']!r} "
                      f"but no email is on file — nothing sent", flush=True)
                return
            per_user, per_ip = self.auth.recent_reset_count(u["id"], ip)
            if (per_user >= auth_mod.RESET_MAX_PER_USER
                    or per_ip >= auth_mod.RESET_MAX_PER_IP):
                print(f"[mail] reset rate-limited for user {u['username']!r}",
                      flush=True)
                return
            token = self.auth.create_reset_token(u["id"], ip)
            url = f"{self.public_url}/reset?token={token}"
            ok = self.mailer.send(
                u["email"], "Reset your firewall-live-log password",
                mailer_mod.reset_email_body(
                    u["username"], url, auth_mod.RESET_TTL_SEC // 60))
            if ok:
                print(f"[mail] reset email sent to {u['email']!r} for user "
                      f"{u['username']!r}", flush=True)
            else:
                print(f"[mail] reset email FAILED to send to {u['email']!r} "
                      f"(see the [mail] send error above)", flush=True)
        except Exception as e:                     # never crash the thread
            print(f"[mail] forgot-password processing error: "
                  f"{type(e).__name__}: {e}", flush=True)

    def _handle_reset_password(self):
        if not self.auth_enabled or not self.auth:
            self._json({"error": "authentication is disabled"}, 400)
            return
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "invalid request body"}, 400)
            return
        self.auth.reset_password_with_token(
            body.get("token", ""), body.get("new_password", ""))
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
          force_secure_cookie=False, mailer=None, public_url=None):
    Handler.state = state
    Handler.auth = auth_manager
    Handler.auth_enabled = auth_enabled
    Handler.force_secure_cookie = force_secure_cookie
    Handler.mailer = mailer
    Handler.public_url = public_url
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    mode = "enabled" if auth_enabled else "DISABLED"
    reset = "on" if (mailer and mailer.configured and public_url) else "off"
    print(f"[web] dashboard on http://{bind}:{port} "
          f"(auth {mode}, email reset {reset})")
    return httpd
