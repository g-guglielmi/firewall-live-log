"""HTTP server: dashboard + live/history JSON API.  Read-only against the
DB (the writer thread is the sole writer)."""

import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import store

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "static")


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
    if port is not None and not port.isdigit():
        raise ValueError("port filter must be numeric")
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

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query)
        try:
            if path in ("/", "/index.html"):
                with open(os.path.join(_STATIC_DIR, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
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
                            + time.strftime("firewall-log-%Y%m%d-%H%M.csv") + '"'})
                return
            self._json({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:
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


def serve(state, bind, port):
    Handler.state = state
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    print(f"[web] dashboard on http://{bind}:{port}")
    return httpd
