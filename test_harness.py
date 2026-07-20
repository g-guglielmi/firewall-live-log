#!/usr/bin/env python3
"""End-to-end synthetic test for firewall-live-log.

Boots the real app with a throwaway config + DB, feeds synthetic UniFi
and Sophos syslog to separate device ports (plus an auto-detect port),
and asserts on the HTTP API, CSV export, retention pruning, and a
graceful-stop final flush.

Runs on Linux/macOS (SIGTERM) and Windows (CTRL_BREAK):

    docker run --rm ghcr.io/g-guglielmi/firewall-live-log:latest \
      python3 /app/test_harness.py

Exit code 0 = all checks pass.  Loopback only.
"""

import http.cookiejar
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

IS_WIN = os.name == "nt"
HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "app", "main.py")
if not os.path.exists(MAIN):
    MAIN = os.path.join(HERE, "main.py")

P_UNIFI, P_SOPHOS, P_AUTO = 15514, 15515, 15516
HTTP_PORT = 18099
BASE = f"http://127.0.0.1:{HTTP_PORT}"

ADMIN_USER = "admin"
ADMIN_PASS = "harness-Admin-Pass-9271!"   # >= 12 chars for the policy

# A cookie-jar opener carries the session cookie across authenticated calls.
_CJ = http.cookiejar.CookieJar()
_OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_CJ))
_CSRF = {"token": ""}


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    """Return 3xx/4xx responses verbatim instead of following/raising, so a
    redirect can be inspected."""

    def http_response(self, request, response):
        return response

    https_response = http_response


def request(method, path, obj=None, csrf=False):
    """Return (status_code, parsed_json_or_{}, response). Never raises on a
    non-2xx status — HTTPError is unwrapped so checks can inspect the code."""
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        req.add_header("X-CSRF-Token", _CSRF["token"])
    try:
        r = _OPENER.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        r = e
    body = r.read()
    try:
        parsed = json.loads(body) if body else {}
    except ValueError:
        parsed = {}
    return r.status if hasattr(r, "status") else r.code, parsed, r

DEVICES = {
    "retention_days": 14,
    "max_events": 0,
    "devices": [
        {"name": "UDM-Test", "port": P_UNIFI, "vendor": "unifi"},
        {"name": "Sophos-Test", "port": P_SOPHOS, "vendor": "sophos"},
        {"name": "Mixed-Auto", "port": P_AUTO, "vendor": "auto"},
    ],
}

checks = {"pass": 0, "fail": 0}


def check(name, cond, detail=""):
    if cond:
        checks["pass"] += 1
        print(f"  PASS  {name}")
    else:
        checks["fail"] += 1
        print(f"  FAIL  {name}  {detail}")


def get_json(path):
    with _OPENER.open(urllib.request.Request(BASE + path), timeout=10) as r:
        return json.loads(r.read())


def unifi_line(tag, descr, src, dst, proto, dpt=None):
    parts = ["<4>Jul 18 12:00:00 UDM kernel:", f"[{tag}]", f'DESCR="{descr}"',
             f"IN=br0 OUT=eth0 SRC={src} DST={dst} TTL=63 PROTO={proto}"]
    if dpt is not None:
        parts.append(f"SPT=40000 DPT={dpt}")
    return " ".join(parts).encode()


def sophos_line(subtype, rule, src, dst, proto, dpt=None):
    parts = ['device="SFW" date=2025-06-01 time=10:15:30 timezone="CEST"',
             'device_name="XGS2100" log_type="Firewall"',
             'log_component="Firewall Rule"', f'log_subtype="{subtype}"',
             f'fw_rule_id=5 fw_rule_name="{rule}"',
             f"src_ip={src} dst_ip={dst}", f'protocol="{proto}"']
    if dpt is not None:
        parts.append(f"src_port=51000 dst_port={dpt}")
    return " ".join(parts).encode()


def read_stdout(proc, lines):
    for l in proc.stdout:
        lines.append(l.rstrip("\n"))


def main():
    tmp = tempfile.mkdtemp(prefix="fll-test-")
    db_path = os.path.join(tmp, "events.db")
    cfg_path = os.path.join(tmp, "devices.json")
    with open(cfg_path, "w") as f:
        json.dump(DEVICES, f)

    env = dict(os.environ, DEVICES_CONFIG=cfg_path, DB_PATH=db_path,
               HTTP_PORT=str(HTTP_PORT), HTTP_BIND="127.0.0.1",
               PRUNE_INTERVAL_SEC="2", RETENTION_DAYS="14",
               AUTH_DB_PATH=os.path.join(tmp, "auth.db"),
               AUTH_ENABLED="true", ADMIN_USERNAME=ADMIN_USER,
               ADMIN_PASSWORD=ADMIN_PASS)

    print("== startup ==")
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WIN else 0
    proc = subprocess.Popen([sys.executable, "-u", MAIN],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env, creationflags=creationflags)
    out = []
    threading.Thread(target=read_stdout, args=(proc, out), daemon=True).start()

    up = False
    deadline = time.time() + 15
    while time.time() < deadline and proc.poll() is None:
        try:
            # /healthz is public — reachable before login.
            urllib.request.urlopen(BASE + "/healthz", timeout=4).read()
            up = True
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.3)
    check("app started, http answering", up, "\n".join(out[:12]))
    if not up:
        proc.kill()
        sys.exit(1)

    print("== auth gate ==")
    code, _, _ = request("GET", "/api/stats")
    check("api requires auth before login (401)", code == 401, str(code))
    code, _, _ = request("GET", "/api/devices")
    check("devices requires auth (401)", code == 401, str(code))
    # index redirects unauthenticated browsers to /login (302, no body leak).
    noredir = urllib.request.build_opener(_NoRedirect())
    try:
        rr = noredir.open(urllib.request.Request(BASE + "/"), timeout=10)
        icode, iloc = rr.status, rr.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        icode, iloc = e.code, e.headers.get("Location", "")
    check("index redirects to /login when unauthenticated",
          icode == 302 and iloc == "/login", f"{icode} {iloc}")

    # SQL-injection / auth-bypass attempt in the username must NOT log in.
    code, _, _ = request("POST", "/api/login",
                         {"username": "admin' OR '1'='1", "password": "x"})
    check("sql-injection login attempt rejected (not 200)", code != 200,
          str(code))

    # Wrong password before the real login.
    code, _, _ = request("POST", "/api/login",
                         {"username": ADMIN_USER, "password": "wrong-pass-xx"})
    check("wrong password -> 401", code == 401, str(code))

    print("== login ==")
    code, body, _ = request("POST", "/api/login",
                           {"username": ADMIN_USER, "password": ADMIN_PASS})
    check("admin login succeeds", code == 200 and body.get("ok"), str(body))
    _CSRF["token"] = body.get("csrf_token", "")
    check("login returns csrf token", bool(_CSRF["token"]))
    check("admin role reported", body.get("user", {}).get("role") == "admin",
          str(body.get("user")))
    code, me, _ = request("GET", "/api/me")
    check("/api/me after login", code == 200
          and me.get("user", {}).get("username") == ADMIN_USER, str(me))
    check("admin from ADMIN_PASSWORD is not forced to change pw",
          me.get("user", {}).get("must_change_pw") is False, str(me))

    check("3 devices reported", len(get_json("/api/devices")) == 3)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = lambda pkt, port: s.sendto(pkt, ("127.0.0.1", port))

    print("== synthetic traffic ==")
    for _ in range(20):
        send(unifi_line("LAN_IN-A-2001", "Allow LAN web",
                        "10.0.10.5", "93.184.216.34", "TCP", 443), P_UNIFI)
    for _ in range(8):
        send(unifi_line("GUEST_IN-D-4001", "Guest isolation",
                        "10.31.0.9", "10.0.20.5", "TCP", 445), P_UNIFI)
    for _ in range(3):
        send(unifi_line("LAN_IN-A-2005", "Allow ping",
                        "10.0.10.5", "10.0.20.5", "ICMP"), P_UNIFI)
    # DNAT / port-forward: no filter verdict in the tag -> classified NAT.
    for _ in range(5):
        send(unifi_line("WAN_LOCAL", "PortForward DNAT [qBittorrent]",
                        "203.0.113.7", "10.0.10.9", "UDP", 49908), P_UNIFI)
    for _ in range(15):
        send(sophos_line("Allowed", "LAN-to-WAN",
                         "192.168.10.20", "8.8.8.8", "TCP", 443), P_SOPHOS)
    for _ in range(6):
        send(sophos_line("Denied", "Drop-RDP",
                         "192.168.10.55", "10.9.9.9", "TCP", 3389), P_SOPHOS)
    for _ in range(4):
        send(sophos_line("Dropped", "Drop-ICMP",
                         "1.2.3.4", "192.168.10.1", "ICMP"), P_SOPHOS)
    # Auto-detect port: one of each vendor.
    send(unifi_line("LAN_IN-A-2001", "auto unifi",
                    "172.16.0.2", "172.16.0.3", "UDP", 53), P_AUTO)
    send(sophos_line("Allowed", "auto sophos",
                     "172.16.0.4", "172.16.0.5", "UDP", 123), P_AUTO)
    # Unparseable
    send(b"this is not a firewall log", P_AUTO)

    time.sleep(2.5)  # past a flush

    print("== live api ==")
    live = get_json("/api/live?since=0&limit=2000")
    evs = live["events"]
    # 36 UDM-Test + 25 Sophos-Test + 2 Mixed-Auto (1 unifi + 1 sophos) = 63.
    check("events stored and returned", len(evs) == 63, str(len(evs)))
    by = lambda **kw: [e for e in evs if all(e[k] == v for k, v in kw.items())]

    check("unifi allow parsed",
          len(by(device="UDM-Test", action="Allow", dst_port=443)) == 20)
    check("unifi guest drop -> Drop",
          len(by(device="UDM-Test", action="Drop", dst_port=445)) == 8)
    check("unifi ICMP -> port -1",
          len(by(device="UDM-Test", proto="ICMP", dst_port=-1)) == 3)
    check("unifi DNAT/port-forward -> NAT",
          len(by(device="UDM-Test", action="NAT", dst_port=49908)) == 5)
    check("sophos Allowed -> Allow",
          len(by(device="Sophos-Test", action="Allow", dst_port=443)) == 15)
    check("sophos Denied -> Block",
          len(by(device="Sophos-Test", action="Block", dst_port=3389)) == 6)
    check("sophos Dropped ICMP -> Drop, port -1",
          len(by(device="Sophos-Test", action="Drop", proto="ICMP",
                 dst_port=-1)) == 4)
    check("sophos rule name captured",
          any(e["rule"] == "Drop-RDP" for e in evs))
    check("auto-detect: unifi on mixed port",
          len(by(device="Mixed-Auto", vendor="unifi")) == 1)
    check("auto-detect: sophos on mixed port",
          len(by(device="Mixed-Auto", vendor="sophos")) == 1)

    print("== filters ==")
    f = get_json("/api/live?since=0&vendor=sophos")
    # 25 on Sophos-Test + 1 auto-detected on Mixed-Auto = 26.
    check("vendor filter", all(e["vendor"] == "sophos" for e in f["events"])
          and len(f["events"]) == 26, str(len(f["events"])))
    f = get_json("/api/live?since=0&action=blocked")
    check("blocked filter", all(e["action"] in ("Block", "Drop", "Reject")
          for e in f["events"]) and len(f["events"]) == 18, str(len(f["events"])))
    f = get_json("/api/live?since=0&action=NAT")
    check("nat filter", all(e["action"] == "NAT" for e in f["events"])
          and len(f["events"]) == 5, str(len(f["events"])))
    f = get_json("/api/live?since=0&port=3389")
    check("port filter", all(e["dst_port"] == 3389 for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&port=44")
    check("port prefix filter",
          all(str(e["dst_port"]).startswith("44") for e in f["events"])
          and len(f["events"]) == 43, str(len(f["events"])))
    f = get_json("/api/live?since=0&port=%3D443")   # "=443" -> exact
    check("port exact filter (=)",
          all(e["dst_port"] == 443 for e in f["events"])
          and len(f["events"]) == 35, str(len(f["events"])))
    code, _, _ = request("GET", "/api/live?since=0&port=44x")
    check("non-numeric port filter -> 400", code == 400, str(code))
    f = get_json("/api/live?since=0&ip=192.168.10.55")
    check("ip filter (src/dst substring)",
          all("192.168.10.55" in (e["src"], e["dst"]) for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&device=UDM-Test")
    check("device filter",
          all(e["device"] == "UDM-Test" for e in f["events"])
          and len(f["events"]) == 36, str(len(f["events"])))

    print("== incremental cursor ==")
    tail = get_json(f"/api/live?since={live['cursor']}")
    check("no new events after cursor",
          tail["events"] == [] and tail["cursor"] == live["cursor"], str(tail))

    print("== stats + per-device health + csv + unparsed ==")
    st = get_json("/api/stats")
    check("stats parsed = 63 (lifetime)", st["parsed"] == 63, str(st["parsed"]))
    check("stats unparsed = 1", st["unparsed"] == 1, str(st["unparsed"]))
    dmap = {d["name"]: d for d in st["devices"]}
    check("per-device totals from meta (scan-free)",
          dmap["UDM-Test"]["events"] == 36
          and dmap["Sophos-Test"]["events"] == 25
          and dmap["Mixed-Auto"]["events"] == 2,
          str({k: v["events"] for k, v in dmap.items()}))
    check("per-device last_seen populated",
          all(dmap[n]["last_seen"] for n in dmap), str(dmap))
    check("all 3 devices seen this minute",
          sum(1 for d in st["devices"] if d["events_last_min"] > 0) == 3,
          str({k: v["events_last_min"] for k, v in dmap.items()}))
    with _OPENER.open(urllib.request.Request(
            BASE + "/api/events.csv?window=86400"), timeout=10) as r:
        csv_text = r.read().decode()
        disp = r.headers.get("Content-Disposition", "")
    check("csv export", "attachment" in disp
          and csv_text.startswith("time,device,vendor,")
          and "Drop-RDP" in csv_text, disp)
    for fav in ("/favicon.ico", "/favicon.png"):
        with _OPENER.open(urllib.request.Request(BASE + fav), timeout=10) as r:
            body = r.read()
            check(f"favicon at {fav}",
                  r.headers.get("Content-Type") == "image/png"
                  and body.startswith(b"\x89PNG")
                  and "max-age" in r.headers.get("Cache-Control", ""),
                  str(r.headers.get("Content-Type")))

    print("== security headers + csp nonce ==")
    _, _, r = request("GET", "/api/me")
    hh = r.headers
    check("X-Content-Type-Options: nosniff",
          hh.get("X-Content-Type-Options") == "nosniff")
    check("X-Frame-Options: DENY", hh.get("X-Frame-Options") == "DENY")
    check("CSP header present", bool(hh.get("Content-Security-Policy")))
    with _OPENER.open(urllib.request.Request(BASE + "/"), timeout=10) as ir:
        html = ir.read().decode()
        csp = ir.headers.get("Content-Security-Policy", "")
    check("index CSP uses a script nonce",
          "script-src 'nonce-" in csp and 'nonce="' in html, csp[:80])

    print("== user management ==")
    code, body, _ = request("POST", "/api/users",
                           {"username": "viewer1", "password": "ViewerPass123",
                            "role": "user"}, csrf=True)
    check("admin creates a user (201)", code == 201, f"{code} {body}")
    code, _, _ = request("POST", "/api/users",
                        {"username": "viewer1", "password": "ViewerPass123"},
                        csrf=True)
    check("duplicate username rejected (409)", code == 409, str(code))
    code, _, _ = request("POST", "/api/users",
                        {"username": "weakpw", "password": "short"}, csrf=True)
    check("weak password rejected (400)", code == 400, str(code))
    code, _, _ = request("POST", "/api/users",
                        {"username": "nocsrf", "password": "GoodPass12345"},
                        csrf=False)
    check("create without CSRF token rejected (403)", code == 403, str(code))

    # A brand-new opener logs in as the non-admin user.
    cj2 = http.cookiejar.CookieJar()
    op2 = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj2))

    def op2_json(path, obj, method="POST", csrf=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-CSRF-Token", csrf)
        try:
            resp = op2.open(req, timeout=10)
        except urllib.error.HTTPError as e:
            resp = e
        b = resp.read()
        return (resp.status if hasattr(resp, "status") else resp.code,
                json.loads(b) if b else {})

    code, lb = op2_json("/api/login",
                        {"username": "viewer1", "password": "ViewerPass123"})
    check("non-admin user can log in", code == 200 and lb.get("ok"), str(lb))
    v_csrf = lb.get("csrf_token", "")
    code, _ = op2_json("/api/users",
                       {"username": "x2", "password": "GoodPass12345"},
                       csrf=v_csrf)
    check("non-admin cannot create users (403)", code == 403, str(code))

    print("== rate limiting (5 fails / 15 min) ==")
    for i in range(5):
        code, _, _ = request("POST", "/api/login",
                            {"username": "nobody-x", "password": f"bad{i}"})
        check(f"failed attempt {i+1} -> 401", code == 401, str(code))
    code, _, resp = request("POST", "/api/login",
                          {"username": "nobody-x", "password": "bad-final"})
    check("6th attempt within window locked out (429)", code == 429, str(code))
    check("lockout sends Retry-After",
          bool(resp.headers.get("Retry-After")),
          str(resp.headers.get("Retry-After")))
    # Per-username lockout must not lock a different account.
    code, _, _ = request("GET", "/api/me")
    check("admin session unaffected by another user's lockout", code == 200,
          str(code))

    print("== logout ==")
    code, _ = op2_json("/api/logout", None, csrf=v_csrf)
    check("logout succeeds (200)", code == 200, str(code))
    code, _ = op2_json("/api/stats", None, method="GET")
    check("session invalid after logout (401)", code == 401, str(code))

    print("== admin reset (ADMIN_RESET) ==")
    # Exercise setup_auth()'s bootstrap + reset wiring in-process against a
    # throwaway auth DB (independent of the running app's DB).
    sys.path.insert(0, os.path.join(HERE, "app"))
    import main as app_main
    reset_db = os.path.join(tmp, "reset-auth.db")
    for k in ("AUTH_ENABLED", "AUTH_DB_PATH", "ADMIN_USERNAME",
              "ADMIN_PASSWORD", "ADMIN_RESET"):
        os.environ.pop(k, None)
    os.environ.update(AUTH_ENABLED="true", AUTH_DB_PATH=reset_db,
                      ADMIN_USERNAME="admin", ADMIN_PASSWORD="Initial-Pass-1234")
    m1 = app_main.setup_auth()
    # Lock the account out, to prove reset clears the lockout too.
    for _ in range(5):
        m1.verify_login("admin", "nope-nope-nope", "10.0.0.9")
    locked, _, retry = m1.verify_login("admin", "Initial-Pass-1234", "10.0.0.9")
    check("account locked before reset", locked is None and retry > 0,
          str(retry))
    m1.close()
    # Forgot the password: recover via ADMIN_RESET with a new password.
    os.environ.update(ADMIN_RESET="true", ADMIN_PASSWORD="Recovered-Pass-9876")
    m2 = app_main.setup_auth()
    u, e, _ = m2.verify_login("admin", "Recovered-Pass-9876", "10.0.0.9")
    check("ADMIN_RESET sets the new admin password", u is not None and e is None,
          str(e))
    check("reset account is admin", u and u["role"] == "admin", str(u))
    old, _, _ = m2.verify_login("admin", "Initial-Pass-1234", "10.0.0.10")
    check("old admin password rejected after reset", old is None)
    m2.close()
    for k in ("AUTH_ENABLED", "AUTH_DB_PATH", "ADMIN_USERNAME",
              "ADMIN_PASSWORD", "ADMIN_RESET"):
        os.environ.pop(k, None)

    print("== retention prune ==")
    # Insert an event well outside the window, then wait for a prune sweep
    # (PRUNE_INTERVAL_SEC=2). A concurrent short-lived writer is fine in WAL.
    old_ts = int(time.time()) - 30 * 86400
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("INSERT INTO events (ts,device,vendor,src,dst,proto,"
                 "dst_port,action,rule) VALUES (?,?,?,?,?,?,?,?,?)",
                 (old_ts, "UDM-Test", "unifi", "10.0.0.1", "10.0.0.2",
                  "TCP", 1, "Allow", "ancient"))
    conn.commit()
    conn.close()
    present = get_json("/api/live?since=0&ip=10.0.0.1")["events"]
    check("old event inserted", len(present) == 1, str(len(present)))
    time.sleep(3.5)
    gone = get_json("/api/live?since=0&ip=10.0.0.1")["events"]
    check("old event pruned by retention", gone == [], str(gone))

    print("== graceful stop ==")
    # Queue a batch, then stop inside the flush window: final drain persists it.
    for _ in range(10):
        send(sophos_line("Allowed", "late-batch",
                         "192.168.99.1", "8.8.4.4", "TCP", 8443), P_SOPHOS)
    time.sleep(0.3)
    proc.send_signal(signal.CTRL_BREAK_EVENT if IS_WIN else signal.SIGTERM)
    try:
        rc = proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = None
    time.sleep(0.3)
    check("clean exit on graceful stop", rc == 0, f"rc={rc}")
    check("writer final flush logged",
          any("stopped cleanly" in l for l in out), "\n".join(out[-6:]))

    conn = sqlite3.connect(db_path, timeout=10)
    n = conn.execute("SELECT COUNT(*) FROM events WHERE rule='late-batch'"
                     ).fetchone()[0]
    conn.close()
    check("late batch survived shutdown", n == 10, str(n))

    print(f"\n{checks['pass']} passed, {checks['fail']} failed. "
          f"(artifacts in {tmp})")
    sys.exit(1 if checks["fail"] else 0)


if __name__ == "__main__":
    main()
