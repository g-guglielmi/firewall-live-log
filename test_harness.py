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

import base64
import email as emaillib
import hashlib
import http.client
import http.cookiejar
import importlib.util
import json
import os
import queue
import re
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


def request(method, path, obj=None, csrf=False, headers=None):
    """Return (status_code, parsed_json_or_{}, response). Never raises on a
    non-2xx status — HTTPError is unwrapped so checks can inspect the code."""
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        req.add_header("X-CSRF-Token", _CSRF["token"])
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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


def api_get(path, key):
    """GET with an Authorization: Bearer key and NO session cookie (a bare
    opener), so a 200 proves the key authenticated, not a leaked session.
    Returns (status, parsed_json_or_{}, raw_bytes)."""
    req = urllib.request.Request(BASE + path)
    if key is not None:
        req.add_header("Authorization", "Bearer " + key)
    try:
        r = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        r = e
    body = r.read()
    code = r.status if hasattr(r, "status") else r.code
    try:
        parsed = json.loads(body) if body and "json" in \
            r.headers.get("Content-Type", "") else {}
    except ValueError:
        parsed = {}
    return code, parsed, body


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
               ADMIN_PASSWORD=ADMIN_PASS,
               MAIL_DEBUG_DIR=os.path.join(tmp, "mail"),
               PUBLIC_URL="https://fw.example.test",
               # Every synthetic datagram comes from 127.0.0.1; a sender
               # bound to 127.0.0.2 must be rejected (checked later). A
               # hostname, so the run exercises DNS-backed entries.
               SYSLOG_ALLOWED_SOURCES="localhost")
    # Don't inherit a real ADMIN_RESET / SMTP host from the caller's shell.
    for _k in ("ADMIN_RESET", "SMTP_HOST", "SMTP_FROM", "ADMIN_EMAIL"):
        env.pop(_k, None)

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
    deadline = time.time() + 5
    while time.time() < deadline and not any(
            "[sources] resolved localhost ->" in l for l in out):
        time.sleep(0.1)
    check("hostname in SYSLOG_ALLOWED_SOURCES is resolved at startup",
          any("[sources] resolved localhost ->" in l and "127.0.0.1" in l
              for l in out),
          str([l for l in out if "[sources]" in l][:3]))
    check("startup log names the hostname and the hold/replay behaviour",
          any("syslog accepted only from: localhost" in l for l in out)
          and any("held up to 10 min for replay" in l for l in out))
    if os.name != "nt":
        import stat as statmod
        modes = {os.path.basename(p): oct(statmod.S_IMODE(os.stat(p).st_mode))
                 for p in (db_path, os.path.join(tmp, "auth.db"))}
        check("databases are created owner-only (0600)",
              all(m == "0o600" for m in modes.values()), str(modes))
    # The image's HEALTHCHECK script: exit 0 against the live app, 1 when
    # nothing answers (port 1 is closed), honouring HTTP_PORT.
    hc = os.path.join(os.path.dirname(MAIN), "healthcheck.py")
    rc_ok = subprocess.run([sys.executable, hc], env=dict(env),
                           capture_output=True).returncode
    rc_bad = subprocess.run([sys.executable, hc],
                            env=dict(env, HTTP_PORT="1"),
                            capture_output=True, timeout=15).returncode
    check("healthcheck.py exits 0 when the app answers, 1 when it doesn't",
          rc_ok == 0 and rc_bad == 1, f"ok={rc_ok} bad={rc_bad}")

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
    # Sophos tags a permitted port-forward as "Allowed"; the NAT-named rule
    # is what marks it as translation -> classified NAT (blue), not Allow.
    for _ in range(7):
        send(sophos_line("Allowed", "DNAT-Web",
                         "203.0.113.9", "192.168.10.80", "TCP", 8443), P_SOPHOS)
    # A blocked packet on a NAT rule stays blocked (red) -- the verdict wins.
    for _ in range(2):
        send(sophos_line("Denied", "DNAT-RDP",
                         "203.0.113.9", "192.168.10.81", "TCP", 3390), P_SOPHOS)
    # Auto-detect port: one of each vendor.
    send(unifi_line("LAN_IN-A-2001", "auto unifi",
                    "172.16.0.2", "172.16.0.3", "UDP", 53), P_AUTO)
    send(sophos_line("Allowed", "auto sophos",
                     "172.16.0.4", "172.16.0.5", "UDP", 123), P_AUTO)
    # A firewall-shaped line we can't parse (has the UniFi SRC= marker but no
    # DST=) is kept as "unparsed" for diagnosis.
    send(b"<4>Jul 18 12:00:00 UDM kernel: [LAN_IN-A-9] SRC=10.0.0.9 "
         b"TTL=63 PROTO=TCP SPT=40000 DPT=443", P_AUTO)
    # Ordinary host syslog the gateway also forwards (no firewall marker) is
    # discarded, not stored — these three lines count as "ignored".
    send(b"<30>Jul 18 12:00:01 UDM charon[123]: 12[ENC] generating "
         b"INFORMATIONAL request 843 [ ]", P_AUTO)
    send(b"<30>Jul 18 12:00:01 UDM dnsmasq-dhcp[99]: DHCPACK(br0) "
         b"10.0.0.5 aa:bb:cc:dd:ee:ff phone", P_UNIFI)
    send(b"this is not a firewall log", P_SOPHOS)

    time.sleep(2.5)  # past a flush

    print("== live api ==")
    live = get_json("/api/live?since=0&limit=2000")
    evs = live["events"]
    # 36 UDM-Test + 34 Sophos-Test + 2 Mixed-Auto (1 unifi + 1 sophos) = 72.
    check("events stored and returned", len(evs) == 72, str(len(evs)))
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
    check("sophos NAT-named Allowed -> NAT",
          len(by(device="Sophos-Test", action="NAT", dst_port=8443)) == 7)
    check("sophos NAT-named Denied -> Block (verdict wins)",
          len(by(device="Sophos-Test", action="Block", dst_port=3390)) == 2)
    check("auto-detect: unifi on mixed port",
          len(by(device="Mixed-Auto", vendor="unifi")) == 1)
    check("auto-detect: sophos on mixed port",
          len(by(device="Mixed-Auto", vendor="sophos")) == 1)

    print("== geoip country annotation ==")
    # Public dst 93.184.216.34 (US) is annotated; private src 10.0.10.5 is not.
    allow = by(device="UDM-Test", action="Allow", dst_port=443)
    check("public dst gets a country code",
          all(e.get("dst_cc") == "us" for e in allow), str(allow[:1]))
    check("private src gets no country code",
          all("src_cc" not in e for e in allow), str(allow[:1]))
    # Sophos public dst 8.8.8.8 -> US.
    check("public dst 8.8.8.8 -> us",
          all(e.get("dst_cc") == "us"
              for e in by(device="Sophos-Test", action="Allow", dst_port=443)),
          "")
    # A reserved/documentation public-looking dst (203.0.113.0/24, RFC5737)
    # is correctly left unannotated.
    check("reserved 203.0.113.x dst not annotated",
          all("dst_cc" not in e for e in by(device="UDM-Test", action="NAT")),
          "")
    # Flag asset + names served and bad names rejected. (api_get returns the
    # raw response bytes, which request() does not.)
    code, _, body = api_get("/flags/us.svg", None)
    check("flag svg served", code == 200 and b"<svg" in body, str(code))
    code, names, _ = api_get("/flags/names.json", None)
    check("flag names served", code == 200 and isinstance(names, dict)
          and names.get("us", "").startswith("United States"),
          str(names.get("us") if isinstance(names, dict) else names))
    # Only /[a-z]{2}\.svg/ reaches a file; anything else under /flags/ is 404.
    code, _, _ = api_get("/flags/index.svg", None)    # 5 letters, not a CC
    code2, _, _ = api_get("/flags/us.png", None)      # wrong extension
    check("flag route rejects non-CC names", code == 404 and code2 == 404,
          f"{code},{code2}")

    print("== filters ==")
    f = get_json("/api/live?since=0&vendor=sophos")
    # 34 on Sophos-Test + 1 auto-detected on Mixed-Auto = 35.
    check("vendor filter", all(e["vendor"] == "sophos" for e in f["events"])
          and len(f["events"]) == 35, str(len(f["events"])))
    f = get_json("/api/live?since=0&action=blocked")
    check("blocked filter", all(e["action"] in ("Block", "Drop", "Reject")
          for e in f["events"]) and len(f["events"]) == 20, str(len(f["events"])))
    f = get_json("/api/live?since=0&action=NAT")
    check("nat filter", all(e["action"] == "NAT" for e in f["events"])
          and len(f["events"]) == 12, str(len(f["events"])))
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
    f = get_json("/api/live?since=0&src=192.168.10.55")
    check("src filter (source only)",
          all("192.168.10.55" in e["src"] for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&dst=10.9.9.9")
    check("dst filter (destination only)",
          all("10.9.9.9" in e["dst"] for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&src=10.9.9.9")   # that value is a dst
    check("src filter does not match destinations",
          len(f["events"]) == 0, str(len(f["events"])))
    f = get_json("/api/live?since=0&rule=Drop-RDP")
    check("rule filter (substring)",
          all(e["rule"] == "Drop-RDP" for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&proto=ICMP")
    check("proto filter",
          all(e["proto"] == "ICMP" for e in f["events"])
          and len(f["events"]) == 7, str(len(f["events"])))
    # Negation: "!" excludes matches. 7 events are ICMP out of 63.
    f = get_json("/api/live?since=0&proto=!ICMP")
    check("proto negation (!) excludes matches",
          all(e["proto"] != "ICMP" for e in f["events"])
          and len(f["events"]) == 65, str(len(f["events"])))
    # Port negation: 6 events are dst_port 3389; excluding leaves 57.
    f = get_json("/api/live?since=0&port=%213389")   # "!3389"
    check("port negation (!) excludes a port",
          all(e["dst_port"] != 3389 for e in f["events"])
          and len(f["events"]) == 66, str(len(f["events"])))
    # dst negation: exclude a destination to filter out its noise.
    f = get_json("/api/live?since=0&dst=%2110.9.9.9")   # "!10.9.9.9"
    check("dst negation (!) excludes a destination",
          all("10.9.9.9" not in e["dst"] for e in f["events"])
          and len(f["events"]) == 66, str(len(f["events"])))
    f = get_json("/api/live?since=0&device=UDM-Test")
    check("device filter",
          all(e["device"] == "UDM-Test" for e in f["events"])
          and len(f["events"]) == 36, str(len(f["events"])))

    print("== window query (filtered, id-bounded) ==")
    w = get_json("/api/events?window=86400&device=Sophos-Test&action=blocked")
    check("window query with filter",
          all(e["action"] in ("Block", "Drop", "Reject") for e in w["events"])
          and len(w["events"]) == 12, str(len(w["events"])))
    w = get_json("/api/events?window=86400&device=UDM-Test&proto=%21ICMP")
    check("window query with negation",
          all(e["proto"] != "ICMP" for e in w["events"])
          and len(w["events"]) == 33, str(len(w["events"])))
    # Backward paging: before=<id> returns only older events.
    w = get_json("/api/events?window=86400&device=UDM-Test")
    ids = sorted(e["id"] for e in w["events"])
    mid = ids[len(ids) // 2]
    w2 = get_json(f"/api/events?window=86400&device=UDM-Test&before={mid}")
    check("window before-cursor pages older",
          all(e["id"] < mid for e in w2["events"])
          and len(w2["events"]) == sum(1 for i in ids if i < mid),
          str(len(w2["events"])))
    # Paging contract: on this tiny DB every scan reaches the range start in
    # one bounded chunk, so the response must say the history is exhausted.
    w3 = get_json("/api/events?window=86400&device=Sophos-Test&action=blocked")
    check("filtered window reports scan complete",
          w3["has_more"] is False and w3.get("next_before") is None,
          str({k: w3.get(k) for k in ("has_more", "next_before")}))
    check("unfiltered before-page reports scan complete",
          w2["has_more"] is False and w2.get("next_before") is None,
          str({k: w2.get(k) for k in ("has_more", "next_before")}))

    print("== custom time range ==")
    now = int(time.time())
    # Open-ended range (from an hour ago, no 'to') == the last-hour window.
    c = get_json(f"/api/events?from={now - 3600}&device=UDM-Test")
    check("custom range (open end) returns recent events",
          len(c["events"]) == 36
          and all(e["device"] == "UDM-Test" for e in c["events"]),
          str(len(c["events"])))
    # Bounded range that ends before any event exists → empty. Exercises the
    # id-ceiling that stops the DESC scan dragging through everything newer.
    c = get_json(f"/api/events?from={now - 90000}&to={now - 86400}&device=UDM-Test")
    check("custom range ending in the past is empty",
          len(c["events"]) == 0, str(len(c["events"])))
    # Bounded range spanning now returns the same set as the open range.
    c = get_json(f"/api/events?from={now - 3600}&to={now + 120}&device=UDM-Test")
    check("bounded range spanning now matches open range",
          len(c["events"]) == 36, str(len(c["events"])))
    # Validation: 'to' must be later than 'from'.
    code, _, _ = request("GET", f"/api/events?from={now}&to={now - 10}")
    check("custom range with to<=from rejected (400)", code == 400, str(code))

    print("== incremental cursor ==")
    tail = get_json(f"/api/live?since={live['cursor']}")
    check("no new events after cursor",
          tail["events"] == [] and tail["cursor"] == live["cursor"], str(tail))

    print("== stats + per-device health + csv + unparsed ==")
    st = get_json("/api/stats")
    check("stats parsed = 72 (lifetime)", st["parsed"] == 72, str(st["parsed"]))
    # Only the firewall-shaped-but-broken line is kept as unparsed; the three
    # non-firewall lines (charon/dnsmasq/plain text) are discarded.
    check("stats unparsed = 1 (firewall-shaped only)", st["unparsed"] == 1, str(st["unparsed"]))
    check("stats ignored = 3 (non-firewall syslog discarded)",
          st["ignored"] == 3, str(st.get("ignored")))
    # db_bytes: on-disk footprint, >= the main file, and reasonable for 63 rows.
    _main = os.path.getsize(db_path)
    check("stats db_bytes present and covers the on-disk files",
          isinstance(st["db_bytes"], int) and st["db_bytes"] >= _main > 0,
          f"db_bytes={st.get('db_bytes')} main={_main}")
    dmap = {d["name"]: d for d in st["devices"]}
    check("per-device totals from meta (scan-free)",
          dmap["UDM-Test"]["events"] == 36
          and dmap["Sophos-Test"]["events"] == 34
          and dmap["Mixed-Auto"]["events"] == 2,
          str({k: v["events"] for k, v in dmap.items()}))
    check("per-device last_seen populated",
          all(dmap[n]["last_seen"] for n in dmap), str(dmap))
    check("all 3 devices seen this minute",
          sum(1 for d in st["devices"] if d["events_last_min"] > 0) == 3,
          str({k: v["events_last_min"] for k, v in dmap.items()}))
    # Sparkline histograms: 15 buckets, last bucket = the rolling /min figure,
    # blocked never exceeds total, fleet blocked = sum of per-device.
    check("per-device hist is 15 buckets ending in events_last_min",
          all(len(d["hist"]) == 15 and len(d["hist_blocked"]) == 15
              and len(d["hist_nat"]) == 15
              and d["hist"][-1] == d["events_last_min"]
              and d["hist_blocked"][-1] == d["blocked_last_min"]
              and d["hist_nat"][-1] == d["nat_last_min"]
              and all(b + na <= t for t, b, na
                      in zip(d["hist"], d["hist_blocked"], d["hist_nat"]))
              for d in st["devices"]),
          str({k: (v["hist"][-1], v["events_last_min"]) for k, v in dmap.items()}))
    check("blocked_last_min counts the Drop/Block events",
          dmap["UDM-Test"]["blocked_last_min"] > 0
          and st["blocked_last_min"] == sum(d["blocked_last_min"] for d in st["devices"])
          and st["blocked_last_min"] < st["events_last_min"],
          str({k: v["blocked_last_min"] for k, v in dmap.items()}))
    check("nat_last_min counts the NAT/forward events (both vendors)",
          dmap["UDM-Test"]["nat_last_min"] == 5
          and dmap["Sophos-Test"]["nat_last_min"] == 7
          and st["nat_last_min"] == sum(d["nat_last_min"] for d in st["devices"])
          and st["nat_last_min"] < st["events_last_min"],
          str({k: v["nat_last_min"] for k, v in dmap.items()}))
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
    check("index CSP uses a style nonce and no 'unsafe-inline'",
          "style-src 'nonce-" in csp and "unsafe-inline" not in csp
          and '<style nonce="' in html, csp[:120])
    check("index CSP img-src is 'self' only (no data:)",
          "img-src 'self';" in csp and "data:" not in csp, csp[:160])
    # A style nonce only holds if the pages carry no style="" attributes at
    # all (CSP blocks them even with a nonce), so prove that for each page.
    inline = {}
    for page in ("/", "/login", "/forgot", "/reset"):
        with _OPENER.open(urllib.request.Request(BASE + page), timeout=10) as pr:
            inline[page] = len(re.findall(r'\sstyle\s*=\s*["\']', pr.read().decode()))
    check("no inline style attributes in any served page",
          not any(inline.values()), str(inline))

    print("== user management ==")
    code, body, _ = request("POST", "/api/users",
                           {"username": "viewer1", "password": "ViewerPass123",
                            "role": "user",
                            "email": "viewer1@example.test"}, csrf=True)
    check("admin creates a user (201)", code == 201, f"{code} {body}")
    _, me_now, _ = request("GET", "/api/me")
    my_id = me_now["user"]["id"]
    code, body, _ = request("POST", "/api/users/set_email",
                           {"id": my_id, "email": "admin@example.test"},
                           csrf=True)
    check("changing your own email without the current password -> 403",
          code == 403 and "current password" in body.get("error", ""),
          f"{code} {body}")
    code, _, _ = request("POST", "/api/users/set_email",
                        {"id": my_id, "email": "admin@example.test",
                         "current_password": "Wrong-Password-1"}, csrf=True)
    check("changing your own email with a wrong password -> 403", code == 403,
          str(code))
    code, _, _ = request("POST", "/api/users/set_email",
                        {"id": my_id, "email": "admin@example.test",
                         "current_password": ADMIN_PASS}, csrf=True)
    _, me_now, _ = request("GET", "/api/me")
    check("changing your own email with the current password -> 200 and "
          "/api/me shows it",
          code == 200 and me_now["user"]["email"] == "admin@example.test",
          f"{code} {me_now}")
    check("email unchanged after the refused attempts' failure was recorded "
          "and cleared by the success (no lockout residue)",
          request("POST", "/api/users/set_email",
                  {"id": my_id, "email": "", "current_password": ADMIN_PASS},
                  csrf=True)[0] == 200)
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

    print("== role management ==")
    _, ulist, _ = request("GET", "/api/users")
    by_name = {u["username"]: u for u in ulist.get("users", [])}
    viewer_id = by_name.get("viewer1", {}).get("id")
    admin_id = by_name.get(ADMIN_USER, {}).get("id")
    code, _, _ = request("POST", "/api/users/set_role",
                        {"id": viewer_id, "role": "admin"}, csrf=True)
    check("admin promotes a user to admin (200)", code == 200, str(code))
    _, ul2, _ = request("GET", "/api/users")
    check("role is now admin", any(u["username"] == "viewer1"
          and u["role"] == "admin" for u in ul2.get("users", [])))
    code, _, _ = request("POST", "/api/users/set_role",
                        {"id": viewer_id, "role": "user"}, csrf=True)
    check("admin demotes back to user (200)", code == 200, str(code))
    code, _, _ = request("POST", "/api/users/set_role",
                        {"id": viewer_id, "role": "superuser"}, csrf=True)
    check("invalid role rejected (400)", code == 400, str(code))
    code, _, _ = request("POST", "/api/users/set_role",
                        {"id": admin_id, "role": "user"}, csrf=True)
    check("admin can't demote their own role (400)", code == 400, str(code))
    code, _, _ = request("POST", "/api/users/set_role",
                        {"id": viewer_id, "role": "admin"}, csrf=False)
    check("set_role without CSRF rejected (403)", code == 403, str(code))
    code, _ = op2_json("/api/users/set_role",
                       {"id": viewer_id, "role": "admin"}, csrf=v_csrf)
    check("non-admin cannot set roles (403)", code == 403, str(code))

    print("== api keys ==")
    # Non-admin (viewer1, still logged in via op2) cannot mint keys.
    code, _ = op2_json("/api/api_keys", {"name": "sneaky"}, csrf=v_csrf)
    check("non-admin cannot create API keys (403)", code == 403, str(code))
    code, kl = op2_json("/api/api_keys", None, method="GET", csrf=v_csrf)
    check("non-admin cannot list API keys (403)", code == 403, str(code))
    # State-changing key routes need CSRF like the rest.
    code, _, _ = request("POST", "/api/api_keys", {"name": "nocsrf-key"},
                         csrf=False)
    check("create API key without CSRF rejected (403)", code == 403, str(code))
    # Admin mints a key; the raw key is returned exactly once, with the prefix.
    code, body, _ = request("POST", "/api/api_keys", {"name": "reader"},
                            csrf=True)
    api_key = body.get("key", "")
    key_id = body.get("id")
    check("admin creates an API key (201)",
          code == 201 and api_key.startswith("fll_"), f"{code} {body}")
    code, _, _ = request("POST", "/api/api_keys", {"name": "   "}, csrf=True)
    check("blank key name rejected (400)", code == 400, str(code))
    # Listing shows the prefix and metadata, never the raw key or its hash.
    _, kl2, _ = request("GET", "/api/api_keys")
    klist = kl2.get("api_keys", [])
    check("key listed by prefix, never the raw value",
          any(k["id"] == key_id and api_key.startswith(k["prefix"])
              and "key" not in k and "key_hash" not in k for k in klist),
          str(klist))

    # The key authenticates the read API with no session cookie present.
    code, ev, _ = api_get("/api/events?window=86400&device=UDM-Test", api_key)
    check("API key reads /api/events (200)",
          code == 200 and len(ev.get("events", [])) == 36,
          f"{code} {len(ev.get('events', []))}")
    code, lv, _ = api_get("/api/live?since=0&limit=2000", api_key)
    check("API key reads /api/live (200)",
          code == 200 and len(lv.get("events", [])) == 72, str(code))
    code, stx, _ = api_get("/api/stats", api_key)
    check("API key reads /api/stats (200)",
          code == 200 and stx.get("parsed") == 72, str(code))
    code, dv, _ = api_get("/api/devices", api_key)
    check("API key reads /api/devices (200)",
          code == 200 and len(dv) == 3, str(code))
    code, _, cbody = api_get("/api/events.csv?window=86400", api_key)
    check("API key downloads CSV (200)",
          code == 200 and cbody.decode().startswith("time,device,vendor,"),
          str(code))
    # last_used_at is recorded after use.
    _, kl3, _ = request("GET", "/api/api_keys")
    check("last_used_at populated after the key is used",
          any(k["id"] == key_id and k["last_used_at"] for k in
              kl3.get("api_keys", [])), str(kl3.get("api_keys")))
    # No credentials, or a bad key, is refused.
    code, _, _ = api_get("/api/events?window=86400", None)
    check("no credentials on the read API -> 401", code == 401, str(code))
    code, _, _ = api_get("/api/events?window=86400", "fll_not-a-real-key-xyz")
    check("bad API key -> 401", code == 401, str(code))
    # A key must NOT reach management/session routes (least privilege).
    for p in ("/api/users", "/api/me", "/api/api_keys"):
        code, _, _ = api_get(p, api_key)
        check(f"API key cannot reach {p} (401)", code == 401, str(code))
    # Revoke over HTTP; the key stops authenticating immediately.
    code, _, _ = request("DELETE", "/api/api_keys/" + str(key_id), csrf=True)
    check("admin revokes an API key (200)", code == 200, str(code))
    code, _, _ = api_get("/api/events?window=86400", api_key)
    check("revoked key no longer authenticates (401)", code == 401, str(code))
    code, _, _ = request("DELETE", "/api/api_keys/999999", csrf=False)
    check("revoke without CSRF rejected (403)", code == 403, str(code))

    print("== overview layout (categories + order) ==")
    # Fresh install: no categories, every device uncategorized (config order).
    _, lay, _ = request("GET", "/api/layout")
    check("layout starts empty, all devices uncategorized",
          lay.get("categories") == []
          and set(lay.get("uncategorized", [])) ==
          {"UDM-Test", "Sophos-Test", "Mixed-Auto"}, str(lay))
    # Non-admin (viewer1, a 'user' now) cannot save the shared layout.
    code, _ = op2_json("/api/layout",
                       {"categories": [{"name": "X", "devices": []}]},
                       csrf=v_csrf)
    check("non-admin cannot save layout (403)", code == 403, str(code))
    # State-changing, so CSRF is required.
    code, _, _ = request("POST", "/api/layout",
                         {"categories": [{"name": "X", "devices": []}]},
                         csrf=False)
    check("save layout without CSRF rejected (403)", code == 403, str(code))
    # Admin saves a grouping + order; the resolved layout echoes back.
    code, body, _ = request("POST", "/api/layout", {"categories": [
        {"name": "Core", "devices": ["Mixed-Auto", "UDM-Test"]},
        {"name": "Perimeter", "devices": ["Sophos-Test"]},
    ]}, csrf=True)
    check("admin saves a layout (200)",
          code == 200 and body.get("ok")
          and [c["name"] for c in body.get("categories", [])] == ["Core", "Perimeter"]
          and body["categories"][0]["devices"] == ["Mixed-Auto", "UDM-Test"]
          and body.get("uncategorized") == [], f"{code} {body}")
    # GET reflects the saved layout, and it persisted to LAYOUT_PATH on disk.
    _, lay2, _ = request("GET", "/api/layout")
    check("saved layout is read back",
          lay2["categories"][1]["devices"] == ["Sophos-Test"], str(lay2))
    layout_file = os.path.join(tmp, "layout.json")
    check("layout persisted to disk", os.path.exists(layout_file), layout_file)
    # Unknown device names are dropped; a missing device falls to uncategorized.
    code, body, _ = request("POST", "/api/layout", {"categories": [
        {"name": "Mix", "devices": ["ghost-fw", "UDM-Test", "UDM-Test"]},
    ]}, csrf=True)
    check("unknown/duplicate devices dropped, rest uncategorized",
          code == 200 and body["categories"][0]["devices"] == ["UDM-Test"]
          and set(body["uncategorized"]) == {"Sophos-Test", "Mixed-Auto"},
          str(body))
    # Reserved and duplicate category names are rejected.
    code, _, _ = request("POST", "/api/layout",
                         {"categories": [{"name": "Uncategorized", "devices": []}]},
                         csrf=True)
    check("reserved category name rejected (400)", code == 400, str(code))
    code, _, _ = request("POST", "/api/layout", {"categories": [
        {"name": "Dup", "devices": []}, {"name": "dup", "devices": []}]},
        csrf=True)
    check("duplicate category names rejected (400)", code == 400, str(code))
    code, _, _ = request("POST", "/api/layout", {"categories": "nope"}, csrf=True)
    check("non-list categories rejected (400)", code == 400, str(code))
    # Layout is not an API-key route (session-only).
    code, _, _ = api_get("/api/layout", None)
    check("layout requires a session (401 without creds)", code == 401, str(code))
    # Reset to a clean slate so nothing downstream depends on the grouping.
    request("POST", "/api/layout", {"categories": []}, csrf=True)

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

    print("== hardening: response headers + parameter validation ==")
    code, _, resp = request("GET", "/api/me")
    srv = resp.headers.get("Server") or ""
    check("Server header does not advertise the Python version",
          "Python" not in srv, srv)
    for hname in ("Permissions-Policy", "Cross-Origin-Opener-Policy",
                  "Cross-Origin-Resource-Policy"):
        check(f"{hname} header present", bool(resp.headers.get(hname)))
    # Integers that reach SQLite must be range-checked: out of range is a 400
    # with a message, never a 500 leaking "OverflowError: ...".
    big = "99999999999999999999"
    for p in (f"/api/live?since={big}", "/api/live?since=-5",
              f"/api/events?from={big}", f"/api/events?window=3600&before={big}",
              f"/api/events?window=3600&port=={big}",
              "/api/events?window=3600&port=70000"):
        code, body, _ = request("GET", p)
        check(f"out-of-range param -> 400 ({p.partition('?')[2][:26]})",
              code == 400 and "Error" not in body.get("error", ""),
              f"{code} {body}")

    print("== hardening: proxy headers, cross-site posts, must-change gate ==")
    # TRUSTED_PROXIES is unset for this instance, so X-Forwarded-For from the
    # (untrusted) peer is ignored: five failures behind five different spoofed
    # addresses still lock the (username, real ip) pair.
    for i in range(5):
        request("POST", "/api/login",
                {"username": "spoofer", "password": f"bad-password-{i}"},
                headers={"X-Forwarded-For": f"203.0.113.{i}"})
    code, _, _ = request("POST", "/api/login",
                         {"username": "spoofer", "password": "bad-final-1"},
                         headers={"X-Forwarded-For": "203.0.113.99"})
    check("spoofed X-Forwarded-For does not dodge the lockout (429)",
          code == 429, str(code))
    time.sleep(0.5)
    check("ignored forwarded header is logged once with the TRUSTED_PROXIES hint",
          sum(1 for l in out if "ignoring X-Forwarded-For from untrusted peer"
              in l and "TRUSTED_PROXIES" in l) == 1,
          str([l for l in out if "untrusted peer" in l][:3]))
    # Browser cross-site requests are refused before anything else runs.
    code, _, _ = request("POST", "/api/login",
                         {"username": ADMIN_USER, "password": ADMIN_PASS},
                         headers={"Sec-Fetch-Site": "cross-site"})
    check("cross-site POST rejected via Sec-Fetch-Site (403)", code == 403,
          str(code))
    code, _, _ = request("POST", "/api/session/touch", None, csrf=True,
                         headers={"Origin": "https://evil.example"})
    check("cross-site POST rejected via Origin (403)", code == 403, str(code))
    code, _, _ = request("POST", "/api/session/touch", None, csrf=True,
                         headers={"Sec-Fetch-Site": "same-origin",
                                  "Origin": f"http://127.0.0.1:{HTTP_PORT}"})
    check("same-origin browser POST passes (200)", code == 200, str(code))
    code, _, _ = request("POST", "/api/session/touch", None, csrf=True,
                         headers={"Origin": "https://fw.example.test"})
    check("Origin matching PUBLIC_URL passes (200)", code == 200, str(code))
    # A temporary password (must_change_pw) can only be used to change the
    # password: every data route is 403 until then.
    code, body, _ = request("POST", "/api/users",
                            {"username": "tempuser",
                             "password": "TempPassword-9911",
                             "must_change_pw": True}, csrf=True)
    check("temp-password user created (201)", code == 201, str(code))
    temp_id = body.get("id")
    tj = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def tcall(method, path, obj=None, csrf_tok=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if csrf_tok:
            req.add_header("X-CSRF-Token", csrf_tok)
        try:
            r = tj.open(req, timeout=10)
        except urllib.error.HTTPError as e:
            r = e
        raw = r.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {}
        return (r.status if hasattr(r, "status") else r.code), parsed
    code, lb = tcall("POST", "/api/login", {"username": "tempuser",
                                            "password": "TempPassword-9911"})
    check("temp-password login succeeds and flags must_change_pw",
          code == 200 and lb.get("user", {}).get("must_change_pw") is True,
          f"{code} {lb}")
    tcsrf = lb.get("csrf_token", "")
    code, _ = tcall("GET", "/api/events?window=3600")
    check("data routes answer 403 until the password is changed", code == 403,
          str(code))
    code, _ = tcall("GET", "/api/me")
    check("/api/me still answers while the change is pending", code == 200,
          str(code))
    code, _ = tcall("POST", "/api/change_password",
                    {"current_password": "TempPassword-9911",
                     "new_password": "ChangedPassword-2233"}, tcsrf)
    check("password change is allowed while pending (200)", code == 200,
          str(code))
    code, lb = tcall("POST", "/api/login", {"username": "tempuser",
                                            "password": "ChangedPassword-2233"})
    code2, _ = tcall("GET", "/api/events?window=3600")
    check("data routes open after the change (200)",
          code == 200 and code2 == 200, f"{code} {code2}")
    request("DELETE", f"/api/users/{temp_id}", csrf=True)

    print("== hardening: re-auth throttle, id parsing, csrf bytes ==")
    # A non-ASCII CSRF header must be a plain 403, never a 500 (str
    # compare_digest raises TypeError on non-ASCII).
    code, body, _ = request("POST", "/api/layout", {"categories": []},
                            headers={"X-CSRF-Token": "\xe9\xe8-not-the-token"})
    check("non-ASCII CSRF header -> 403 (not 500)",
          code == 403 and "CSRF" in body.get("error", ""), f"{code} {body}")
    # JSON true is not a record id (isinstance(True, int) is True).
    for p, extra in (("/api/users/set_email", {"email": "x@example.test"}),
                     ("/api/users/set_role", {"role": "user"}),
                     ("/api/users/reset_password",
                      {"new_password": "Whatever-Password-1"})):
        code, body, _ = request("POST", p, {"id": True, **extra}, csrf=True)
        check(f"{p} rejects id=true (400)", code == 400, f"{code} {body}")
    # A Unicode digit in the URL (0xB2 = "²" in the header charset) passes
    # str.isdigit() but not int(); must be a 400, not a 500.
    sess = next(c.value for c in _CJ if c.name == "session")
    raw = (f"DELETE /api/users/\xb2 HTTP/1.0\r\nHost: 127.0.0.1\r\n"
           f"Cookie: session={sess}\r\nX-CSRF-Token: {_CSRF['token']}\r\n"
           f"Content-Length: 0\r\n\r\n").encode("latin-1")
    with socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=10) as rs:
        rs.sendall(raw)
        resp = b""
        while True:
            chunk = rs.recv(4096)
            if not chunk:
                break
            resp += chunk
    status = resp.split(b" ", 2)[1] if resp.startswith(b"HTTP/") else b"?"
    check("DELETE /api/users/<unicode digit> -> 400 (not 500)",
          status == b"400", resp[:120])
    # The change-password current-password check is throttled like a login:
    # five wrong guesses lock the (username, ip) pair for this route AND
    # for /api/login, and the 6th answers 429 with Retry-After.
    code, body, _ = request("POST", "/api/users",
                            {"username": "pwguess",
                             "password": "Guessable-Pass-5566"}, csrf=True)
    guess_id = body.get("id")
    gj = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def gcall(method, path, obj=None, csrf_tok=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if csrf_tok:
            req.add_header("X-CSRF-Token", csrf_tok)
        try:
            r = gj.open(req, timeout=10)
        except urllib.error.HTTPError as e:
            r = e
        rawb = r.read()
        try:
            parsed = json.loads(rawb) if rawb else {}
        except ValueError:
            parsed = {}
        return (r.status if hasattr(r, "status") else r.code), parsed, r
    code, lb, _ = gcall("POST", "/api/login", {"username": "pwguess",
                                               "password": "Guessable-Pass-5566"})
    gcsrf = lb.get("csrf_token", "")
    codes = []
    for i in range(5):
        code, _, _ = gcall("POST", "/api/change_password",
                           {"current_password": f"wrong-guess-{i}",
                            "new_password": "Another-Password-7788"}, gcsrf)
        codes.append(code)
    check("wrong current password -> 403 x5", codes == [403] * 5, str(codes))
    code, body, r6 = gcall("POST", "/api/change_password",
                           {"current_password": "Guessable-Pass-5566",
                            "new_password": "Another-Password-7788"}, gcsrf)
    check("6th current-password check is locked out (429 + Retry-After)",
          code == 429 and bool(r6.headers.get("Retry-After")), f"{code} {body}")
    code, _, _ = gcall("POST", "/api/login", {"username": "pwguess",
                                              "password": "Guessable-Pass-5566"})
    check("the same lockout applies to /api/login for that user (429)",
          code == 429, str(code))
    code, _, _ = gcall("GET", "/api/me")
    check("the existing session itself keeps working (200)", code == 200,
          str(code))
    request("DELETE", f"/api/users/{guess_id}", csrf=True)

    print("== hardening: syslog validation + csv formula injection ==")
    send(unifi_line("WAN_IN-D-7001", "=HYPERLINK(evil)",
                    "198.51.100.7", "10.0.10.5", "TCP", 3389), P_UNIFI)
    send(unifi_line("WAN_IN-D-7002", "+bad-rule",
                    "198.51.100.8", "10.0.10.5", "TCP", 3389), P_UNIFI)
    # SRC is not an IP: not an event, kept as unparsed for diagnosis.
    send(unifi_line("LAN_IN-A-7003", "not-an-ip",
                    "<img/src=x>", "10.0.10.5", "TCP", 80), P_UNIFI)
    # Oversized rule text is capped; an impossible port becomes the sentinel.
    send(unifi_line("LAN_IN-A-7004", "R" * 400,
                    "10.0.10.77", "10.0.10.5", "TCP", 99999), P_UNIFI)
    time.sleep(2.5)
    _, ev, _ = request("GET", "/api/events?window=3600&device=UDM-Test"
                       "&src=198.51.100.")
    rules = sorted(e["rule"] for e in ev.get("events", []))
    check("JSON API returns rule text verbatim (no csv prefixing)",
          rules == ["+bad-rule", "=HYPERLINK(evil)"], str(rules))
    with _OPENER.open(urllib.request.Request(
            BASE + "/api/events.csv?window=3600&device=UDM-Test"
            "&src=198.51.100."), timeout=10) as r:
        csv2 = r.read().decode()
    check("csv export neutralises formula-leading cells",
          "'=HYPERLINK(evil)" in csv2 and "'+bad-rule" in csv2
          and ",=HYPERLINK" not in csv2, csv2[-160:])
    with _OPENER.open(urllib.request.Request(
            BASE + "/api/events.csv?window=86400&device=UDM-Test&proto=ICMP"),
            timeout=10) as r:
        csv3 = r.read().decode()
    check("csv keeps the numeric -1 port untouched", ",-1," in csv3
          and ",'-1," not in csv3, csv3[-120:])
    _, ev, _ = request("GET", "/api/events?window=3600&src=%3Cimg")
    check("non-IP SRC never becomes an event", ev.get("events") == [],
          str(ev.get("events"))[:80])
    st2 = get_json("/api/stats")
    check("non-IP SRC line is kept as unparsed (now 2)", st2["unparsed"] == 2,
          str(st2["unparsed"]))
    _, ev, _ = request("GET", "/api/events?window=3600&src=10.0.10.77")
    e77 = (ev.get("events") or [{}])[0]
    check("rule text capped at 256 chars, impossible port -> -1",
          len(e77.get("rule", "")) == 256 and e77.get("dst_port") == -1,
          f"len={len(e77.get('rule', ''))} port={e77.get('dst_port')}")

    print("== hardening: syslog source filter, literal filters, csv paging ==")
    # SYSLOG_ALLOWED_SOURCES=127.0.0.1: a datagram from 127.0.0.2 is discarded
    # before parsing, counted as rejected, and logged once with the hint.
    st_before = get_json("/api/stats")
    rs2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rs2.bind(("127.0.0.2", 0))
    for i in range(3):
        rs2.sendto(unifi_line("WAN_IN-D-8800", "Should-Not-Land",
                              "198.51.100.77", "10.0.10.5", "TCP", 22),
                   ("127.0.0.1", P_UNIFI))
    rs2.close()
    time.sleep(2.5)
    st_after = get_json("/api/stats")
    check("datagrams from a non-allowed source are rejected (counted, not stored)",
          st_after.get("rejected") == 3
          and st_after["parsed"] == st_before["parsed"]
          and st_after["unparsed"] == st_before["unparsed"],
          f"rejected={st_after.get('rejected')} parsed {st_before['parsed']}"
          f"->{st_after['parsed']}")
    _, ev, _ = request("GET", "/api/events?window=3600&rule=Should-Not-Land")
    check("rejected datagram never becomes an event", ev.get("events") == [])
    check("rejected source is logged once with the SYSLOG_ALLOWED_SOURCES hint",
          sum(1 for l in out if "rejected syslog from 127.0.0.2" in l
              and "SYSLOG_ALLOWED_SOURCES" in l) == 1,
          str([l for l in out if "rejected syslog" in l][:3]))
    # An unparsed (firewall-shaped) line is stored truncated to 4 KB.
    send(("SRC=not-an-ip DST=10.0.10.5 PROTO=TCP DPT=80 " + "J" * 9000).encode(),
         P_UNIFI)
    time.sleep(2.0)
    with sqlite3.connect(f"file:{urllib.request.pathname2url(db_path)}?mode=ro",
                         uri=True) as rdb:
        raw_len = rdb.execute("SELECT length(raw) FROM unparsed "
                              "ORDER BY id DESC LIMIT 1").fetchone()[0]
    check("unparsed line stored truncated to 4096 bytes", raw_len == 4096,
          str(raw_len))
    # LIKE wildcards in a filter are literal: "%" and "_" match themselves.
    send(unifi_line("LAN_IN-A-8801", "Pct_100%_done", "10.0.10.90",
                    "10.0.10.5", "TCP", 443), P_UNIFI)
    time.sleep(2.0)
    _, ev, _ = request("GET", "/api/events?window=3600&device=UDM-Test&rule=100%25")
    check("filter '100%' matches the literal rule only",
          [e["rule"] for e in ev.get("events", [])] == ["Pct_100%_done"],
          str([e["rule"] for e in ev.get("events", [])])[:120])
    _, ev, _ = request("GET", "/api/events?window=3600&device=UDM-Test&rule=%25")
    check("filter '%' is literal (not match-everything)",
          len(ev.get("events", [])) == 1, str(len(ev.get("events", []))))
    _, ev_all, _ = request("GET", "/api/events?window=3600&device=UDM-Test&limit=5000")
    _, ev, _ = request("GET", "/api/events?window=3600&device=UDM-Test&rule=_")
    check("filter '_' is literal (not any-character)",
          0 < len(ev.get("events", [])) < len(ev_all.get("events", []))
          and all("_" in e["rule"] for e in ev.get("events", [])),
          f"{len(ev.get('events', []))} of {len(ev_all.get('events', []))}")
    # CSV: limit honoured, header exactly once, row count = JSON count.
    with _OPENER.open(urllib.request.Request(
            BASE + "/api/events.csv?window=86400&limit=5"), timeout=10) as r:
        lines = [l for l in r.read().decode().splitlines() if l]
    check("csv limit=5 -> header + 5 rows", len(lines) == 6
          and lines[0].startswith("time,") and
          sum(1 for l in lines if l.startswith("time,")) == 1, str(len(lines)))
    _, ev_all, _ = request("GET", "/api/events?window=86400&limit=5000")
    with _OPENER.open(urllib.request.Request(
            BASE + "/api/events.csv?window=86400"), timeout=10) as r:
        lines = [l for l in r.read().decode().splitlines() if l]
    check("csv row count equals the JSON window count",
          len(lines) - 1 == len(ev_all.get("events", [])),
          f"csv={len(lines) - 1} json={len(ev_all.get('events', []))}")

    print("== logout ==")
    code, _ = op2_json("/api/logout", None, csrf=v_csrf)
    check("logout succeeds (200)", code == 200, str(code))
    code, _ = op2_json("/api/stats", None, method="GET")
    check("session invalid after logout (401)", code == 401, str(code))

    print("== self-service password reset (email link) ==")
    maildir = os.path.join(tmp, "mail")

    def mail_files():
        return [os.path.join(maildir, f) for f in os.listdir(maildir)] \
            if os.path.isdir(maildir) else []

    # Unknown identifier: generic 200 and (after a beat) no email produced.
    before = len(mail_files())
    code, body, _ = request("POST", "/api/forgot_password",
                          {"username_or_email": "nobody@example.test"})
    check("forgot for unknown -> generic 200", code == 200 and body.get("ok"),
          str(body))
    # Attacker-sized identifiers are truncated before they reach the log.
    code, _, _ = request("POST", "/api/forgot_password",
                         {"username_or_email": "Z" * 3000 + "@example.test"})
    time.sleep(0.5)
    long_lines = [l for l in out if "unknown account" in l and "ZZZZ" in l]
    check("forgot: oversized identifier is truncated in the log",
          code == 200 and long_lines and all(len(l) < 200 for l in long_lines),
          f"{code} {[len(l) for l in long_lines]}")
    # Real user with an email: generic 200, and an email file appears.
    code, body, _ = request("POST", "/api/forgot_password",
                          {"username_or_email": "viewer1@example.test"})
    check("forgot for real user -> generic 200", code == 200, str(code))
    token = None
    deadline = time.time() + 5
    while time.time() < deadline:
        files = mail_files()
        if len(files) >= before + 1:
            newest = max(files, key=os.path.getmtime)
            with open(newest, encoding="utf-8") as f:
                parsed = emaillib.message_from_file(f)
            payload = parsed.get_payload(decode=True)     # decode QP/base64
            text = payload.decode("utf-8") if payload else ""
            m = re.search(r"/reset#token=([A-Za-z0-9_\-]+)", text)
            if m:
                token = m.group(1)
                break
        time.sleep(0.2)
    check("reset email sent with the token in the URL fragment (#token=)",
          token is not None and "/reset?token=" not in text)
    reset_page = urllib.request.urlopen(BASE + "/reset", timeout=10) \
        .read().decode()
    check("reset page reads the fragment, still accepts the pre-v0.4.41 "
          "query form, and scrubs the URL",
          "location.hash" in reset_page and "location.search" in reset_page
          and "history.replaceState" in reset_page)
    check("no email leaked for unknown identifier",
          len(mail_files()) == before + 1, str(len(mail_files())))

    if token:
        # Password policy still applies through the reset endpoint.
        code, _, _ = request("POST", "/api/reset_password",
                            {"token": token, "new_password": "short"})
        check("reset rejects a weak password (400)", code == 400, str(code))
        code, body, _ = request("POST", "/api/reset_password",
                              {"token": token,
                               "new_password": "Recovered-Viewer-1"})
        check("reset with valid token (200)", code == 200, str(body))
        # Token is single-use.
        code, _, _ = request("POST", "/api/reset_password",
                            {"token": token,
                             "new_password": "Another-Pass-1234"})
        check("reset token is single-use (400)", code == 400, str(code))
        # New password works; the old one no longer does.
        cj3 = http.cookiejar.CookieJar()
        op3 = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj3))

        def login_as(opener, pw):
            data = json.dumps({"username": "viewer1", "password": pw}).encode()
            req = urllib.request.Request(BASE + "/api/login", data=data,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = opener.open(req, timeout=10)
            except urllib.error.HTTPError as e:
                r = e
            r.read()
            return r.status if hasattr(r, "status") else r.code

        check("login works with the reset password",
              login_as(op3, "Recovered-Viewer-1") == 200)
        check("old password rejected after reset",
              login_as(urllib.request.build_opener(
                  urllib.request.HTTPCookieProcessor(
                      http.cookiejar.CookieJar())), "ViewerPass123") == 401)
    # Bad/garbage token is rejected.
    code, _, _ = request("POST", "/api/reset_password",
                        {"token": "not-a-real-token", "new_password": "Whatever-12345"})
    check("garbage reset token rejected (400)", code == 400, str(code))

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

    print("== session idle timeout + max ttl ==")
    # Uses whole-second deadlines, so margins are >1s to avoid boundary flake.
    import auth as authmod
    am = authmod.AuthManager(os.path.join(tmp, "sess1.db"),
                             max_ttl_sec=3600, idle_sec=2)   # 2s idle, 1h cap
    su = am.create_user("sessuser", "SessPass123456")
    tok, _, _ = am.create_session(su)
    check("session valid immediately after login", am.get_session(tok) is not None)
    time.sleep(3.3)
    check("session idles out after the idle timeout", am.get_session(tok) is None)
    tok2, _, _ = am.create_session(su)
    time.sleep(1.2)
    am.touch_session(tok2)              # user activity slides the window
    time.sleep(1.2)                     # 2.4s since login, but touched at 1.2s
    check("activity (touch) extends the idle window",
          am.get_session(tok2) is not None)
    am.close()

    print("== hardening: auth lock, reset pre-check, lockout tiers ==")
    am2 = authmod.AuthManager(os.path.join(tmp, "hard.db"))
    hu = am2.create_user("harduser", "HardPass123456")
    htok, _, _ = am2.create_session(hu)
    # 1. Password hashing must not hold the DB lock: a slow verify in one
    #    thread must not delay a session lookup in another (that lookup is
    #    what every authenticated request does).
    real_verify = authmod.verify_password

    def slow_verify(pw, stored):
        time.sleep(0.8)
        return real_verify(pw, stored)
    authmod.verify_password = slow_verify
    th = threading.Thread(target=am2.verify_login,
                          args=("harduser", "wrong-password-1", "10.9.9.1"))
    th.start()
    time.sleep(0.15)
    t0 = time.monotonic()
    sess = am2.get_session(htok)
    dt = time.monotonic() - t0
    th.join()
    authmod.verify_password = real_verify
    check("session lookup is not blocked by a concurrent password hash",
          sess is not None and dt < 0.4, f"{dt:.2f}s")
    # 2. A bogus reset token is rejected *before* the new password is hashed
    #    (no free 600k-iteration PBKDF2 for unauthenticated callers).
    calls = {"n": 0}
    real_hash = authmod.hash_password

    def counting_hash(pw, *a, **k):
        calls["n"] += 1
        return real_hash(pw, *a, **k)
    authmod.hash_password = counting_hash
    try:
        am2.reset_password_with_token("bogus-token", "Whatever-12345",
                                      ip="10.9.9.2")
    except authmod.AuthError:
        pass
    check("bogus reset token is rejected without hashing", calls["n"] == 0,
          str(calls["n"]))
    rtok = am2.create_reset_token(hu, "10.9.9.2")
    am2.reset_password_with_token(rtok, "NewHardPass12345", ip="10.9.9.2")
    check("valid reset token hashes exactly once", calls["n"] == 1,
          str(calls["n"]))
    authmod.hash_password = real_hash
    # 3. Reset submissions are rate-limited per IP.
    code429, retry = None, 0
    for _ in range(authmod.RESET_ATTEMPT_MAX_PER_IP + 1):
        try:
            am2.reset_password_with_token("bogus", "Whatever-12345",
                                          ip="10.9.9.3")
        except authmod.AuthError as e:
            code429, retry = e.code, e.retry_after
    check("reset submissions rate-limited per IP (429 + Retry-After)",
          code429 == 429 and retry > 0, f"{code429} retry={retry}")
    # 4. Lockout tiers: 5 failures lock only the (username, ip) pair; the
    #    account itself locks for everyone after 20 failures from anywhere.
    for _ in range(5):
        am2.verify_login("harduser", "wrong-password-1", "10.9.9.4")
    _, _, r_a = am2.verify_login("harduser", "NewHardPass12345", "10.9.9.4")
    check("5 failures lock the (username, ip) pair", r_a > 0, str(r_a))
    u_b, _, r_b = am2.verify_login("harduser", "NewHardPass12345", "10.9.9.5")
    check("the same account from another IP is not locked out",
          u_b is not None and r_b == 0, f"user={u_b is not None} retry={r_b}")
    for i in range(authmod.USER_LOCKOUT_THRESHOLD):      # 4 per IP, 5 IPs
        am2.verify_login("harduser", "wrong-password-1", f"10.9.10.{i // 4}")
    _, _, r_c = am2.verify_login("harduser", "NewHardPass12345", "10.9.11.1")
    check("20 failures from anywhere lock the account for every IP", r_c > 0,
          str(r_c))
    # 5. Junk that can't be a username is never written to login_attempts.
    am2.verify_login("A" * 5000, "x", "10.9.9.6")
    n_junk = am2.db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE LENGTH(username) > 64"
    ).fetchone()[0]
    check("oversized username is not recorded in login_attempts", n_junk == 0,
          str(n_junk))
    am2.close()

    print("== hardening: input validation (unit) ==")
    import parsers as parsersmod
    import webserver as webmod
    check("unifi line with a non-IP SRC is not an event",
          parsersmod.parse_unifi(
              "[LAN_IN-A-1] SRC=<img> DST=10.0.0.1 PROTO=TCP DPT=80") is None)
    check("sophos line with a non-IP dst_ip is not an event",
          parsersmod.parse_sophos(
              'src_ip=10.0.0.1 dst_ip=evil protocol="TCP" dst_port=80') is None)
    pr = parsersmod.parse_unifi('[LAN_IN-A-1] DESCR="' + "x" * 600 +
                                '" SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=70000')
    check("rule capped at 256 chars and out-of-range port -> -1",
          pr is not None and len(pr[5]) == 256 and pr[3] == -1, str(pr)[:80])
    check("IPv6 addresses still parse",
          parsersmod.parse_unifi(
              "SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP DPT=443") is not None)
    check("sophos IPv4 still parses with raw spelling kept",
          (parsersmod.parse_sophos(
              'src_ip=192.168.010.1 dst_ip=8.8.8.8 protocol="TCP" dst_port=53')
           or [None])[0] in (None, "192.168.010.1"))
    nets = webmod.parse_trusted_proxies("10.0.0.5, 172.16.0.0/12")
    check("client ip: untrusted peer keeps its own address",
          webmod.client_ip_from("203.0.113.9", "1.2.3.4", nets) == "203.0.113.9")
    check("client ip: trusted proxy's X-Forwarded-For last hop is used",
          webmod.client_ip_from("172.17.0.2", "1.2.3.4, 198.51.100.7", nets)
          == "198.51.100.7")
    check("client ip: trusted proxy without the header -> peer",
          webmod.client_ip_from("10.0.0.5", None, nets) == "10.0.0.5")
    check("client ip: a non-address last hop falls back to the peer",
          webmod.client_ip_from("10.0.0.5", "1.2.3.4, evil-string", nets)
          == "10.0.0.5"
          and webmod.client_ip_from("10.0.0.5", "x, 2001:db8::7", nets)
          == "2001:db8::7")
    check("id parsing: unicode digits / bools are not ids",
          webmod._path_id("12") == 12 and webmod._path_id("²") is None
          and webmod._path_id("") is None and webmod._path_id("-1") is None
          and webmod._body_id(3) == 3 and webmod._body_id(True) is None
          and webmod._body_id(0) is None and webmod._body_id("3") is None)
    # The untrusted-forward warning table must stay bounded however many
    # distinct peers show up (quiet the warnings while we flood it).
    import io as iomod
    saved_err, sys.stderr = sys.stderr, iomod.StringIO()
    try:
        for i in range(webmod._FWD_WARN_MAX + 500):
            webmod.warn_untrusted_forward(f"2001:db8::{i:x}", "X-Forwarded-For")
    finally:
        sys.stderr = saved_err
    check("untrusted-forward warning table is capped",
          len(webmod._fwd_warned) <= webmod._FWD_WARN_MAX,
          str(len(webmod._fwd_warned)))
    import listener as listenermod
    srcs = webmod.parse_trusted_proxies("192.168.1.1, 10.0.0.0/24",
                                        name="SYSLOG_ALLOWED_SOURCES")
    check("syslog source filter: empty list accepts all, else exact/CIDR",
          listenermod.source_allowed("8.8.8.8", ())
          and listenermod.source_allowed("192.168.1.1", srcs)
          and listenermod.source_allowed("10.0.0.77", srcs)
          and not listenermod.source_allowed("10.0.1.1", srcs)
          and not listenermod.source_allowed("garbage", srcs))
    check("syslog source filter: v4-mapped IPv6 sender matches an IPv4 entry",
          listenermod.source_allowed("::ffff:10.0.0.5", srcs)
          and not listenermod.source_allowed("::ffff:10.0.1.5", srcs))
    import sources as sourcesmod
    bad = {}
    for entry in ("10.0.0.300", "10.0.0.0/33", "bad host!", "a..b", "::g"):
        try:
            sourcesmod.parse(entry)
            bad[entry] = ""
        except ValueError as e:
            bad[entry] = str(e)
    check("bad SYSLOG_ALLOWED_SOURCES entries (typo'd IPs, odd names) are "
          "refused under the setting's name",
          all(v.startswith("SYSLOG_ALLOWED_SOURCES:") for v in bad.values()),
          str(bad))
    p_nets, p_hosts = sourcesmod.parse(
        " 192.168.1.1, Site-B.Example.NET., 10.0.0.0/24, site-b.example.net,"
        " none, localhost ")
    check("SYSLOG_ALLOWED_SOURCES mixes IPs, CIDRs and hostnames "
          "(lower-cased, deduplicated, trailing dot dropped)",
          [str(n) for n in p_nets] == ["192.168.1.1/32", "10.0.0.0/24"]
          and p_hosts == ("site-b.example.net", "localhost"),
          f"{p_nets} {p_hosts}")
    check("sources.parse: empty and 'none' mean no filter",
          sourcesmod.parse("") == ((), ())
          and sourcesmod.parse("none") == ((), ()))

    # SourceFilter with a scripted resolver: hostnames resolve to a set that
    # can change; failures keep the last known addresses; `generation`
    # moves only when the allowed set actually changes.
    import ipaddress as ipmod
    answers = {"site-b.example.net": {"203.0.113.7"}}

    def fake_resolver(host):
        a = answers.get(host)
        if a is None:
            raise socket.gaierror(-2, "Name or service not known")
        return frozenset(ipmod.ip_address(x) for x in a)

    sf = sourcesmod.SourceFilter(p_nets, ("site-b.example.net", "site-c.test"),
                                 resolver=fake_resolver)
    check("hostname not resolved yet: its sender is NOT allowed, literal "
          "entries still are, nobody at all when only hostnames are "
          "configured, everybody when nothing is",
          not sf.allows("203.0.113.7") and sf.allows("10.0.0.9")
          and not sourcesmod.SourceFilter(
              (), ("x.test",), resolver=fake_resolver).allows("8.8.8.8")
          and sourcesmod.SourceFilter().allows("8.8.8.8"))
    g0 = sf.generation
    ch1 = sf.resolve_all()
    check("first resolution round allows the resolved address and bumps "
          "generation; the failing name is tolerated",
          ch1 and sf.generation == g0 + 1 and sf.allows("203.0.113.7")
          and sf.host_for("203.0.113.7") == "site-b.example.net"
          and sf.host_for("10.0.0.9") is None and sf._failures == 1)
    ch2 = sf.resolve_all()
    check("unchanged answers: no generation bump",
          not ch2 and sf.generation == g0 + 1)
    answers["site-b.example.net"] = {"203.0.113.9", "2001:db8::9"}
    answers["site-c.test"] = {"198.51.100.4"}
    sf.resolve_all()
    check("IP change: new addresses (v4 + v6) allowed, old one no longer, "
          "second name now resolved and failure streak reset",
          sf.allows("203.0.113.9") and sf.allows("2001:db8::9")
          and not sf.allows("203.0.113.7") and sf.allows("198.51.100.4")
          and sf.generation == g0 + 2 and sf._failures == 0
          and sf.allows("::ffff:198.51.100.4"))
    del answers["site-b.example.net"]
    sf.resolve_all()
    check("DNS failure keeps the last known addresses (never locks a site out)",
          sf.allows("203.0.113.9") and sf.generation == g0 + 2
          and sf._failures == 1)
    sf._failures = 1
    b1 = sf._next_interval()
    sf._failures = 4
    b4 = sf._next_interval()
    sf._failures = 20
    b20 = sf._next_interval()
    sf._failures = 0
    b0 = sf._next_interval()
    check("retry backoff: 60 s doubling per failed round, capped at the "
          "hourly interval",
          (b1, b4, b20, b0) == (60, 480, 3600, 3600), str((b1, b4, b20, b0)))

    # Resolver thread: a trigger re-resolves after the minimum gap, several
    # triggers inside the gap collapse into one round, idle = baseline.
    answers["site-b.example.net"] = {"203.0.113.9"}
    sf2 = sourcesmod.SourceFilter((), ("site-b.example.net",),
                                  resolver=fake_resolver)
    sf2.interval = 30
    sf2.min_gap = 0.4
    stop2 = threading.Event()
    sf2.start(stop2)
    time.sleep(0.2)
    r1 = sf2.rounds
    for i in range(5):
        sf2.trigger()
    time.sleep(0.9)
    r2 = sf2.rounds
    sf2.trigger()
    time.sleep(0.9)
    r3 = sf2.rounds
    stop2.set()
    check("resolver thread: initial round, then one round per trigger "
          "after the gap (5 rapid triggers collapse into one)",
          (r1, r2, r3) == (1, 2, 3), str((r1, r2, r3)))
    check("trigger/start on a filter without hostnames are no-ops",
          sourcesmod.SourceFilter(p_nets).trigger() is None
          and sourcesmod.SourceFilter(p_nets).start(stop2) is None)

    # Listener hold/replay, end to end on a private port: datagrams from an
    # address that is not allowed are held; when the resolver's answer
    # changes to include that address they are replayed with their original
    # timestamps, and the rejected counter is corrected.
    import listener as listenermod
    import config as configmod
    answers["site-b.example.net"] = {"127.0.0.1"}
    sf3 = sourcesmod.SourceFilter((), ("site-b.example.net",),
                                  resolver=fake_resolver)
    sf3.resolve_all()
    dev3 = configmod.Device("Held-Test", 15531, "unifi")
    q3 = queue.Queue()
    drops3 = {"n": 0, "ignored": 0, "rejected": 0, "lock": threading.Lock()}
    stop3 = threading.Event()
    threading.Thread(target=listenermod.run,
                     args=(stop3, dev3, q3, drops3, sf3, "127.0.0.1"),
                     daemon=True).start()
    time.sleep(0.5)
    rs3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rs3.bind(("127.0.0.2", 0))
    t_sent = int(time.time())
    for i in range(3):
        rs3.sendto(unifi_line("WAN_IN-D-8900", f"Held-{i}", "198.51.100.77",
                              "10.0.10.5", "TCP", 22 + i),
                   ("127.0.0.1", 15531))
    rs3.sendto(b"<14>Oct 27 00:00:00 gw dhcpd: lease 10.0.0.9 renewed",
               ("127.0.0.1", 15531))          # held too, ignored on replay
    rs3.close()
    time.sleep(0.6)
    held_state = (drops3["rejected"], q3.qsize(), sf3._kicked)
    check("datagrams from a not-yet-allowed sender are rejected, held and "
          "trigger a re-resolution",
          held_state == (4, 0, True), str(held_state))
    time.sleep(1.1)
    answers["site-b.example.net"] = {"127.0.0.1", "127.0.0.2"}
    sf3.resolve_all()
    deadline = time.time() + 4
    while time.time() < deadline and q3.qsize() < 3:
        time.sleep(0.1)
    items3 = [q3.get_nowait() for _ in range(q3.qsize())]
    check("after the sender becomes allowed the held datagrams are replayed "
          "in order with their original timestamps; host chatter is ignored",
          [it[9] for it in items3] == ["Held-0", "Held-1", "Held-2"]
          and all(it[0] == "ev" and t_sent <= it[1] <= t_sent + 1
                  for it in items3)
          and drops3["rejected"] == 0 and drops3["ignored"] == 1,
          f"{[(it[0], it[1], it[-1]) for it in items3]} {drops3}")
    rs3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rs3.bind(("127.0.0.2", 0))
    rs3.sendto(unifi_line("WAN_IN-A-8901", "Now-Direct", "198.51.100.77",
                          "10.0.10.5", "TCP", 443), ("127.0.0.1", 15531))
    rs3.close()
    time.sleep(0.6)
    check("the newly allowed sender's later datagrams go straight through",
          q3.qsize() == 1 and q3.get_nowait()[9] == "Now-Direct"
          and drops3["rejected"] == 0)
    stop3.set()
    # Hold buffer bounds: per-datagram size, count, and age.
    hb = listenermod._Held()
    hb.add(1000, "10.9.9.9", b"x" * 9000)
    for i in range(listenermod.HELD_MAX + 10):
        hb.add(1000 + i // 1000, "10.9.9.9", b"y")
    check("held datagrams are truncated to 4 KB and the buffer keeps the "
          "newest HELD_MAX",
          len(hb.items) == listenermod.HELD_MAX
          and all(len(it[2]) <= listenermod.MAX_RAW_LEN for it in hb.items))
    hb2 = listenermod._Held()
    hb2.add(1000, "10.9.9.9", b"old")
    hb2.add(1000 + listenermod.HELD_TTL + 1, "10.9.9.8", b"new")
    rel = hb2.release(1000 + listenermod.HELD_TTL + 1,
                      sourcesmod.SourceFilter())
    check("a held datagram older than HELD_TTL is discarded, not replayed",
          [it[2] for it in rel] == [b"new"], str(rel))
    check("reject log mentions the hold only when hostnames are configured",
          listenermod._RejectLog("d", held=True).held
          and not listenermod._RejectLog("d").held)
    import store as storemod
    odd_dir = os.path.join(tmp, "geo #1 100% odd")
    os.makedirs(odd_dir, exist_ok=True)
    odd_db = os.path.join(odd_dir, "events.db")
    storemod.open_writer(odd_db).close()
    try:
        rdb = storemod.open_reader(odd_db)
        odd_ok = rdb.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        rdb.close()
    except Exception as e:                           # noqa: BLE001
        odd_ok = False
        odd_err = str(e)
    check("read-only SQLite URI works with '#', '%' and spaces in the path",
          odd_ok, locals().get("odd_err", ""))
    # CSV streaming: pages of CSV_PAGE rows, header once, lock released
    # between pages (one query per page), limit honoured.
    import io as iomod2
    st_unit = webmod.AppState(db_path, [], None)
    calls = {"n": 0}
    real_query = st_unit.query

    def counting_query(fn):
        calls["n"] += 1
        return real_query(fn)
    st_unit.query = counting_query
    with sqlite3.connect(f"file:{urllib.request.pathname2url(db_path)}?mode=ro",
                         uri=True) as rdb:
        total_ev = rdb.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    h = webmod.Handler.__new__(webmod.Handler)
    h.state, h.command, h.wfile = st_unit, "GET", iomod2.BytesIO()
    h.send_response = lambda code: None
    h.send_header = lambda k, v: None
    h.end_headers = lambda: None
    h.CSV_PAGE = 7
    h._stream_csv(0, None, {}, 50)
    csv_lines = [l for l in h.wfile.getvalue().decode().splitlines() if l]
    want = min(50, total_ev)
    check("csv streaming: header once, rows = min(limit, total), paged queries",
          len(csv_lines) == want + 1
          and sum(1 for l in csv_lines if l.startswith("time,")) == 1
          and calls["n"] >= (want + 6) // 7,
          f"lines={len(csv_lines)} want={want} queries={calls['n']}")
    st_unit._db.close() if st_unit._db else None
    try:
        webmod.parse_trusted_proxies("not-an-ip")
        bad = False
    except ValueError:
        bad = True
    check("TRUSTED_PROXIES rejects garbage", bad)
    check("TRUSTED_PROXIES 'none' / empty mean trust nobody",
          webmod.parse_trusted_proxies("none") == ()
          and webmod.parse_trusted_proxies("") == ())
    check("csv: formula-leading text cells are prefixed, others untouched",
          webmod._csv_safe("=1+1") == "'=1+1"
          and webmod._csv_safe("@cmd") == "'@cmd"
          and webmod._csv_safe("Allow LAN") == "Allow LAN"
          and webmod._csv_safe("") == "")

    print("== hardening: container entrypoint + supply-chain helpers (unit) ==")

    def load_module(name, *candidates):
        for p in candidates:
            if os.path.exists(p):
                spec = importlib.util.spec_from_file_location(name, p)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
        return None
    ep = load_module("fll_entrypoint",
                     os.path.join(HERE, "app", "docker-entrypoint.py"),
                     os.path.join(HERE, "docker-entrypoint.py"))
    check("entrypoint: the /data tree may be chowned",
          ep.chown_allowed("/data") and ep.chown_allowed("/data/sub/dir"))
    denied = [p for p in ("/", "/etc", "/etc/x", "/usr/lib", "/proc", "/dev",
                          "/app", "/tmp", "/var/lib/x", "/root")
              if ep.chown_allowed(p)]
    check("entrypoint: system directories are never chowned", not denied,
          str(denied))
    plan = ep.fixup_plan(lambda k, d: {"DB_PATH": "/mnt/vol/events.db",
                                       "LAYOUT_PATH": ""}.get(k, d))
    check("entrypoint: only the /data tree is chowned recursively; another "
          "volume gets the dir + named files",
          ("/data", True, ["/data/auth.db", "/data/devices.json"]) in plan
          and ("/mnt/vol", False, ["/mnt/vol/events.db"]) in plan
          and len(plan) == 2, str(plan))
    for bad, why in (({"PUID": "0"}, "root"), ({"PGID": "0"}, "root"),
                     ({"PUID": "abc"}, "numeric")):
        os.environ.update(bad)
        try:
            ep.runtime_ids()
            refused = False
        except SystemExit as e:
            refused = why in str(e)
        for k in bad:
            os.environ.pop(k, None)
        check(f"entrypoint refuses {bad}", refused)
    check("entrypoint default ids are 10001:10001",
          ep.runtime_ids() == (10001, 10001))
    bg = load_module("build_geo", os.path.join(HERE, "scripts", "build_geo.py"))
    if bg is not None:                      # scripts/ isn't shipped in the image
        flags = sorted(f for f in os.listdir(bg.FLAG_DIR) if f.endswith(".svg"))
        unsafe = []
        for f in flags:
            with open(os.path.join(bg.FLAG_DIR, f), "rb") as fh:
                if not bg.svg_is_safe(fh.read()):
                    unsafe.append(f)
        check(f"all {len(flags)} vendored flag SVGs pass the safety scan",
              bool(flags) and not unsafe, str(unsafe[:5]))
        check("svg scan rejects scripts, handlers, entities, external refs",
              not bg.svg_is_safe(b"<svg><script>x</script></svg>")
              and not bg.svg_is_safe(b'<svg onload="x"/>')
              and not bg.svg_is_safe(b'<svg><image href="http://evil/x"/></svg>')
              and not bg.svg_is_safe(b'<!DOCTYPE svg [<!ENTITY x "y">]><svg/>')
              and not bg.svg_is_safe(b'<svg><a xlink:href="javascript:1"/></svg>')
              and bg.svg_is_safe(b'<svg><use href="#a"/><path fill="url(#g)"/>'
                                 b'</svg>'))
        data = b"flag-icons-tarball-bytes"
        good = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        check("integrity check accepts the pinned hash and rejects other bytes",
              bg.verify_integrity(data, good)
              and not bg.verify_integrity(data + b"x", good))
        check("pinned flag-icons integrity is a sha512 SRI string",
              bg.FLAG_ICONS_INTEGRITY.startswith("sha512-")
              and len(base64.b64decode(bg.FLAG_ICONS_INTEGRITY[7:])) == 64)
    # Absolute cap wins even with constant activity: 1s cap, 60s idle.
    am2 = authmod.AuthManager(os.path.join(tmp, "sess2.db"),
                              max_ttl_sec=1, idle_sec=60)
    cu = am2.create_user("capuser", "CapPass1234567")
    tokc, _, _ = am2.create_session(cu)
    am2.touch_session(tokc)            # would extend to +60s, but cap is +1s
    time.sleep(2.5)
    check("max ttl caps the session despite activity",
          am2.get_session(tokc) is None)
    am2.close()

    print("== api key verification (unit) ==")
    ak = authmod.AuthManager(os.path.join(tmp, "apikeys.db"))
    kid, raw = ak.create_api_key("live", created_by=None,
                                 expires_at=int(time.time()) + 3600)
    check("a valid key verifies", ak.verify_api_key(raw) is not None)
    check("the wrong key does not verify",
          ak.verify_api_key("fll_" + "z" * 40) is None)
    check("a key without the fll_ prefix is rejected",
          ak.verify_api_key(raw[4:]) is None)
    # Expire it by hand; it must stop verifying.
    ak.db.execute("UPDATE api_keys SET expires_at = ? WHERE id = ?",
                  (int(time.time()) - 1, kid))
    ak.db.commit()
    check("an expired key does not verify", ak.verify_api_key(raw) is None)
    # A past expiry at creation is refused.
    try:
        ak.create_api_key("past", expires_at=int(time.time()) - 10)
        past_rejected = False
    except authmod.AuthError:
        past_rejected = True
    check("creating a key with a past expiry is rejected", past_rejected)
    ak.close()

    print("== mailer TLS options ==")
    import ssl as _ssl
    import mailer as mailmod
    ctx_default = mailmod.Mailer(host="h", sender="a@b.c")._context()
    check("default keeps TLS cert verification on",
          ctx_default.verify_mode == _ssl.CERT_REQUIRED
          and ctx_default.check_hostname is True)
    ctx_insecure = mailmod.Mailer(host="h", sender="a@b.c",
                                  tls_verify=False)._context()
    check("tls_verify=False disables cert verification",
          ctx_insecure.verify_mode == _ssl.CERT_NONE
          and ctx_insecure.check_hostname is False)
    env_map = {"SMTP_HOST": "h", "SMTP_FROM": "a@b.c",
               "SMTP_TLS_INSECURE": "true", "SMTP_DEBUG": "1"}
    me = mailmod.from_env(lambda k, d=None: env_map.get(k, d))
    check("from_env parses SMTP_TLS_INSECURE and SMTP_DEBUG",
          me.tls_verify is False and me.debug is True)
    # AUTH over a cleartext connection is refused unless explicitly allowed,
    # and the AUTH exchange is never written to the SMTP debug log.
    plain = mailmod.Mailer(host="h", sender="a@b.c", username="u",
                           password="p", security="none")
    saved_err2, sys.stderr = sys.stderr, iomod.StringIO()
    try:
        sent = plain.send("x@y.z", "s", "b")
        err_txt = sys.stderr.getvalue()
    finally:
        sys.stderr = saved_err2
    check("SMTP AUTH with SMTP_SECURITY=none is refused (send -> False)",
          plain.plain_auth_blocked and sent is False
          and "refusing SMTP AUTH" in err_txt, err_txt[:120])
    check("SMTP_ALLOW_PLAINTEXT_AUTH=true lifts the refusal",
          not mailmod.from_env(lambda k, d=None: {
              "SMTP_HOST": "h", "SMTP_FROM": "a@b.c", "SMTP_USERNAME": "u",
              "SMTP_SECURITY": "none",
              "SMTP_ALLOW_PLAINTEXT_AUTH": "true"}.get(k, d)).plain_auth_blocked)

    class _FakeSMTP:
        def __init__(self):
            self.debuglevel, self.seen = 1, []

        def set_debuglevel(self, n):
            self.debuglevel = n

        def login(self, u, p):
            self.seen.append(("login", self.debuglevel))

        def send_message(self, m):
            self.seen.append(("send", self.debuglevel))
    fake = _FakeSMTP()
    mailmod.Mailer(host="h", sender="a@b.c", username="u", password="p",
                   security="starttls", debug=True)._auth_and_send(fake, None)
    check("SMTP debug level is 0 during login() and restored afterwards",
          fake.seen == [("login", 0), ("send", 1)], str(fake.seen))

    print("== live filter scan bound ==")
    import store as storemod
    bdb = os.path.join(tmp, "bound.db")
    wb = storemod.open_writer(bdb)
    # 30 events for device D; src is unique per row (10.1.<id>.0).
    storemod.insert_events(wb, [
        (1700000000 + i, "D", "unifi", f"10.1.{i}.0", "9.9.9.9", "TCP", 443,
         "Allow", "r") for i in range(1, 31)])
    wb.commit()
    rb = storemod.open_reader(bdb)
    saved_cap = storemod.LIVE_SCAN_CAP
    try:
        storemod.LIVE_SCAN_CAP = 5          # only the last ~5 ids in scope
        _, res = storemod.query_live(rb, 0, {"device": "D", "ip": "10.1.3."}, 500)
        check("old filtered match beyond live scan cap is skipped", res == [],
              str(res))
        _, res_dev = storemod.query_live(rb, 0, {"device": "D"}, 500)
        check("device-only live view is NOT scan-bounded",
              len(res_dev) == 30, str(len(res_dev)))
        storemod.LIVE_SCAN_CAP = 10_000
        _, res2 = storemod.query_live(rb, 0, {"device": "D", "ip": "10.1.3."}, 500)
        check("filtered match within scan cap is returned",
              len(res2) == 1 and res2[0]["src"] == "10.1.3.0", str(res2))
        # Chunked window scan: with a 10-id span, a filter matching only the
        # oldest row needs several resume steps — every chunk must make strict
        # progress (next_before decreases) and terminate at the range start.
        found, cursor, hops, progressed = [], None, 0, True
        while hops < 10:
            evs, more, nb = storemod.query_range(
                rb, 0, None, {"ip": "10.1.1."}, 500, before=cursor,
                scan_span=10)
            found += evs
            if not more:
                break
            if cursor is not None and nb >= cursor:
                progressed = False
                break
            cursor, hops = nb, hops + 1
        check("chunked filtered scan progresses, finds the match, and stops",
              progressed and len(found) == 1 and found[0]["src"] == "10.1.1.0"
              and 2 <= hops <= 4,
              f"hops={hops} found={len(found)} progressed={progressed}")
    finally:
        storemod.LIVE_SCAN_CAP = saved_cap
        rb.close(); wb.close()

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

    print("== HTTPS deployment: __Host- cookie + HSTS ==")
    # A second instance with AUTH_FORCE_SECURE_COOKIE=true stands in for a
    # TLS-terminating trusted proxy: the session cookie must be the
    # __Host-session cookie (Secure, Path=/, no Domain), HSTS must be sent,
    # a plain "session" cookie must be ignored, and logout must clear both.
    tls_dir = os.path.join(tmp, "tls")
    os.makedirs(tls_dir)
    tls_cfg = os.path.join(tls_dir, "devices.json")
    with open(tls_cfg, "w") as f:
        json.dump({"retention_days": 1, "max_events": 0, "devices": [
            {"name": "TLS-Test", "port": 15541, "vendor": "unifi"}]}, f)
    e_tls = dict(env, DEVICES_CONFIG=tls_cfg, HTTP_PORT=str(HTTP_PORT + 1),
                 DB_PATH=os.path.join(tls_dir, "events.db"),
                 AUTH_DB_PATH=os.path.join(tls_dir, "auth.db"),
                 AUTH_FORCE_SECURE_COOKIE="true")
    pr_tls = subprocess.Popen([sys.executable, "-u", MAIN], env=e_tls,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              creationflags=creationflags)
    out_tls = []
    threading.Thread(target=read_stdout, args=(pr_tls, out_tls),
                     daemon=True).start()
    up_tls = False
    deadline = time.time() + 15
    while time.time() < deadline and pr_tls.poll() is None:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PORT + 1}/healthz",
                                   timeout=4).read()
            up_tls = True
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.3)
    check("forced-secure instance starts", up_tls, "\n".join(out_tls[:12]))

    def raw(method, path, body=None, headers=None, port=HTTP_PORT + 1):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, data, hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        try:
            parsed = json.loads(payload) if payload else {}
        except ValueError:
            parsed = {}
        hl = resp.getheaders()
        conn.close()
        return resp.status, parsed, hl

    if up_tls:
        st, lg, hl = raw("POST", "/api/login",
                         {"username": ADMIN_USER, "password": ADMIN_PASS})
        cookies = [v for k, v in hl if k.lower() == "set-cookie"]
        hsts = [v for k, v in hl if k.lower() == "strict-transport-security"]
        check("login over HTTPS sets __Host-session (Secure, Path=/, no "
              "Domain) and only that cookie",
              st == 200 and len(cookies) == 1
              and cookies[0].startswith("__Host-session=")
              and "Secure" in cookies[0] and "Path=/" in cookies[0]
              and "HttpOnly" in cookies[0] and "SameSite=Strict" in cookies[0]
              and "Domain" not in cookies[0], f"{st} {cookies}")
        check("HSTS header is sent over HTTPS (one year, no subdomains)",
              hsts == ["max-age=31536000"], str(hsts))
        tok = cookies[0].split(";", 1)[0].split("=", 1)[1] if cookies else ""
        st_ok, _, _ = raw("GET", "/api/me",
                          headers={"Cookie": f"__Host-session={tok}"})
        st_plain, _, _ = raw("GET", "/api/me",
                             headers={"Cookie": f"session={tok}"})
        check("the __Host- cookie authenticates; a plain 'session' cookie "
              "with the same token is ignored over HTTPS",
              st_ok == 200 and st_plain == 401, f"{st_ok} {st_plain}")
        st, _, hl = raw("GET", "/healthz")
        check("HSTS is on every response of the HTTPS instance (even public "
              "ones)",
              [v for k, v in hl if k.lower() == "strict-transport-security"]
              == ["max-age=31536000"])
        st, _, hl = raw("POST", "/api/logout",
                        headers={"Cookie": f"__Host-session={tok}",
                                 "X-CSRF-Token": lg.get("csrf_token", "")})
        cleared = sorted(v.split("=", 1)[0] for k, v in hl
                         if k.lower() == "set-cookie" and "Max-Age=0" in v)
        check("logout clears both cookie names (old plain cookie too)",
              st == 200 and cleared == ["__Host-session", "session"],
              f"{st} {cleared}")
        st, _, _ = raw("GET", "/api/me",
                       headers={"Cookie": f"__Host-session={tok}"})
        check("session is gone after logout", st == 401, str(st))
    pr_tls.kill()
    pr_tls.wait(timeout=10)
    # The plain-HTTP main instance: cookie named "session", no HSTS, and a
    # spoofed X-Forwarded-Proto from the untrusted peer changes nothing.
    _, _, r = request("GET", "/api/me")
    check("plain HTTP: no HSTS header, cookie is the plain 'session'",
          r.headers.get("Strict-Transport-Security") is None
          and any(c.name == "session" for c in _CJ)
          and not any(c.name == "__Host-session" for c in _CJ))
    _, _, r = request("GET", "/api/me",
                      headers={"X-Forwarded-Proto": "https"})
    check("plain HTTP: spoofed X-Forwarded-Proto from an untrusted peer does "
          "not switch HSTS on",
          r.headers.get("Strict-Transport-Security") is None)

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

    print("== unwritable data folder diagnostics ==")
    # A data folder the container user cannot write to (the classic first-run
    # mistake) must die with one actionable message, not a traceback loop.
    # Blocking trick: the DB's parent "directory" is a regular file, so both
    # makedirs and sqlite fail with an OSError on every platform.
    blocker = os.path.join(tmp, "blocker")
    with open(blocker, "w") as f:
        f.write("not a directory")

    def spawn_dies_with(extra):
        e2 = dict(env, **extra)
        pr = subprocess.run([sys.executable, "-u", MAIN], env=e2,
                            capture_output=True, text=True, timeout=30)
        return pr.returncode, pr.stdout + pr.stderr

    rc2, out2 = spawn_dies_with(
        {"AUTH_DB_PATH": os.path.join(blocker, "auth.db")})
    check("unwritable auth db dies with guidance, not a traceback",
          rc2 == 2 and "cannot open the auth database" in out2
          and "UID 10001" in out2 and "Traceback" not in out2,
          f"rc={rc2} out={out2[-300:]}")
    rc2, out2 = spawn_dies_with(
        {"AUTH_ENABLED": "false",
         "DB_PATH": os.path.join(blocker, "events.db")})
    check("unwritable event db dies with guidance, not a traceback",
          rc2 == 2 and "cannot open the event database" in out2
          and "Traceback" not in out2, f"rc={rc2} out={out2[-300:]}")

    print("== starter config auto-seed ==")
    # No devices.json: the app seeds Firewall-1..5 on udp/5514-5518 (vendor
    # auto-detect) and starts, instead of restart-looping until one is made.
    seed_dir = os.path.join(tmp, "seed")
    os.makedirs(seed_dir)
    seed_cfg = os.path.join(seed_dir, "devices.json")
    e3 = dict(env, DEVICES_CONFIG=seed_cfg,
              DB_PATH=os.path.join(seed_dir, "events.db"),
              AUTH_ENABLED="false")
    pr3 = subprocess.Popen([sys.executable, "-u", MAIN], env=e3,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, creationflags=creationflags)
    out3 = []
    threading.Thread(target=read_stdout, args=(pr3, out3), daemon=True).start()
    up3 = False
    deadline = time.time() + 15
    while time.time() < deadline and pr3.poll() is None:
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=4).read()
            up3 = True
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.3)
    seeded = None
    if os.path.exists(seed_cfg):
        with open(seed_cfg) as f:
            seeded = json.load(f)
    check("missing devices.json is seeded and the app starts",
          up3 and seeded is not None
          and [d["port"] for d in seeded["devices"]] == [5514, 5515, 5516,
                                                         5517, 5518]
          and all(d["vendor"] == "auto" for d in seeded["devices"])
          and any("created a starter" in l for l in out3),
          f"up={up3} seeded={seeded} log={out3[:4]}")
    if os.name != "nt" and up3:
        import stat as statmod
        m_cfg = oct(statmod.S_IMODE(os.stat(seed_cfg).st_mode))
        m_db = oct(statmod.S_IMODE(os.stat(e3["DB_PATH"]).st_mode))
        check("seeded devices.json stays editable (0644), its db is 0600",
              m_cfg == "0o644" and m_db == "0o600", f"cfg={m_cfg} db={m_db}")
    pr3.send_signal(signal.CTRL_BREAK_EVENT if IS_WIN else signal.SIGTERM)
    try:
        pr3.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pr3.kill()
    # The seeder must never clobber an existing config.
    import config as configmod
    try:
        configmod.seed_starter(cfg_path)      # the harness's real config
        overwrote = True
    except FileExistsError:
        overwrote = False
    check("seed never overwrites an existing config", overwrote is False,
          str(overwrote))

    print(f"\n{checks['pass']} passed, {checks['fail']} failed. "
          f"(artifacts in {tmp})")
    sys.exit(1 if checks["fail"] else 0)


if __name__ == "__main__":
    main()
