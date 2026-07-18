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
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
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
               PRUNE_INTERVAL_SEC="2", RETENTION_DAYS="14")

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
            get_json("/api/stats")
            up = True
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.3)
    check("app started, http answering", up, "\n".join(out[:12]))
    if not up:
        proc.kill()
        sys.exit(1)

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
    # 31 UDM-Test + 25 Sophos-Test + 2 Mixed-Auto (1 unifi + 1 sophos) = 58.
    check("events stored and returned", len(evs) == 58, str(len(evs)))
    by = lambda **kw: [e for e in evs if all(e[k] == v for k, v in kw.items())]

    check("unifi allow parsed",
          len(by(device="UDM-Test", action="Allow", dst_port=443)) == 20)
    check("unifi guest drop -> Drop",
          len(by(device="UDM-Test", action="Drop", dst_port=445)) == 8)
    check("unifi ICMP -> port -1",
          len(by(device="UDM-Test", proto="ICMP", dst_port=-1)) == 3)
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
    f = get_json("/api/live?since=0&port=3389")
    check("port filter", all(e["dst_port"] == 3389 for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&ip=192.168.10.55")
    check("ip filter (src/dst substring)",
          all("192.168.10.55" in (e["src"], e["dst"]) for e in f["events"])
          and len(f["events"]) == 6, str(len(f["events"])))
    f = get_json("/api/live?since=0&device=UDM-Test")
    check("device filter",
          all(e["device"] == "UDM-Test" for e in f["events"])
          and len(f["events"]) == 31, str(len(f["events"])))

    print("== incremental cursor ==")
    tail = get_json(f"/api/live?since={live['cursor']}")
    check("no new events after cursor",
          tail["events"] == [] and tail["cursor"] == live["cursor"], str(tail))

    print("== stats + csv + unparsed ==")
    st = get_json("/api/stats")
    check("stats total = 58", st["total"] == 58, str(st["total"]))
    check("stats unparsed = 1", st["unparsed"] == 1, str(st["unparsed"]))
    check("stats devices active", sum(1 for d in st["devices"]
          if d["active"]) == 3)
    with urllib.request.urlopen(BASE + "/api/events.csv?window=86400",
                                timeout=10) as r:
        csv_text = r.read().decode()
        disp = r.headers.get("Content-Disposition", "")
    check("csv export", "attachment" in disp
          and csv_text.startswith("time,device,vendor,")
          and "Drop-RDP" in csv_text, disp)

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
