# firewall-live-log

A permanent, multi-device **live firewall log dashboard**. Each firewall
or gateway ships its syslog to its own UDP port; the dashboard shows a
real-time, colour-coded stream of every connection — source IP,
destination IP, protocol, port, and the allow/block verdict — across the
whole fleet at once, filterable by device, vendor, IP, and port.

Supports **UniFi** (UDM / UniFi OS, iptables-style logs) and **Sophos
Firewall** (SFOS v18–v22, key=value logs) simultaneously, with automatic
per-port vendor detection. Events are kept in SQLite with time-based
retention so you also get short-term history and CSV export.

- **Zero dependencies** — pure Python 3 standard library, one container.
- **One UDP port per device**, each labelled with a friendly name and
  vendor in a small JSON config.
- **Auto-detects UniFi vs Sophos** from the log format; override per port.
- **Green = allowed, red = blocked/dropped/rejected.**
- **Filter** by device, vendor, source/destination IP (substring), and
  port — live or over a historical window.
- **Retention** (default 14 days) with an optional row-count safety cap;
  old events are pruned automatically and space reclaimed.
- **CSV export** of any filtered window.

> For turning captured traffic into *firewall rules* (zone-pair analysis,
> rule candidates, port-range consolidation), see the companion project
> [unifi-syslog-analyzer](https://github.com/g-guglielmi/unifi-syslog-analyzer).
> This project is the always-on live view; that one is the batch
> rule-mining tool.

## Quick start

```sh
# 1. Create a data directory on the host (bind mount) and a device config.
sudo mkdir -p /srv/firewall-live-log
sudo cp devices.example.json /srv/firewall-live-log/devices.json
sudo chown -R 10001:10001 /srv/firewall-live-log   # container runs as uid 10001

# 2. Run. --network host is recommended for a syslog collector: it needs
#    many UDP ports and preserves each packet's real source IP.
docker run -d --name firewall-live-log --restart unless-stopped \
  --network host \
  -v /srv/firewall-live-log:/data \
  ghcr.io/g-guglielmi/firewall-live-log:latest
```

Open the dashboard at `http://<docker-host>:8080`, then point each
firewall's syslog at this host on the port you assigned it.

Pin a version for reproducible deploys:
`ghcr.io/g-guglielmi/firewall-live-log:v0.0.1`
(all versions under [Packages](https://github.com/g-guglielmi/firewall-live-log/pkgs/container/firewall-live-log)).

### Without host networking

If you can't use `--network host`, publish the ports explicitly. A
contiguous range is easiest — assign your devices ports in that range in
`devices.json`:

```sh
docker run -d --name firewall-live-log --restart unless-stopped \
  -p 8080:8080 -p 5514-5539:5514-5539/udp \
  -v /srv/firewall-live-log:/data \
  ghcr.io/g-guglielmi/firewall-live-log:latest
```

Note: Docker's UDP port-forwarding can rewrite the packet source IP in
some configurations. Since the source IP is exactly what a firewall log
is about, `--network host` is the safer choice for this collector.

## Device configuration (`devices.json`)

```json
{
  "retention_days": 14,
  "max_events": 0,
  "devices": [
    { "name": "UDM-HQ",          "port": 5514, "vendor": "unifi" },
    { "name": "Sophos-HQ",       "port": 5516, "vendor": "sophos" },
    { "name": "Unknown-Device",  "port": 5518, "vendor": "auto" }
  ]
}
```

- **name** — friendly label shown on the dashboard (must be unique).
- **port** — the UDP port this device sends syslog to (unique per device).
- **vendor** — `unifi`, `sophos`, or `auto` (detect from the log format).
- **retention_days** — how long events are kept (env `RETENTION_DAYS`
  overrides).
- **max_events** — optional hard cap on stored rows, `0` = disabled (env
  `MAX_EVENTS` overrides). A backstop against disk runaway on very busy
  fleets — see sizing below.

Editing `devices.json` takes effect on container restart.

## Configure the firewalls to send syslog

- **UniFi (UDM / UniFi OS):** Settings → CyberSecure → Traffic Logging →
  Flow Logging = *All Traffic* → Activity Logging (Syslog) → *SIEM
  Server* → this host, on that device's port.
- **Sophos Firewall (SFOS):** Configure → System services → Log settings
  → add a Syslog server (this host + the device's port, UDP) and enable
  *Firewall* traffic under the log selection.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DEVICES_CONFIG` | `/data/devices.json` | Path to the device config. |
| `DB_PATH` | `/data/events.db` | SQLite file (on the bind mount). |
| `HTTP_PORT` / `HTTP_BIND` | `8080` / `0.0.0.0` | Dashboard/API. |
| `RETENTION_DAYS` | `14` | Overrides the config value. |
| `MAX_EVENTS` | `0` | Row-count cap (0 = off); overrides config. |
| `PRUNE_INTERVAL_SEC` | `3600` | How often retention is enforced. |
| `QUEUE_MAX` | `100000` | In-flight events before overflow drops. |

## Sizing & retention

A live log stores **one row per event** (a timeline can't be aggregated
the way rule-mining data can). Plan disk accordingly:

- Each stored event is roughly **0.2 KB** including indexes.
- At an average of *E* events/sec across the fleet, 14 days ≈
  `E × 86400 × 14 × 0.2 KB`. Example: 200 events/sec ≈ **~48 GB**.

If your fleet is busy, either shorten `RETENTION_DAYS`, set a `MAX_EVENTS`
cap, or scope firewall logging to the rule hits you actually want to see
rather than literally all traffic. The dashboard's **Dropped** tile shows
whether the writer is ever falling behind (queue overflow); **Unparsed**
shows lines that didn't match a parser.

## API

| Endpoint | Description |
|---|---|
| `GET /api/live?since=<cursor>&…` | Incremental tail; pass filters `device`, `vendor`, `ip`, `port`, `action`. |
| `GET /api/events?window=<secs>&…` | Historical snapshot within a time window. |
| `GET /api/events.csv?window=<secs>&…` | CSV of a filtered window. |
| `GET /api/stats` | Totals, rate, per-device activity, retention. |
| `GET /api/devices` | Configured devices. |

`action` filter accepts `Allow` or `blocked` (Block/Drop/Reject).

## Testing

```sh
docker run --rm ghcr.io/g-guglielmi/firewall-live-log:latest python3 /app/test_harness.py
```

Boots the real app, feeds synthetic UniFi and Sophos syslog to separate
ports, and verifies parsing, action normalization, auto-detection,
filters, retention pruning, CSV export, and a graceful-stop final flush.
The same harness gates CI and every release. It also runs directly with
`python3 test_harness.py` on Linux/macOS/Windows.

## Security notes

- The dashboard has **no authentication** — run it on a management
  network or behind an authenticating reverse proxy.
- Firewall logs are sensitive metadata about your network; protect the
  bind-mounted data directory accordingly.
- The container runs as a non-root user (uid 10001); the bind-mounted
  data directory must be writable by that uid (`chown 10001`), and
  `devices.json` must be readable by it.
- That non-root user cannot bind UDP ports below 1024. Assign collection
  ports ≥ 1024 in `devices.json` (the examples use 5514+). If a firewall
  can only send to 514, remap it on the host (e.g. a `PREROUTING` DNAT to
  a high port) rather than running the container as root.

## License

[MIT](LICENSE)
