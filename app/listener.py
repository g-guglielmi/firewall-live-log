"""One UDP syslog listener per device.

Each listener binds its device's port, parses every datagram with the
device's configured vendor (or auto-detect), and puts a normalized item
on the shared queue for the single writer thread to persist.  Queue items:

    ("ev", ts, device, vendor, src, dst, proto, dst_port, action, rule)
    ("un", ts, device, raw)          # firewall-shaped line we couldn't parse

A datagram that carries no firewall marker at all (ordinary host syslog the
gateway also forwards — IPsec, DHCP, systemd, …) is not a firewall event; it
is discarded at the listener and counted in `drops["ignored"]`, so it never
reaches the queue, the events table, or the unparsed table.

Syslog is unauthenticated UDP, so two more edges are enforced here:

  * an optional source allow-list (SYSLOG_ALLOWED_SOURCES): a datagram from
    any other address is discarded before it is even decoded, and counted
    in `drops["rejected"]` (logged at most hourly per source);
  * an unparsed line is stored truncated to MAX_RAW_LEN bytes, so a flood of
    junk can't park 64 KB rows in the database between prunes.

If the queue is full (writer overloaded) the datagram is dropped and the
shared drop counter is incremented — bounded memory beats unbounded lag.
"""

import ipaddress
import queue
import socket
import sys
import threading
import time

import parsers

RECVBUF_REQUEST = 8 * 1024 * 1024
MAX_RAW_LEN = 4096                  # stored bytes of an unparsed line

_REJECT_LOG_INTERVAL = 3600         # per source
_REJECT_LOG_MAX = 1024              # distinct sources remembered


def source_allowed(sender, allowed):
    """True when ``allowed`` is empty (no filter) or contains the sender.
    A v4-mapped IPv6 sender (an IPv6 socket receiving IPv4) is matched as
    its IPv4 address, so an IPv4 CIDR in the list works for both families."""
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(sender)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in allowed)


class _RejectLog:
    """Once-an-hour-per-source logger for rejected datagrams, bounded so a
    sender rotating through addresses can't grow the table without limit."""

    def __init__(self, device):
        self.device = device
        self.lock = threading.Lock()
        self.seen = {}

    def note(self, sender):
        now = time.monotonic()
        with self.lock:
            last = self.seen.get(sender)
            if last is not None and now - last < _REJECT_LOG_INTERVAL:
                return
            if last is None and len(self.seen) >= _REJECT_LOG_MAX:
                for k in [k for k, t in self.seen.items()
                          if now - t >= _REJECT_LOG_INTERVAL]:
                    del self.seen[k]
                if len(self.seen) >= _REJECT_LOG_MAX:
                    return
            self.seen[sender] = now
        print(f"[listener {self.device}] rejected syslog from {sender}: not "
              "in SYSLOG_ALLOWED_SOURCES", file=sys.stderr, flush=True)


def run(stop_event, device, q, drops, allowed=(), bind="0.0.0.0"):
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_REQUEST)
    if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
        # "::" should take IPv4 senders too (as v4-mapped addresses).
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
    try:
        sock.bind((bind, device.port))
    except OSError as e:
        print(f"[listener {device.name}] cannot bind udp/{device.port} on "
              f"{bind}: {e}", file=sys.stderr)
        stop_event.set()
        return
    sock.settimeout(1.0)
    where = f"udp/{device.port}" if bind in ("0.0.0.0", "::") \
        else f"{bind} udp/{device.port}"
    print(f"[listener {device.name}] {where} vendor={device.vendor}"
          + (f" sources={len(allowed)} allowed" if allowed else ""))
    sys.stdout.flush()
    rejects = _RejectLog(device.name)

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            if stop_event.is_set():
                break
            raise

        if not source_allowed(addr[0], allowed):
            with drops["lock"]:
                drops["rejected"] += 1
            rejects.note(addr[0])
            continue
        text = data.decode("utf-8", "replace")
        now = int(time.time())
        rec = parsers.parse(text, device.vendor)
        if rec is not None:
            vendor, src, dst, proto, dport, action, rule = rec
            item = ("ev", now, device.name, vendor, src, dst, proto,
                    dport, action, rule)
        elif parsers.looks_like_firewall(text, device.vendor):
            # Real parser gap: keep it for diagnosis, but bounded.
            item = ("un", now, device.name, text[:MAX_RAW_LEN])
        else:
            # Ordinary host syslog the gateway forwards alongside its firewall
            # logs — not a firewall event. Discard it rather than filling the
            # unparsed table (and the disk) with VPN/DHCP/OS chatter.
            with drops["lock"]:
                drops["ignored"] += 1
            continue
        try:
            q.put_nowait(item)
        except queue.Full:
            with drops["lock"]:
                drops["n"] += 1

    sock.close()
    print(f"[listener {device.name}] stopped")
    sys.stdout.flush()
