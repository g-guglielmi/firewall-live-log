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

  * an optional source allow-list (SYSLOG_ALLOWED_SOURCES, a shared
    sources.SourceFilter): a datagram from any other address is discarded
    before it is even decoded, and counted in `drops["rejected"]` (logged
    at most hourly per source). When the list contains hostnames, a
    rejected datagram is additionally *held* for HELD_TTL seconds: the
    reject triggers a DNS re-check, and if the sender turns out to be a
    site whose address just changed, the held datagrams are replayed in
    order (with their original timestamps) instead of being lost;
  * an unparsed line is stored truncated to MAX_RAW_LEN bytes, so a flood of
    junk can't park 64 KB rows in the database between prunes.

If the queue is full (writer overloaded) the datagram is dropped and the
shared drop counter is incremented — bounded memory beats unbounded lag.
"""

import collections
import queue
import socket
import sys
import threading
import time

import parsers
from sources import source_allowed      # noqa: F401 (re-exported for tests)

RECVBUF_REQUEST = 8 * 1024 * 1024
MAX_RAW_LEN = 4096                  # stored bytes of an unparsed line

HELD_MAX = 5000                     # datagrams held per listener
HELD_TTL = 600                      # seconds a held datagram can wait

_REJECT_LOG_INTERVAL = 3600         # per source
_REJECT_LOG_MAX = 1024              # distinct sources remembered


class _RejectLog:
    """Once-an-hour-per-source logger for rejected datagrams, bounded so a
    sender rotating through addresses can't grow the table without limit."""

    def __init__(self, device, held=False):
        self.device = device
        self.held = held
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
              "in SYSLOG_ALLOWED_SOURCES"
              + (" (held for replay while hostnames re-resolve)"
                 if self.held else ""), file=sys.stderr, flush=True)


class _Held:
    """Datagrams rejected while hostnames are configured, kept briefly so
    they can be replayed if their sender becomes allowed after a DNS
    re-resolution. Bounded in count and per-datagram size; the oldest go
    first when full, and anything older than HELD_TTL is discarded."""

    def __init__(self):
        self.items = collections.deque(maxlen=HELD_MAX)

    def _expire(self, now):
        items = self.items
        while items and now - items[0][0] > HELD_TTL:
            items.popleft()

    def add(self, now, sender, data):
        self._expire(now)
        self.items.append((now, sender, data[:MAX_RAW_LEN]))

    def release(self, now, sources):
        """Remove and return the held datagrams whose sender is now allowed,
        oldest first."""
        self._expire(now)
        out, keep = [], collections.deque(maxlen=HELD_MAX)
        for item in self.items:
            (out if sources.allows(item[1]) else keep).append(item)
        self.items = keep
        return out


def _ingest(device, text, now, q, drops):
    """Parse one decoded datagram and queue it (or count why not)."""
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
        return
    try:
        q.put_nowait(item)
    except queue.Full:
        with drops["lock"]:
            drops["n"] += 1


def _replay(device, held, filt, q, drops):
    released = held.release(int(time.time()), filt)
    if not released:
        return
    by_sender = collections.Counter()
    for ts, sender, raw in released:
        _ingest(device, raw.decode("utf-8", "replace"), ts, q, drops)
        by_sender[sender] += 1
    with drops["lock"]:
        # They were counted as rejected when held; they weren't, in the end.
        drops["rejected"] = max(0, drops["rejected"] - len(released))
    for sender, n in by_sender.items():
        host = filt.host_for(sender)
        print(f"[listener {device.name}] accepted {n} held datagram(s) from "
              f"{sender}" + (f" (now allowed via {host})" if host else ""),
              flush=True)


def run(stop_event, device, q, drops, sources=None, bind="0.0.0.0"):
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
    filt = sources if sources is not None and sources.enabled else None
    held = _Held() if filt is not None and filt.hosts else None
    generation = filt.generation if filt is not None else 0
    where = f"udp/{device.port}" if bind in ("0.0.0.0", "::") \
        else f"{bind} udp/{device.port}"
    print(f"[listener {device.name}] {where} vendor={device.vendor}"
          + (f" sources={filt.describe()}" if filt is not None else ""))
    sys.stdout.flush()
    rejects = _RejectLog(device.name, held=held is not None)

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            data = addr = None
        except OSError:
            if stop_event.is_set():
                break
            raise

        if held is not None and filt.generation != generation:
            # The resolver changed the allowed set: give held datagrams
            # from a newly allowed sender their chance (checked at least
            # once a second thanks to the socket timeout).
            generation = filt.generation
            _replay(device, held, filt, q, drops)
        if data is None:
            continue

        if filt is not None and not filt.allows(addr[0]):
            with drops["lock"]:
                drops["rejected"] += 1
            rejects.note(addr[0])
            if held is not None:
                held.add(int(time.time()), addr[0], data)
                filt.trigger()
            continue
        _ingest(device, data.decode("utf-8", "replace"), int(time.time()),
                q, drops)

    sock.close()
    print(f"[listener {device.name}] stopped")
    sys.stdout.flush()
