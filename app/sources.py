"""Syslog source allow-list (SYSLOG_ALLOWED_SOURCES), with DNS-backed entries.

The setting takes literal addresses and CIDRs plus hostnames — typically
the dynamic-DNS names of remote sites that send syslog over the internet
from behind NAT, where the only stable identifier is the name. Hostnames
are resolved by a background thread:

  * every RESOLVE_INTERVAL (an hour) as a baseline;
  * right away when a listener rejects a datagram — a site whose public IP
    just changed shows up as rejects from an unknown address — but at most
    once per TRIGGER_MIN_GAP, so a scanner hammering a collector port can't
    turn the container into a DNS chatterbox;
  * on a short retry (RETRY_INTERVAL, doubling up to the hourly interval)
    while any name fails to resolve.

A failed lookup keeps the name's last known addresses: a DNS hiccup must
never lock a site out. Every change of the resolved set bumps
``generation``; listeners watch it to replay datagrams they held from
addresses that have since become allowed (see listener.py).

The filter is shared by all listener threads. ``allowed`` and
``generation`` are replaced atomically by the resolver thread and only
read elsewhere, so no lock is needed on the datagram path.
"""

import ipaddress
import re
import socket
import sys
import threading
import time

RESOLVE_INTERVAL = 3600             # baseline re-resolution
TRIGGER_MIN_GAP = 60                # floor between reject-triggered rounds
RETRY_INTERVAL = 60                 # first retry while a name fails
_FAIL_LOG_INTERVAL = 3600           # per hostname

_HOST_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?", re.IGNORECASE)


def parse(value, name="SYSLOG_ALLOWED_SOURCES"):
    """Parse "ip, cidr, hostname, ..." (empty or "none" = nothing) into
    ``(networks, hostnames)``. An entry made only of digits, dots, colons
    and slashes has to be a valid address or CIDR — a typo'd IP must fail
    at startup, not become a hostname that silently never resolves."""
    nets, hosts = [], []
    for part in (value or "").split(","):
        part = part.strip()
        if not part or part.lower() == "none":
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[0-9.:/]+", part) or not _HOST_RE.fullmatch(part):
            raise ValueError(
                f"{name}: {part!r} is not an IP, CIDR or hostname")
        host = part.rstrip(".").lower()
        if host not in hosts:
            hosts.append(host)
    return tuple(nets), tuple(hosts)


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


def lookup(host):
    """All A/AAAA addresses of ``host`` as a frozenset of ip_address objects.
    Raises OSError (socket.gaierror) when the name does not resolve."""
    out = set()
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM):
        # Link-local IPv6 carries a "%scope" suffix ip_network can't take.
        out.add(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
    return frozenset(out)


def _fmt(addrs):
    return ", ".join(sorted(str(a) for a in addrs)) or "(no address)"


class SourceFilter:
    def __init__(self, nets=(), hosts=(), resolver=lookup):
        self.nets = tuple(nets)
        self.hosts = tuple(dict.fromkeys(hosts))
        self._resolver = resolver
        self._resolved = {}         # host -> frozenset(ip_address); replaced
        self._fail_logged = {}      # host -> monotonic of last failure log
        self._failures = 0          # consecutive rounds with a failed name
        self.allowed = self.nets    # networks the listeners match against
        self.generation = 0         # bumped on every change of `allowed`
        self.rounds = 0             # resolution rounds run (diagnostics)
        self.interval = RESOLVE_INTERVAL
        self.min_gap = TRIGGER_MIN_GAP
        self.retry = RETRY_INTERVAL
        self._cv = threading.Condition()
        self._kicked = False

    @property
    def enabled(self):
        """False when nothing is configured: every sender is accepted."""
        return bool(self.nets or self.hosts)

    def allows(self, sender):
        if not self.enabled:
            return True
        # A hostname that hasn't resolved yet allows nobody (not everybody).
        return bool(self.allowed) and source_allowed(sender, self.allowed)

    def host_for(self, sender):
        """The configured hostname a (now allowed) sender resolved from."""
        try:
            addr = ipaddress.ip_address(sender)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        for host, addrs in self._resolved.items():
            if addr in addrs:
                return host
        return None

    def describe(self):
        return ", ".join([str(n) for n in self.nets] + list(self.hosts))

    def resolve_all(self):
        """One resolution round over every hostname. Returns True when the
        allowed set changed. Never raises."""
        if not self.hosts:
            return False
        now = time.monotonic()
        resolved = dict(self._resolved)
        changed = failed = False
        for host in self.hosts:
            try:
                addrs = frozenset(self._resolver(host))
            except (OSError, ValueError) as e:     # gaierror is an OSError
                failed = True
                last = self._fail_logged.get(host)
                if last is None or now - last >= _FAIL_LOG_INTERVAL:
                    self._fail_logged[host] = now
                    known = resolved.get(host)
                    tail = (f"; keeping {_fmt(known)}" if known else
                            "; no address known yet, its syslog is held "
                            "for replay")
                    print(f"[sources] cannot resolve {host}: {e}{tail}",
                          file=sys.stderr, flush=True)
                continue
            self._fail_logged.pop(host, None)
            if addrs != resolved.get(host):
                resolved[host] = addrs
                changed = True
                print(f"[sources] resolved {host} -> {_fmt(addrs)}",
                      flush=True)
        self._failures = self._failures + 1 if failed else 0
        self.rounds += 1
        if changed:
            dynamic = tuple(ipaddress.ip_network(a)
                            for host in self.hosts
                            for a in sorted(resolved.get(host, ()), key=str))
            self._resolved = resolved
            self.allowed = self.nets + dynamic
            self.generation += 1
        return changed

    def trigger(self):
        """A listener rejected a datagram: re-resolve soon (rate-limited)."""
        if not self.hosts:
            return
        with self._cv:
            self._kicked = True
            self._cv.notify()

    def _next_interval(self):
        if self._failures:
            return min(self.retry * 2 ** (self._failures - 1), self.interval)
        return self.interval

    def run(self, stop_event):
        """Resolver thread body: resolve, then sleep until the next baseline
        round, or until a trigger once ``min_gap`` has passed."""
        while not stop_event.is_set():
            self.resolve_all()
            start = time.monotonic()
            deadline = start + self._next_interval()
            gap_end = start + self.min_gap
            with self._cv:
                while not stop_event.is_set():
                    now = time.monotonic()
                    if now >= deadline or (self._kicked and now >= gap_end):
                        break
                    target = min(deadline, gap_end) if self._kicked \
                        else deadline
                    self._cv.wait(min(target - now, 5.0))
                self._kicked = False

    def start(self, stop_event):
        if not self.hosts:
            return None
        t = threading.Thread(target=self.run, args=(stop_event,),
                             name="sources", daemon=True)
        t.start()
        return t
