"""Local IP -> ISO country-code lookup for the public source/destination IPs
shown in the log.

The range tables are compiled from the RIR delegation files by
``scripts/build_geo.py`` and shipped in ``app/geo/`` (gzipped). This module
only reads them — no network, no third-party dependency. Tables load lazily on
the first lookup, so an install that never opens a log view pays nothing.

Only *globally routable* addresses are resolved: ``ipaddress.is_global`` skips
private (RFC1918), CGNAT, loopback, link-local, documentation and other
reserved space, which get no flag. Lookup is an ``O(log n)`` bisect over the
sorted ranges; results are memoised per IP for the hot path.
"""

import array
import bisect
import gzip
import ipaddress
import os
import struct
import threading

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geo")
_LOCK = threading.Lock()
_LOADED = False
# IPv4: parallel arrays for a cheap bisect; ccs4 is a flat 2-bytes-per-entry blob.
_S4 = array.array("I")
_E4 = array.array("I")
_C4 = b""
# IPv6: 128-bit keys don't fit a typed array, so plain int lists.
_S6, _E6, _C6 = [], [], []


def _load():
    global _LOADED, _S4, _E4, _C4, _S6, _E6, _C6
    with _LOCK:
        if _LOADED:
            return
        try:
            _load_v4(os.path.join(_DIR, "ip4.bin.gz"))
            _load_v6(os.path.join(_DIR, "ip6.bin.gz"))
        except OSError:
            # No compiled tables (never built) — degrade to "no country".
            _S4, _E4, _C4, _S6, _E6, _C6 = array.array("I"), array.array("I"), b"", [], [], []
        _LOADED = True


def _load_v4(path):
    global _S4, _E4, _C4
    with gzip.open(path, "rb") as f:
        raw = f.read()
    n = len(raw) // 10
    s, e, cc = array.array("I"), array.array("I"), bytearray(2 * n)
    for i in range(n):
        a, b, c = struct.unpack_from(">II2s", raw, i * 10)
        s.append(a); e.append(b); cc[2 * i:2 * i + 2] = c
    _S4, _E4, _C4 = s, e, bytes(cc)


def _load_v6(path):
    global _S6, _E6, _C6
    with gzip.open(path, "rb") as f:
        raw = f.read()
    n = len(raw) // 34
    for i in range(n):
        o = i * 34
        _S6.append(int.from_bytes(raw[o:o + 16], "big"))
        _E6.append(int.from_bytes(raw[o + 16:o + 32], "big"))
        _C6.append(raw[o + 32:o + 34].decode("ascii"))


_cache = {}


def country(ip):
    """Return the lowercase ISO-3166 code (e.g. ``"us"``) for a public IP, or
    ``None`` for a private/reserved/unknown address or unparseable string."""
    hit = _cache.get(ip, _MISS)
    if hit is not _MISS:
        return hit
    cc = _resolve(ip)
    if len(_cache) < 100000:
        _cache[ip] = cc
    return cc


_MISS = object()


def _resolve(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None
    if not _LOADED:
        _load()
    n = int(addr)
    if addr.version == 4:
        i = bisect.bisect_right(_S4, n) - 1
        if i >= 0 and n <= _E4[i]:
            return _C4[2 * i:2 * i + 2].decode("ascii").lower()
        return None
    i = bisect.bisect_right(_S6, n) - 1
    if i >= 0 and n <= _E6[i]:
        return _C6[i].lower()
    return None


def annotate(events):
    """Add ``src_cc`` / ``dst_cc`` to each event dict in place (only when the
    address resolves to a country). Returns the same list for convenience."""
    for e in events:
        cc = country(e.get("src"))
        if cc:
            e["src_cc"] = cc
        cc = country(e.get("dst"))
        if cc:
            e["dst_cc"] = cc
    return events
