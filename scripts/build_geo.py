#!/usr/bin/env python3
"""Compile the local IP->country tables and vendor the flag artwork.

Everything the dashboard needs for the country flags is generated here and
committed to the repo, so the running container never makes an external call
and the project keeps its zero-dependency, stdlib-only runtime.

Sources (all public / permissively licensed):

  * RIR *delegated-extended* statistics files (AFRINIC, APNIC, ARIN, LACNIC,
    RIPE NCC) — the authoritative per-country IP allocations. Public data.
  * flag-icons (https://github.com/lipis/flag-icons), MIT — the 4x3 SVG
    flags, plus its country.json for tooltip names.

Outputs (committed):

  * app/geo/ip4.bin.gz   — sorted IPv4 ranges,  record = >IIH-ish (see below)
  * app/geo/ip6.bin.gz   — sorted IPv6 ranges
  * app/geo/meta.json    — build date + row counts (informational)
  * app/static/flags/<cc>.svg      — one flag per country we can place
  * app/static/flags/names.json    — { "us": "United States", ... }

Record formats (little tooling, big clarity):
  ip4: struct ">II2s"  = start_u32, end_u32, cc (2 ASCII bytes)          =10B
  ip6: 16 bytes start + 16 bytes end (big-endian) + 2 ASCII cc           =34B

Run:  python3 scripts/build_geo.py
"""

import gzip
import io
import ipaddress
import json
import os
import re
import struct
import sys
import tarfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEO_DIR = os.path.join(ROOT, "app", "geo")
FLAG_DIR = os.path.join(ROOT, "app", "static", "flags")

RIRS = {
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "apnic": "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
}
FLAG_ICONS_TGZ = "https://registry.npmjs.org/flag-icons/-/flag-icons-7.2.3.tgz"

_CC = re.compile(r"^[A-Za-z]{2}$")


def _get(url, binary=True):
    print("  fetch", url)
    req = urllib.request.Request(url, headers={"User-Agent": "fll-build-geo"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def collect_ranges():
    """Return (ipv4, ipv6) sorted lists of (start_int, end_int, cc_upper)."""
    v4, v6 = [], []
    for name, url in RIRS.items():
        text = _get(url, binary=False)
        for line in text.splitlines():
            # registry|cc|type|start|value|date|status|...
            f = line.split("|")
            if len(f) < 7 or f[1] == "*":
                continue
            cc, typ, start, value, status = f[1], f[2], f[3], f[4], f[6]
            if status not in ("allocated", "assigned") or not _CC.match(cc):
                continue
            cc = cc.upper()
            try:
                if typ == "ipv4":
                    s = int(ipaddress.IPv4Address(start))
                    v4.append((s, s + int(value) - 1, cc))
                elif typ == "ipv6":
                    net = ipaddress.IPv6Network(f"{start}/{int(value)}", strict=False)
                    v6.append((int(net.network_address),
                               int(net.broadcast_address), cc))
            except (ipaddress.AddressValueError, ValueError):
                continue
    v4.sort(); v6.sort()
    return v4, v6


def write_v4(ranges):
    buf = io.BytesIO()
    prev_end = -1
    for s, e, cc in ranges:
        if s <= prev_end:          # RIR data is disjoint; skip any overlap
            continue
        buf.write(struct.pack(">II2s", s, e, cc.encode("ascii")))
        prev_end = e
    _write_gz(os.path.join(GEO_DIR, "ip4.bin.gz"), buf.getvalue())
    return buf.tell() // 10


def write_v6(ranges):
    buf = io.BytesIO()
    prev_end = -1
    for s, e, cc in ranges:
        if s <= prev_end:
            continue
        buf.write(s.to_bytes(16, "big") + e.to_bytes(16, "big")
                  + cc.encode("ascii"))
        prev_end = e
    _write_gz(os.path.join(GEO_DIR, "ip6.bin.gz"), buf.getvalue())
    return buf.tell() // 34


def _write_gz(path, raw):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wb", compresslevel=9) as f:
        f.write(raw)
    print("  wrote %s (%d KB)" % (path, os.path.getsize(path) // 1024))


def vendor_flags(used_ccs):
    """Extract 4x3 SVGs and country names for the CCs we actually have, from
    the flag-icons tarball. Returns the set of CCs that got a flag."""
    tgz = _get(FLAG_ICONS_TGZ)
    os.makedirs(FLAG_DIR, exist_ok=True)
    # clear any stale flags so removals propagate
    for old in os.listdir(FLAG_DIR):
        if old.endswith(".svg"):
            os.remove(os.path.join(FLAG_DIR, old))
    names = {}
    have = set()
    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
        # country.json -> [{"code":"US","name":"United States"}, ...]
        cj = tar.extractfile("package/country.json")
        cmap = {c["code"].upper(): c["name"] for c in json.load(cj)}
        for m in tar.getmembers():
            mm = re.match(r"package/flags/4x3/([a-z]{2})\.svg$", m.name)
            if not mm:
                continue
            cc = mm.group(1).upper()
            if cc not in used_ccs:
                continue
            svg = tar.extractfile(m).read()
            with open(os.path.join(FLAG_DIR, cc.lower() + ".svg"), "wb") as f:
                f.write(svg)
            have.add(cc)
            names[cc.lower()] = cmap.get(cc, cc)
    with open(os.path.join(FLAG_DIR, "names.json"), "w", encoding="utf-8") as f:
        json.dump(dict(sorted(names.items())), f, ensure_ascii=False,
                  separators=(",", ":"))
    print("  vendored %d flags" % len(have))
    return have


def main():
    print("[1/3] downloading + parsing RIR delegation files")
    v4, v6 = collect_ranges()
    used = {cc for _, _, cc in v4} | {cc for _, _, cc in v6}
    print("      ipv4 ranges:", len(v4), " ipv6 ranges:", len(v6),
          " countries:", len(used))

    print("[2/3] vendoring flag artwork")
    have = vendor_flags(used)

    print("[3/3] writing compiled tables")
    # Only keep ranges whose country we can actually display a flag for; the
    # rest would render as a broken image. (Regional pseudo-codes like AP have
    # no flag.) Lookups for those simply return no country.
    v4 = [r for r in v4 if r[2] in have]
    v6 = [r for r in v6 if r[2] in have]
    n4 = write_v4(v4)
    n6 = write_v6(v6)
    with open(os.path.join(GEO_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"built": time.strftime("%Y-%m-%d"),
                   "ipv4_ranges": n4, "ipv6_ranges": n6,
                   "countries": len(have)}, f, indent=2)
    print("done: %d ipv4 + %d ipv6 ranges, %d flags" % (n4, n6, len(have)))


if __name__ == "__main__":
    sys.exit(main())
