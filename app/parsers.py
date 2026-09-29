"""Vendor-specific syslog parsers producing a normalized firewall event.

A normalized event is the tuple:

    (vendor, src_ip, dst_ip, proto, dst_port, action, rule)

with sentinels  dst_port = -1  (ICMP / no port) and  rule = ""  (absent),
and action in {Allow, Block, Drop, Reject, NAT, ?}.  NAT marks a
translation record (DNAT/SNAT/masquerade/port-forward) — a NAT log line
describes address translation, not a permit/deny verdict, so it is kept
as its own category rather than coerced into Allow or Block.

Two vendors are supported today:

  * unifi  — UniFi OS / UDM iptables-style firewall syslog
             (SRC= DST= PROTO= DPT=, DESCR="...", [ZONE-Action-RuleID] tag)
  * sophos — Sophos Firewall (SFOS v18-v22) key=value firewall logs
             (src_ip= dst_ip= protocol= dst_port= log_subtype= ...)

Auto-detection is reliable: the two formats use disjoint field names
(`SRC=` upper-case vs `src_ip=`), so a single marker check picks the
parser with no ambiguity.  Detection can always be overridden per port.
"""

import ipaddress
import re

# Syslog is unauthenticated UDP: anything that can reach a collector port can
# write rows. Every field is therefore validated/bounded here, at the edge —
# addresses must parse as IPs and free text is capped — so hostile or
# malformed datagrams can't plant arbitrary strings or megabytes in the
# database. A line whose SRC/DST isn't an IP is not a firewall event: the
# parser returns None and the collector keeps it in the "unparsed" table,
# where the operator can see it.
MAX_RULE_LEN = 256
MAX_PROTO_LEN = 16


def _ip_or_none(value):
    """The address string if it parses as an IPv4/IPv6 address, else None.
    The raw spelling is kept (not normalised) so stored values match what the
    firewall logged and existing filters keep working."""
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _port_or_sentinel(value):
    """0-65535 as int, else -1 (ICMP / absent / garbage)."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return -1
    return port if 0 <= port <= 65535 else -1


# --------------------------------------------------------------------------
# Vendor detection
# --------------------------------------------------------------------------
_MARK_SOPHOS = re.compile(r"\bsrc_ip=\S")
_MARK_UNIFI = re.compile(r"\bSRC=\S")


def detect_vendor(line):
    """Return 'sophos', 'unifi', or None for a raw syslog line."""
    if _MARK_SOPHOS.search(line):
        return "sophos"
    if _MARK_UNIFI.search(line):
        return "unifi"
    return None


_MARKERS = {"unifi": _MARK_UNIFI, "sophos": _MARK_SOPHOS}


def looks_like_firewall(line, vendor="auto"):
    """True if the line carries a vendor's firewall-log marker (UniFi `SRC=`,
    Sophos `src_ip=`).

    Gateways forward their whole host syslog — IPsec (charon), DHCP (dnsmasq),
    the OOM watchdog, systemd, and so on — over the same port as the firewall
    logs. Those aren't firewall events and shouldn't be parsed *or* kept as
    "unparsed". This marker test separates the two: a line with a marker that
    still fails to parse is a real parser gap worth keeping to diagnose; a line
    without any marker is ordinary host syslog, and the collector discards it.
    For a port pinned to one vendor only that vendor's marker counts; in
    auto mode either does."""
    mark = _MARKERS.get(vendor)
    if mark is not None:
        return bool(mark.search(line))
    return bool(_MARK_UNIFI.search(line) or _MARK_SOPHOS.search(line))


# --------------------------------------------------------------------------
# UniFi (iptables-style)
# --------------------------------------------------------------------------
_U_FIELD = re.compile(r"\b(SRC|DST|PROTO|DPT)=(\S+)")
_U_DESCR = re.compile(r'DESCR="([^"]*)"|DESCR=(\S+)')
_U_TAG = re.compile(r"\[([^\]\[]{1,120})\]")
_U_TAG_ACTION = re.compile(r"-(Allow|Block|Drop|Reject|[ABDR])-")

_U_ACTION_MARKER = {"A": "Allow", "B": "Block", "D": "Drop", "R": "Reject",
                    "Allow": "Allow", "Block": "Block",
                    "Drop": "Drop", "Reject": "Reject"}
_U_KEYWORDS = [("allow", "Allow"), ("accept", "Allow"), ("reject", "Reject"),
               ("drop", "Drop"), ("block", "Block"), ("deny", "Block")]
# NAT/forward markers: a DNAT/SNAT/masquerade/port-forward line is a
# translation record, not a filter verdict.  Matched as whole words so
# "nat" can't fire on substrings like "donate".  Shared by both vendors —
# UniFi keys off the rule DESCR, Sophos off fw_rule_name.
_U_NAT = re.compile(r"\b(?:d?nat|snat|masquerade|port[\s_-]?forward)\b", re.I)


def parse_unifi(line):
    fields = dict(_U_FIELD.findall(line))
    src, dst = _ip_or_none(fields.get("SRC")), _ip_or_none(fields.get("DST"))
    if not src or not dst:
        return None
    proto = fields.get("PROTO", "?").upper()[:MAX_PROTO_LEN]
    dst_port = _port_or_sentinel(fields.get("DPT"))

    m = _U_DESCR.search(line)
    rule = (m.group(1) if m and m.group(1) is not None
            else (m.group(2) if m else "")) or ""
    rule = rule[:MAX_RULE_LEN]

    action = "?"
    for tag in _U_TAG.findall(line):
        am = _U_TAG_ACTION.search(tag)
        if am:
            action = _U_ACTION_MARKER[am.group(1)]
            break
    if action == "?":
        # A real filter verdict in the rule tag wins above; here there is
        # none, so a NAT/forward rule is classified as NAT before the fuzzy
        # allow/block keyword fallback gets a chance to mislabel it.
        if _U_NAT.search(rule):
            action = "NAT"
        else:
            low = rule.lower()
            for kw, act in _U_KEYWORDS:
                if kw in low:
                    action = act
                    break
    return (src, dst, proto, dst_port, action, rule)


# --------------------------------------------------------------------------
# Sophos Firewall (SFOS key=value)
# --------------------------------------------------------------------------
_S_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_S_ACTION = {
    "allow": "Allow", "allowed": "Allow", "accept": "Allow",
    "accepted": "Allow", "deny": "Block", "denied": "Block",
    "drop": "Drop", "dropped": "Drop", "reject": "Reject",
    "rejected": "Reject", "violation": "Block",
}
# Fields that may carry the verdict, in order of preference.
_S_ACTION_FIELDS = ("log_subtype", "status", "fw_rule_action", "action")


def _sophos_action(kv, rule):
    verdict = "?"
    for field in _S_ACTION_FIELDS:
        v = kv.get(field)
        if v and v.lower() in _S_ACTION:
            verdict = _S_ACTION[v.lower()]
            break
    # A block/drop/reject verdict is the priority signal and wins outright.
    # Otherwise a rule named for a translation is surfaced as NAT — Sophos
    # tags a permitted DNAT/SNAT as "Allowed", so unlike UniFi (whose NAT
    # lines carry no verdict) we key off the operator's rule-naming habit,
    # via the same _U_NAT regex.
    if verdict in ("Block", "Drop", "Reject"):
        return verdict
    if _U_NAT.search(rule):
        return "NAT"
    return verdict


def parse_sophos(line):
    kv = {}
    for m in _S_KV.finditer(line):
        kv[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    src, dst = _ip_or_none(kv.get("src_ip")), _ip_or_none(kv.get("dst_ip"))
    if not src or not dst:
        return None
    proto = (kv.get("protocol") or "?").upper()[:MAX_PROTO_LEN]
    dst_port = _port_or_sentinel(kv.get("dst_port"))
    rule = (kv.get("fw_rule_name") or (
        f"rule {kv['fw_rule_id']}" if kv.get("fw_rule_id") else ""))[:MAX_RULE_LEN]
    return (src, dst, proto, dst_port, _sophos_action(kv, rule), rule)


_PARSERS = {"unifi": parse_unifi, "sophos": parse_sophos}


def parse(line, vendor="auto"):
    """Parse a line with the given vendor ('auto'|'unifi'|'sophos').

    Returns (vendor, src, dst, proto, dst_port, action, rule) or None.
    In 'auto' mode the vendor is detected from the line's field style.
    """
    v = vendor if vendor in _PARSERS else detect_vendor(line)
    if v is None:
        return None
    result = _PARSERS[v](line)
    if result is None:
        return None
    return (v,) + result
