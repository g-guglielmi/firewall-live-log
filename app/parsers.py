"""Vendor-specific syslog parsers producing a normalized firewall event.

A normalized event is the tuple:

    (vendor, src_ip, dst_ip, proto, dst_port, action, rule)

with sentinels  dst_port = -1  (ICMP / no port) and  rule = ""  (absent),
and action in {Allow, Block, Drop, Reject, ?}.

Two vendors are supported today:

  * unifi  — UniFi OS / UDM iptables-style firewall syslog
             (SRC= DST= PROTO= DPT=, DESCR="...", [ZONE-Action-RuleID] tag)
  * sophos — Sophos Firewall (SFOS v18-v22) key=value firewall logs
             (src_ip= dst_ip= protocol= dst_port= log_subtype= ...)

Auto-detection is reliable: the two formats use disjoint field names
(`SRC=` upper-case vs `src_ip=`), so a single marker check picks the
parser with no ambiguity.  Detection can always be overridden per port.
"""

import re

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


def parse_unifi(line):
    fields = dict(_U_FIELD.findall(line))
    src, dst = fields.get("SRC"), fields.get("DST")
    if not src or not dst:
        return None
    proto = fields.get("PROTO", "?").upper()
    try:
        dst_port = int(fields["DPT"])
    except (KeyError, ValueError):
        dst_port = -1

    m = _U_DESCR.search(line)
    rule = (m.group(1) if m and m.group(1) is not None
            else (m.group(2) if m else "")) or ""

    action = "?"
    for tag in _U_TAG.findall(line):
        am = _U_TAG_ACTION.search(tag)
        if am:
            action = _U_ACTION_MARKER[am.group(1)]
            break
    if action == "?":
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


def _sophos_action(kv):
    for field in _S_ACTION_FIELDS:
        v = kv.get(field)
        if v and v.lower() in _S_ACTION:
            return _S_ACTION[v.lower()]
    return "?"


def parse_sophos(line):
    kv = {}
    for m in _S_KV.finditer(line):
        kv[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    src, dst = kv.get("src_ip"), kv.get("dst_ip")
    if not src or not dst:
        return None
    proto = (kv.get("protocol") or "?").upper()
    try:
        dst_port = int(kv["dst_port"])
    except (KeyError, ValueError):
        dst_port = -1
    rule = kv.get("fw_rule_name") or (
        f"rule {kv['fw_rule_id']}" if kv.get("fw_rule_id") else "")
    return (src, dst, proto, dst_port, _sophos_action(kv), rule)


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
