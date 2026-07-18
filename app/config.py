"""Device configuration: load and validate devices.json.

Shape:

    {
      "retention_days": 14,       # optional; env RETENTION_DAYS overrides
      "max_events": 0,            # optional safety cap, 0 = disabled
      "devices": [
        {"name": "UDM-HQ",        "port": 5514, "vendor": "auto"},
        {"name": "Sophos-Branch", "port": 5515, "vendor": "sophos"}
      ]
    }

vendor is one of: auto | unifi | sophos.
"""

import json

VALID_VENDORS = {"auto", "unifi", "sophos"}


class ConfigError(Exception):
    pass


class Device:
    __slots__ = ("name", "port", "vendor")

    def __init__(self, name, port, vendor):
        self.name = name
        self.port = port
        self.vendor = vendor

    def as_dict(self):
        return {"name": self.name, "port": self.port, "vendor": self.vendor}


class Config:
    def __init__(self, devices, retention_days, max_events):
        self.devices = devices
        self.retention_days = retention_days
        self.max_events = max_events


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ConfigError(
            f"config file not found: {path} — mount a devices.json and set "
            f"DEVICES_CONFIG (see devices.example.json)")
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path} is not valid JSON: {e}")

    if not isinstance(raw, dict) or "devices" not in raw:
        raise ConfigError("config must be an object with a 'devices' list")

    devices, seen_ports, seen_names = [], set(), set()
    for i, d in enumerate(raw["devices"]):
        if not isinstance(d, dict):
            raise ConfigError(f"devices[{i}] must be an object")
        name = d.get("name")
        port = d.get("port")
        vendor = d.get("vendor", "auto")
        if not name or not isinstance(name, str):
            raise ConfigError(f"devices[{i}] needs a non-empty string 'name'")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigError(f"device {name!r}: 'port' must be 1-65535")
        if vendor not in VALID_VENDORS:
            raise ConfigError(
                f"device {name!r}: vendor must be one of {sorted(VALID_VENDORS)}")
        if port in seen_ports:
            raise ConfigError(f"port {port} is used by more than one device")
        if name in seen_names:
            raise ConfigError(f"duplicate device name {name!r}")
        seen_ports.add(port)
        seen_names.add(name)
        devices.append(Device(name, port, vendor))

    if not devices:
        raise ConfigError("config has no devices")

    retention_days = raw.get("retention_days", 14)
    max_events = raw.get("max_events", 0)
    return Config(devices, retention_days, max_events)
