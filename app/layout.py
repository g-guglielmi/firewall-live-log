"""Overview layout: how firewalls are grouped into categories and ordered on
the dashboard's Overview tab.

This is a *display-only* preference, kept deliberately separate from
``devices.json`` so the config file can stay in whatever order the operator
likes (e.g. UDP-port order) while the GUI arranges the overview. It is a
single, shared, admin-managed arrangement persisted as a small JSON file in
the data directory (default ``/data/layout.json``), written atomically.

Only device *names* are stored; the live per-device data still comes from the
events DB. A device present in the config but not placed by the layout falls
into a trailing "Uncategorized" group (in config order), so newly added
firewalls always show up without touching the saved layout.
"""

import json
import os
import tempfile
import threading

LAYOUT_VERSION = 1
UNCATEGORIZED = "Uncategorized"


class LayoutStore:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        with self.lock:
            self._cats = self._read()

    def _read(self):
        """Load and defensively normalise the saved categories, or [] when the
        file is missing/corrupt (a bad layout must never break the dashboard)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        cats = data.get("categories") if isinstance(data, dict) else None
        if not isinstance(cats, list):
            return []
        out = []
        for c in cats:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str):
                continue
            devs = c.get("devices")
            devs = [d for d in devs if isinstance(d, str)] \
                if isinstance(devs, list) else []
            out.append({"name": c["name"], "devices": devs})
        return out

    def get(self):
        """A copy of the raw saved categories (names + device-name lists)."""
        with self.lock:
            return [{"name": c["name"], "devices": list(c["devices"])}
                    for c in self._cats]

    def save(self, categories):
        """Persist a validated categories list ([{name, devices}]) atomically.
        The caller is responsible for validation (names, caps, device names)."""
        clean = [{"name": c["name"], "devices": list(c["devices"])}
                 for c in categories]
        with self.lock:
            self._write(clean)
            self._cats = clean

    def _write(self, cats):
        payload = {"version": LAYOUT_VERSION, "categories": cats}
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".layout-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, self.path)          # atomic on POSIX and Windows
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def resolve(self, device_names):
        """Return ``(categories, uncategorized)`` for the given configured
        device names (in config order).

        ``categories`` is the saved list in order — each ``{name, devices}``
        keeps only devices that still exist, and every device appears at most
        once. ``uncategorized`` is the configured devices no category placed,
        in config order."""
        valid = list(device_names)
        valid_set = set(valid)
        seen = set()
        groups = []
        with self.lock:
            cats = [{"name": c["name"], "devices": list(c["devices"])}
                    for c in self._cats]
        for c in cats:
            placed = []
            for d in c["devices"]:
                if d in valid_set and d not in seen:
                    placed.append(d)
                    seen.add(d)
            groups.append({"name": c["name"], "devices": placed})
        leftover = [d for d in valid if d not in seen]
        return groups, leftover
