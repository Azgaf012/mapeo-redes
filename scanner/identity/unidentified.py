"""Report of hosts the application could not name (``unidentified_devices.csv``).

The file is rewritten after every scan. The operator fills ``manual_type`` (and
optionally ``manual_vendor`` / ``manual_model`` / ``apply_to_oui``); the next scan
moves those rows into ``identity_overrides.csv`` and applies them with top weight.
The same file can be downloaded and re-uploaded from the web interface.
"""

import csv
import io
import os
import threading
from datetime import datetime

from scanner.identity.overrides import TRUE_VALUES, normalize_type, oui_of

COLUMNS = ["ip", "mac", "oui", "vendor", "hostname", "open_ports", "sys_object_id", "sys_descr",
           "hint", "last_seen", "manual_type", "manual_vendor", "manual_model", "apply_to_oui"]
MANUAL_COLUMNS = ("manual_type", "manual_vendor", "manual_model", "apply_to_oui")


def _read(path):
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def manual_entries(rows):
    """Turn completed report rows into ``(match_type, value, type, vendor, model)``."""
    found = []
    for row in rows:
        device_type = normalize_type(row.get("manual_type"))
        if not device_type:
            continue
        by_oui = (row.get("apply_to_oui") or "").strip().lower() in TRUE_VALUES
        mac = (row.get("mac") or "").strip()
        vendor, model = row.get("manual_vendor") or "", row.get("manual_model") or ""
        if mac and by_oui and oui_of(mac):
            found.append(("oui", oui_of(mac), device_type, vendor, model))
        elif mac:
            found.append(("mac", mac, device_type, vendor, model))
        elif (row.get("ip") or "").strip():
            found.append(("ip", row["ip"].strip(), device_type, vendor, model))
    return found


class UnidentifiedLog:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._entries = {}

    def begin_scan(self):
        with self._lock:
            self._entries = {}

    def add(self, facts, hint=""):
        key = facts.mac or facts.ip
        with self._lock:
            self._entries[key] = {
                "ip": facts.ip, "mac": facts.mac or "", "oui": oui_of(facts.mac),
                "vendor": facts.vendor or "", "hostname": facts.hostname or "",
                "open_ports": " ".join(str(port) for port in facts.open_ports or []),
                "sys_object_id": facts.snmp.get("sys_object_id") or "",
                "sys_descr": (facts.snmp.get("sys_descr") or "")[:120],
                "hint": hint, "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
            }

    def collect_manual(self):
        """Rows the operator completed in the report file."""
        return manual_entries(_read(self.path))

    def template(self):
        """Current report as CSV text (header only when nothing is pending)."""
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(_read(self.path))
        return buffer.getvalue()

    def write(self):
        """Persist this scan's unidentified hosts, keeping what the operator already typed."""
        previous = {}
        for row in _read(self.path):
            previous[row.get("mac") or row.get("ip") or ""] = row
            previous.setdefault(row.get("ip") or "", row)
        with self._lock:
            entries = dict(self._entries)
        for key, row in entries.items():
            old = previous.get(key) or previous.get(row["ip"]) or {}
            for column in MANUAL_COLUMNS:
                row[column] = old.get(column, "")
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(sorted(entries.values(), key=lambda item: item["ip"]))
        except OSError:
            pass
        return len(entries)
