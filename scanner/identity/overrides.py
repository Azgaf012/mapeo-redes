"""User-maintained identity overrides (``identity_overrides.csv``).

The unidentified report lists devices the application could not name. The operator
fills ``manual_type`` / ``manual_vendor`` / ``manual_model`` in that report; those rows
are moved here (keyed by MAC, or by OUI when ``apply_to_oui`` is set) and applied with
maximum weight on every following scan. Hand-written rows also work.

Columns: match_type, match_value, device_type, vendor, model, notes, added_at
match_type: mac | oui | ip | hostname_prefix | sysobjectid_prefix
"""

import csv
import os
import threading
from datetime import datetime

from scanner.drivers.protocols import normalize_mac

COLUMNS = ["match_type", "match_value", "device_type", "vendor", "model", "notes", "added_at"]
VALID_TYPES = {"ROUTER", "FIREWALL", "SWITCH", "ACCESS_POINT", "SERVER", "PC", "LAPTOP", "PHONE",
               "PRINTER", "CAMERA", "NVR", "UPS", "SMART_TV", "CONTROLLER", "WIFI_CLIENT", "UNKNOWN"}
ALIASES = {
    "CAMARA": "CAMERA", "CAMARA IP": "CAMERA", "IMPRESORA": "PRINTER", "PUNTO DE ACCESO": "ACCESS_POINT",
    "AP": "ACCESS_POINT", "ACCESS POINT": "ACCESS_POINT", "TELEFONO": "PHONE", "CELULAR": "PHONE",
    "TABLET": "PHONE", "COMPUTADORA": "PC", "COMPUTADOR": "PC", "PORTATIL": "LAPTOP", "SERVIDOR": "SERVER",
    "TV": "SMART_TV", "SMART TV": "SMART_TV", "CONTROLADOR": "CONTROLLER", "GRABADOR": "NVR",
    "CLIENTE WIFI": "WIFI_CLIENT", "CLIENTE WI-FI": "WIFI_CLIENT",
}
TRUE_VALUES = {"si", "sí", "s", "yes", "y", "true", "1", "x"}


def normalize_type(value):
    text = (value or "").strip()
    if not text:
        return None
    key = (text.upper().replace("Á", "A").replace("É", "E").replace("Í", "I")
           .replace("Ó", "O").replace("Ú", "U"))
    key = ALIASES.get(key, key.replace(" ", "_"))
    return key if key in VALID_TYPES else None


def oui_of(mac):
    clean = normalize_mac(mac)
    return clean[:6] if len(clean) >= 6 else ""


def _read(path):
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return [row for row in csv.DictReader(handle)]


class OverridesStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._stamp = None
        self._rows = []

    def _load(self):
        try:
            stamp = os.stat(self.path).st_mtime_ns
        except OSError:
            stamp = None
        if stamp != self._stamp:
            self._rows, self._stamp = _read(self.path), stamp
        return self._rows

    def match(self, facts):
        """Return the first override row that applies to the host, or None."""
        with self._lock:
            rows = list(self._load())
        mac = normalize_mac(facts.mac)
        oid = (facts.snmp.get("sys_object_id") or "").lstrip(".")
        hostname = (facts.hostname or "").lower()
        order = {"mac": 0, "ip": 1, "hostname_prefix": 2, "sysobjectid_prefix": 3, "oui": 4}
        for row in sorted(rows, key=lambda item: order.get(item.get("match_type"), 9)):
            kind, value = (row.get("match_type") or "").strip(), (row.get("match_value") or "").strip()
            if not value:
                continue
            if ((kind == "mac" and normalize_mac(value) == mac and mac)
                    or (kind == "oui" and mac.startswith(normalize_mac(value)[:6]) and mac)
                    or (kind == "ip" and value == facts.ip)
                    or (kind == "hostname_prefix" and hostname.startswith(value.lower()) and hostname)
                    or (kind == "sysobjectid_prefix" and oid.startswith(value.lstrip(".")) and oid)):
                return row
        return None

    def upsert(self, match_type, match_value, device_type, vendor, model, notes=""):
        key = normalize_mac(match_value)[:12] if match_type in ("mac", "oui") else match_value
        with self._lock:
            rows = list(self._load())
            rows = [row for row in rows if not (
                row.get("match_type") == match_type and
                (normalize_mac(row.get("match_value", "")) == key if match_type in ("mac", "oui")
                 else row.get("match_value") == key))]
            rows.append({"match_type": match_type, "match_value": match_value,
                         "device_type": device_type or "", "vendor": vendor or "", "model": model or "",
                         "notes": notes or "", "added_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            self._stamp = None

    def count(self):
        with self._lock:
            return len(self._load())
