"""Aruba Instant driver (SNMP, AI-AP-MIB).

When the Virtual Controller answers SNMP it publishes every access point and every
wireless client of the cluster. That identifies the APs (name, serial, model) and
the clients behind private MAC addresses (name, OS), and tells which AP each client
is on - without a manual CSV.

Column numbers: the client table (``aiClientTable``: MAC=1, IP=3, name=5, OS=6) is
documented by HPE/Observium. The AP table columns below are a best guess and are
validated at run time (IP column is detected from the data). Every raw table is
dumped to ``<logs>/driver_debug/aruba_<ip>.json`` so the mapping can be corrected
from real firmware output.
"""

import ipaddress
import json
import logging
import os
import threading

from scanner.drivers.base import Driver, DriverResult
from scanner.snmp_inventory import snmp_text, walk_snmp_columns

log = logging.getLogger("netmap.identity")

AP_TABLE = "1.3.6.1.4.1.14823.2.3.3.1.2.1.1"
CLIENT_TABLE = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1"
AP_COLUMNS = {"name": 2, "ip": 3, "serial": 4, "model": 6}      # best guess, validated at run time
CLIENT_COLUMNS = {"ip": 3, "name": 5, "os": 6}
WALK_COLUMNS = range(1, 13)


def _mac_from_suffix(suffix):
    parts = suffix.split(".")[:6]
    try:
        return ":".join(f"{int(part):02X}" for part in parts) if len(parts) == 6 else ""
    except ValueError:
        return ""


def _rows(tables, prefix):
    rows = {}
    for key, values in tables.items():
        if not key.startswith(prefix):
            continue
        column = int(key[len(prefix):])
        for suffix, value in values.items():
            mac = _mac_from_suffix(suffix)
            if mac:
                rows.setdefault(mac, {})[column] = snmp_text(value).strip()
    return rows


def _is_ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value)) != "0.0.0.0"
    except ValueError:
        return False


def _detect_ip_column(rows, default):
    columns = {column for row in rows.values() for column in row}
    for column in sorted(columns):
        values = [row[column] for row in rows.values() if column in row]
        if values and all(_is_ipv4(value) for value in values):
            return column
    return default


def _useful(value):
    value = (value or "").strip()
    return value if value and not value.replace(".", "").replace(":", "").isdigit() else ""


class ArubaInstantDriver(Driver):
    name = "aruba-instant-snmp"
    priority = 30

    def __init__(self):
        self._lock = threading.Lock()
        self._done = False

    def begin_scan(self):
        self._done = False

    def matches(self, facts):
        if not facts.snmp.get("has_snmp"):
            return False
        oid = (facts.snmp.get("sys_object_id") or "").lstrip(".")
        descr = (facts.snmp.get("sys_descr") or "").lower()
        return oid.startswith("1.3.6.1.4.1.14823.") or "instant" in descr or "aruba" in descr

    def probe(self, facts):
        with self._lock:
            if self._done:
                return None
            tables = walk_snmp_columns(
                facts.ip, facts.credentials,
                {**{f"ap{column}": f"{AP_TABLE}.{column}" for column in WALK_COLUMNS},
                 **{f"cl{column}": f"{CLIENT_TABLE}.{column}" for column in WALK_COLUMNS}})
            ap_rows, client_rows = _rows(tables, "ap"), _rows(tables, "cl")
            if not ap_rows and not client_rows:
                return None
            self._done = True  # only the Virtual Controller publishes these tables
        self._dump(facts.ip, ap_rows, client_rows)

        ip_column = _detect_ip_column(ap_rows, AP_COLUMNS["ip"])
        peers, own = [], {}
        for mac, row in ap_rows.items():
            peer = {"mac": mac, "ip": row.get(ip_column, ""),
                    "hostname": _useful(row.get(AP_COLUMNS["name"])),
                    "serial": _useful(row.get(AP_COLUMNS["serial"])),
                    "model": _useful(row.get(AP_COLUMNS["model"])),
                    "device_type": "ACCESS_POINT"}
            peers.append(peer)
            if peer["ip"] == facts.ip:
                own = peer

        client_ip_column = _detect_ip_column(client_rows, CLIENT_COLUMNS["ip"])
        clients = [{"mac": mac, "ip": row.get(client_ip_column, ""),
                    "name": _useful(row.get(CLIENT_COLUMNS["name"])),
                    "os": _useful(row.get(CLIENT_COLUMNS["os"])),
                    "raw": {str(column): value for column, value in row.items()}}
                   for mac, row in client_rows.items()]
        return DriverResult(
            device_type="ACCESS_POINT", weight=85, vendor="Aruba",
            model=own.get("model", ""), serial=own.get("serial", ""),
            hostname=own.get("hostname", ""), peers=peers, clients=clients,
            detail=f"Virtual Controller: {len(peers)} AP, {len(clients)} clientes")

    def _dump(self, ip, ap_rows, client_rows):
        if not self.debug_dir:
            return
        try:
            os.makedirs(self.debug_dir, exist_ok=True)
            with open(os.path.join(self.debug_dir, f"aruba_{ip}.json"), "w", encoding="utf-8") as handle:
                json.dump({"ap_table": ap_rows, "client_table": client_rows}, handle,
                          ensure_ascii=False, indent=1)
        except OSError as exc:
            log.warning("No se pudo guardar el volcado de Aruba: %s", exc)
