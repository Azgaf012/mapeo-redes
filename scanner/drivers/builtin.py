"""Built-in identification drivers.

Each driver is small and independent. Add a vendor by creating another ``Driver``
(here or as a plugin in ``plugins/``) - nothing else needs to change.
"""

import logging
import re

from scanner.drivers.base import Driver, DriverResult
from scanner.drivers.hostnames import classify_hostname
from scanner.drivers.protocols import fetch_upnp_description, mdns_reverse_name
from scanner.drivers.vendors import match_sys_object_id, type_from_description

log = logging.getLogger("netmap.identity")

INFRASTRUCTURE = {"ROUTER", "FIREWALL", "SWITCH", "ACCESS_POINT", "CONTROLLER"}


class SysObjectIdDriver(Driver):
    """The enterprise number in sysObjectID names the vendor and often the product line."""

    name = "sysobjectid"
    priority = 10

    def matches(self, facts):
        return bool(facts.snmp.get("sys_object_id"))

    def probe(self, facts):
        found = match_sys_object_id(facts.snmp.get("sys_object_id"))
        if not found:
            return None
        prefix, vendor, device_type = found
        descr = facts.snmp.get("sys_descr") or ""
        model = facts.snmp.get("model") or descr.split(" / ")[0][:80]
        weight = 85
        if device_type == "AUTO":
            device_type = type_from_description(f"{descr} {model}", facts.hostname)
            weight = 80
        return DriverResult(device_type=device_type, weight=weight if device_type else 0,
                            vendor=vendor, model=model,
                            detail=f"sysObjectID {prefix.rstrip('.')} ({vendor})")


class PrinterMibDriver(Driver):
    """Printer-MIB / Host-Resources: model, serial and page count for any SNMP printer."""

    name = "printer-mib"
    priority = 40
    _OIDS = {"descr": "1.3.6.1.2.1.25.3.2.1.3.1", "serial": "1.3.6.1.2.1.43.5.1.1.17.1",
             "pages": "1.3.6.1.2.1.43.10.2.1.4.1.1"}

    def matches(self, facts):
        if not facts.snmp.get("has_snmp"):
            return False
        match = match_sys_object_id(facts.snmp.get("sys_object_id"))
        descr = (facts.snmp.get("sys_descr") or "").lower()
        return bool((match and match[2] == "PRINTER") or "printer" in descr
                    or (9100 in (facts.open_ports or []) and facts.base_type in ("UNKNOWN", "PRINTER")))

    def probe(self, facts):
        from scanner.snmp_inventory import get_snmp_values, snmp_text

        values = get_snmp_values(facts.ip, facts.credentials, self._OIDS.values())
        text = {key: snmp_text(values[oid]).strip() for key, oid in self._OIDS.items() if oid in values}
        model = text.get("descr") or (facts.snmp.get("sys_descr") or "").split(" / ")[0][:80]
        extra = {"printer_pages": text["pages"]} if text.get("pages") else {}
        return DriverResult(device_type="PRINTER", weight=90, model=model,
                            serial=text.get("serial", ""), extra=extra,
                            detail="Printer-MIB")


class HikvisionSadpDriver(Driver):
    """Hikvision SADP broadcast reply: model, serial and firmware without credentials."""

    name = "hikvision-sadp"
    priority = 20

    def matches(self, facts):
        return facts.shared is not None and bool(facts.shared.lookup(facts.ip, facts.mac, "sadp"))

    def probe(self, facts):
        info = facts.shared.lookup(facts.ip, facts.mac, "sadp")[0]
        label = f"{info.get('device_type', '')} {info.get('description', '')}"
        is_recorder = re.search(r"\b(?:i?DS-(?:7|8|9)\d|NVR|DVR|XVR)", label, re.I) is not None
        return DriverResult(
            device_type="NVR" if is_recorder else "CAMERA", weight=90, vendor="Hikvision",
            model=info.get("device_type") or info.get("description", ""),
            serial=info.get("serial", ""), firmware=info.get("firmware", ""),
            detail="Respuesta SADP de Hikvision")


class UbiquitiDiscoveryDriver(Driver):
    name = "ubiquiti-discovery"
    priority = 20

    def matches(self, facts):
        return facts.shared is not None and bool(facts.shared.lookup(facts.ip, facts.mac, "ubnt"))

    def probe(self, facts):
        info = facts.shared.lookup(facts.ip, facts.mac, "ubnt")[0]
        model = info.get("model", "")
        device_type = None
        if re.match(r"(?:u[0-9a-z]*-?ap|uap|u6|u7|ual|nanostation|litebeam|loco|airmax)", model, re.I):
            device_type = "ACCESS_POINT"
        elif re.match(r"(?:us-|usw|edgeswitch|es-)", model, re.I):
            device_type = "SWITCH"
        elif re.match(r"(?:udm|uxg|usg|edgerouter|er-)", model, re.I):
            device_type = "ROUTER"
        return DriverResult(device_type=device_type, weight=85 if device_type else 0,
                            vendor="Ubiquiti", model=model, hostname=info.get("hostname", ""),
                            firmware=info.get("firmware", ""), detail="Descubrimiento Ubiquiti")


class MikrotikNeighborDriver(Driver):
    name = "mikrotik-mndp"
    priority = 20

    def matches(self, facts):
        return facts.shared is not None and bool(facts.shared.lookup(facts.ip, facts.mac, "mndp"))

    def probe(self, facts):
        info = facts.shared.lookup(facts.ip, facts.mac, "mndp")[0]
        board = info.get("model") or info.get("platform", "")
        if re.match(r"(?:crs|css)", board, re.I):
            device_type = "SWITCH"
        elif re.match(r"(?:cap|wap|rbcap|rbwap|mantbox|sxt|lhg)", board, re.I):
            device_type = "ACCESS_POINT"
        else:
            device_type = "ROUTER"
        return DriverResult(device_type=device_type, weight=80, vendor="MikroTik", model=board,
                            hostname=info.get("hostname", ""), firmware=info.get("firmware", ""),
                            detail="MNDP de MikroTik")


class UpnpDriver(Driver):
    """SSDP announcement plus the UPnP device description (TVs, printers, gateways)."""

    name = "upnp"
    priority = 50

    def matches(self, facts):
        return facts.shared is not None and bool(facts.shared.lookup(facts.ip, facts.mac, "ssdp"))

    def probe(self, facts):
        announcements = facts.shared.lookup(facts.ip, facts.mac, "ssdp")
        server = next((item.get("server") for item in announcements if item.get("server")), "")
        description = {}
        for item in announcements:
            if item.get("location"):
                description = fetch_upnp_description(facts.ip, item["location"])
                if description:
                    break
        kinds = " ".join([description.get("device_type", ""), " ".join(
            item.get("st", "") for item in announcements)]).lower()
        label = " ".join([description.get("manufacturer", ""), description.get("model_name", ""),
                          description.get("friendly_name", ""), server]).lower()
        device_type, weight = None, 0
        if "internetgatewaydevice" in kinds:
            device_type, weight = "ROUTER", 60
        elif "printer" in kinds or "printer" in label:
            device_type, weight = "PRINTER", 60
        elif "mediarenderer" in kinds or "tv" in label.split():
            device_type, weight = "SMART_TV", 55
        elif "camera" in label or "ipcamera" in kinds:
            device_type, weight = "CAMERA", 55
        extra = {"upnp": {**description, "server": server}} if (description or server) else {}
        return DriverResult(device_type=device_type, weight=weight,
                            vendor=description.get("manufacturer", ""),
                            model=description.get("model_name", ""),
                            hostname=description.get("friendly_name", ""),
                            extra=extra, detail="UPnP/SSDP")


class MdnsDriver(Driver):
    """Reverse mDNS name (iPhones, Macs, Chromecast answer unicast queries)."""

    name = "mdns"
    priority = 60

    def __init__(self, enabled=True):
        self.enabled = enabled

    def matches(self, facts):
        return (self.enabled and facts.base_type in ("UNKNOWN", "PC", "LAPTOP", "PHONE")
                and not facts.is_gateway)

    def probe(self, facts):
        name = mdns_reverse_name(facts.ip)
        if not name:
            return None
        hint = classify_hostname(name)
        return DriverResult(device_type=hint[0] if hint else None,
                            weight=hint[1] if hint else 0, hostname=name,
                            extra={"mdns_name": name},
                            detail=f"mDNS {name}" + (f" ({hint[2]})" if hint else ""))


def builtin_drivers(mdns_enabled=True):
    from scanner.drivers.aruba_instant import ArubaInstantDriver

    return [SysObjectIdDriver(), HikvisionSadpDriver(), UbiquitiDiscoveryDriver(),
            MikrotikNeighborDriver(), ArubaInstantDriver(), PrinterMibDriver(),
            UpnpDriver(), MdnsDriver(enabled=mdns_enabled)]
