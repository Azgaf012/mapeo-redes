"""Vendor knowledge tables: sysObjectID prefixes and OUI-name roles.

``sysObjectID`` enterprise numbers come from the IANA registry. The HP ProCurve
prefix was confirmed on a real HP 2530 switch; the others are standard but have
not been verified against every firmware. Correct or extend them without
touching code through ``identity_overrides.csv`` (match_type ``sysobjectid_prefix``)
or a plugin in ``plugins/``.
"""

import re

from scanner.classifier import is_access_point_identity

# (prefix, vendor, device type or "AUTO" -> decide from sysDescr)
SYS_OBJECT_IDS = [
    ("1.3.6.1.4.1.11.2.3.7.11.", "HPE (ProCurve / ArubaOS-Switch)", "SWITCH"),
    ("1.3.6.1.4.1.11.2.3.9.", "HP", "PRINTER"),
    ("1.3.6.1.4.1.47196.", "Aruba (ArubaOS-CX)", "SWITCH"),
    ("1.3.6.1.4.1.14823.", "Aruba", "AUTO"),
    ("1.3.6.1.4.1.9.1.", "Cisco", "AUTO"),
    ("1.3.6.1.4.1.41112.", "Ubiquiti", "AUTO"),
    ("1.3.6.1.4.1.14988.", "MikroTik", "AUTO"),
    ("1.3.6.1.4.1.12356.", "Fortinet", "FIREWALL"),
    ("1.3.6.1.4.1.25461.", "Palo Alto Networks", "FIREWALL"),
    ("1.3.6.1.4.1.367.", "Ricoh", "PRINTER"),
    ("1.3.6.1.4.1.1248.", "Epson", "PRINTER"),
    ("1.3.6.1.4.1.2435.", "Brother", "PRINTER"),
    ("1.3.6.1.4.1.1347.", "Kyocera", "PRINTER"),
    ("1.3.6.1.4.1.253.", "Xerox", "PRINTER"),
    ("1.3.6.1.4.1.641.", "Lexmark", "PRINTER"),
    ("1.3.6.1.4.1.1602.", "Canon", "PRINTER"),
    ("1.3.6.1.4.1.18334.", "Konica Minolta", "PRINTER"),
    ("1.3.6.1.4.1.318.", "APC (Schneider Electric)", "UPS"),
    ("1.3.6.1.4.1.534.", "Eaton", "UPS"),
    ("1.3.6.1.4.1.39165.", "Hikvision", "CAMERA"),
    ("1.3.6.1.4.1.6574.", "Synology", "SERVER"),
    ("1.3.6.1.4.1.24681.", "QNAP", "SERVER"),
    ("1.3.6.1.4.1.2011.", "Huawei", "AUTO"),
    ("1.3.6.1.4.1.171.", "D-Link", "AUTO"),
    ("1.3.6.1.4.1.11863.", "TP-Link", "AUTO"),
    ("1.3.6.1.4.1.4526.", "Netgear", "AUTO"),
]

_SWITCH = re.compile(r"switch|\bus-|\busw|edgeswitch|catalyst|procurve|\bcbs\d|\bsg\d|\bcrs\d|\bdgs-", re.I)
_ROUTER = re.compile(r"router|routeros|edgerouter|\bers?-|\bisr\d|\basr\d|\bhap\b", re.I)
_FIREWALL = re.compile(r"firewall|fortigate|\basa\b|pan-os|\busg\b", re.I)


def match_sys_object_id(oid):
    """Longest matching prefix for an sysObjectID, or None."""
    oid = (oid or "").strip().lstrip(".")
    best = None
    for prefix, vendor, device_type in SYS_OBJECT_IDS:
        if (oid + ".").startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, vendor, device_type)
    return best


def type_from_description(description, hostname=""):
    """Infer a network role from sysDescr/model text; None when it is not decisive."""
    if is_access_point_identity(hostname, {"sys_descr": description}):
        return "ACCESS_POINT"
    if _FIREWALL.search(description):
        return "FIREWALL"
    if _SWITCH.search(description):
        return "SWITCH"
    if _ROUTER.search(description):
        return "ROUTER"
    return None


# (vendor-name keywords, device type, weight, note). The weight is deliberately
# low: an OUI says who made the radio/NIC, not what the finished device is.
VENDOR_ROLES = [
    (("ricoh", "lexmark", "konica", "oki data", "kyocera", "epson", "brother", "xerox"),
     "PRINTER", 45, "fabricante de impresoras"),
    (("hikvision", "dahua", "axis communications", "uniview", "hanwha", "reolink", "vivotek"),
     "CAMERA", 45, "fabricante de cámaras"),
    (("american power conversion", "eaton", "cyber power", "tripp lite"),
     "UPS", 40, "fabricante de UPS"),
    (("synology", "qnap"), "SERVER", 45, "fabricante de NAS"),
    (("azurewave", "liteon", "hon hai", "foxconn", "fugui", "cloud network technology",
      "mediatek", "ralink", "qualcomm", "murata", "universal global scientific", "askey",
      "wistron neweb", "compal", "intel corporate", "shenzhen elink", "wnc corporation",
      "fn-link", "azurewave", "liteon"),
     "WIFI_CLIENT", 30, "módulo Wi-Fi/NIC usado en portátiles, PC y dispositivos IoT"),
    (("motorola", "xiaomi", "oppo", "vivo", "oneplus", "realme", "huawei device", "honor",
      "samsung electronics", "spreadtrum", "tecno", "infinix"),
     "PHONE", 35, "fabricante de teléfonos"),
]

# Vendors that make network gear but whose OUI does not say which kind.
NETWORK_VENDORS = ("d-link", "tp-link", "huawei", "zyxel", "netgear", "hewlett packard enterprise",
                   "aruba", "cisco", "ubiquiti", "mikrotik", "fortinet", "cambium", "ruckus")


def _word(keyword, text):
    return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}", text) is not None


def vendor_role(vendor):
    """Return ``(type, weight, note)`` for a vendor name, or None."""
    name = (vendor or "").lower()
    if not name:
        return None
    for keywords, device_type, weight, note in VENDOR_ROLES:
        if any(_word(keyword, name) for keyword in keywords):
            return device_type, weight, note
    return None


def network_vendor_with_telnet(vendor, open_ports):
    """Managed-switch vendors that expose Telnet (23): a weak but useful switch hint."""
    name = (vendor or "").lower()
    return 23 in (open_ports or []) and any(
        _word(keyword, name) for keyword in ("hewlett packard enterprise", "aruba", "d-link", "cisco"))


def vendor_hint(vendor):
    """Short human note for the unidentified report."""
    name = (vendor or "").lower()
    role = vendor_role(vendor)
    if role:
        return role[2]
    if any(_word(keyword, name) for keyword in NETWORK_VENDORS):
        return "fabricante de red: falta confirmar si es AP, switch o router"
    if "espressif" in name:
        return "IoT (Espressif): sensor, enchufe o dispositivo doméstico"
    return ""
