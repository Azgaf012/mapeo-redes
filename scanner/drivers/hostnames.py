"""Classify a device from a host name learned through mDNS, DNS, NetBIOS or SNMP."""

import re

_RULES = [
    (re.compile(r"iphone|ipad|ipod", re.I), "PHONE", 60, "Apple iOS/iPadOS"),
    (re.compile(r"android|galaxy|(?:^|[-_ ])sm-[a-z]\d|redmi|poco|pixel[-_ ]|oneplus|realme|"
                r"oppo|vivo[-_ ]|tecno|infinix|(?:^|[-_ ])moto[-_ ]", re.I), "PHONE", 55, "Android"),
    (re.compile(r"macbook|(?:^|[-_ ])mbp(?:$|[-_ 0-9])", re.I), "LAPTOP", 60, "Apple Mac portátil"),
    (re.compile(r"imac|mac-?mini|mac-?studio", re.I), "PC", 55, "Apple Mac de escritorio"),
    (re.compile(r"^(?:laptop|notebook)[-_]|thinkpad|latitude|elitebook|probook|ideapad|surface", re.I),
     "LAPTOP", 55, "Portátil"),
    (re.compile(r"^(?:desktop|pc|workstation|win)[-_]", re.I), "PC", 55, "Computador Windows"),
    (re.compile(r"chromecast|roku|apple-?tv|fire-?tv|bravia|webos|tizen|smart-?tv|"
                r"(?:^|[-_ .])tv(?:$|[-_ .0-9])", re.I), "SMART_TV", 55, "TV / multimedia"),
    (re.compile(r"^npi[0-9a-f]{6}|^brn[0-9a-f]{6}|^km[0-9a-f]{6}|printer|impresora|"
                r"epson[0-9a-f]{4}|^hp[0-9a-f]{6}", re.I), "PRINTER", 55, "Impresora"),
    (re.compile(r"(?:^|[-_])(?:nvr|dvr)(?:$|[-_0-9])", re.I), "NVR", 55, "Grabador de video"),
    (re.compile(r"(?:^|[-_])(?:cam|camera|ipc)(?:$|[-_0-9])|^ds-2cd", re.I), "CAMERA", 55, "Cámara IP"),
]


def classify_hostname(name):
    """Return ``(device_type, weight, label)`` or None."""
    text = (name or "").strip()
    if not text or text in {"Celular / Móvil", "Smartphone (MAC Privada)"}:
        return None
    for pattern, device_type, weight, label in _RULES:
        if pattern.search(text):
            return device_type, weight, label
    return None
