"""Vendor-neutral and vendor-specific discovery protocols (UDP/multicast).

Everything here is best effort: a network or device that does not answer simply
produces no evidence. Parsers are pure functions so they can be tested without
a network. Responses come from the LAN and are treated as untrusted text: no
XML parser is used (regex extraction only) and device descriptions are fetched
only from the address that answered.
"""

import ipaddress
import logging
import re
import socket
import struct
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

log = logging.getLogger("netmap.identity")

SSDP_GROUP = ("239.255.255.250", 1900)
SADP_GROUP = ("239.255.255.250", 37020)
UBNT_PORT = 10001
MNDP_PORT = 5678


def normalize_mac(mac):
    return "".join(char for char in (mac or "").upper() if char in "0123456789ABCDEF")


class SharedDiscovery:
    """Answers collected once per scan and looked up per host by IP or MAC."""

    def __init__(self):
        self.by_ip = {}
        self.by_mac = {}

    def add(self, source, data, ip=None, mac=None):
        if ip:
            self.by_ip.setdefault(ip, {}).setdefault(source, []).append(data)
        clean = normalize_mac(mac)
        if len(clean) == 12:
            self.by_mac.setdefault(clean, {}).setdefault(source, []).append(data)

    def lookup(self, ip, mac, source):
        found, seen = [], set()
        clean = normalize_mac(mac)
        for bucket in (self.by_ip.get(ip, {}), self.by_mac.get(clean, {}) if clean else {}):
            for item in bucket.get(source, []):
                if id(item) not in seen:
                    seen.add(id(item))
                    found.append(item)
        return found

    def summary(self):
        counts = {}
        for bucket in (self.by_ip, self.by_mac):
            for sources in bucket.values():
                for source, items in sources.items():
                    counts[source] = max(counts.get(source, 0), 0) + len(items)
        return counts


# ---------------------------------------------------------------------------
# Low-level UDP helper
# ---------------------------------------------------------------------------

def _udp_sweep(payload, dest, local_ip="", timeout=2.0, listen_port=0, group=None, repeats=2):
    """Send ``payload`` and collect ``(sender_ip, data)`` for ``timeout`` seconds."""
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            sock.bind((local_ip or "", listen_port))
        except OSError:
            sock.bind(("", listen_port))
        if local_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        if group:
            membership = socket.inet_aton(group) + socket.inet_aton(local_ip or "0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        for _ in range(repeats):
            sock.sendto(payload, dest)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, address = sock.recvfrom(8192)
            except socket.timeout:
                break
            except ConnectionResetError:
                continue
            except OSError:
                break
            results.append((address[0], data))
    finally:
        sock.close()
    return results


def _tag(text, name):
    match = re.search(rf"<(?:\w+:)?{name}[^>]*>\s*([^<]*?)\s*</", text, re.I)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# SSDP / UPnP
# ---------------------------------------------------------------------------

def parse_ssdp_response(data):
    text = data.decode("latin-1", errors="ignore")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    if not headers:
        return None
    return {key: headers.get(key, "")[:300] for key in ("server", "st", "usn", "location")}


def ssdp_sweep(local_ip="", timeout=2.5):
    request = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found = {}
    for ip, data in _udp_sweep(request, SSDP_GROUP, local_ip, timeout):
        parsed = parse_ssdp_response(data)
        if parsed:
            found.setdefault(ip, []).append(parsed)
    return found


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def fetch_upnp_description(ip, location, timeout=1.0):
    """Read the UPnP device description, only from the host that announced it."""
    try:
        parts = urlsplit(location)
        if parts.scheme != "http" or parts.hostname != ip or not (parts.port or 80):
            return {}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(urllib.request.Request(location), timeout=timeout) as response:
            text = response.read(16384).decode("utf-8", errors="ignore")
    except Exception:
        return {}
    return parse_upnp_description(text)


def parse_upnp_description(text):
    return {key: _tag(text, tag)[:120] for key, tag in (
        ("friendly_name", "friendlyName"), ("manufacturer", "manufacturer"),
        ("model_name", "modelName"), ("model_number", "modelNumber"),
        ("serial", "serialNumber"), ("device_type", "deviceType")) if _tag(text, tag)}


# ---------------------------------------------------------------------------
# Hikvision SADP
# ---------------------------------------------------------------------------

def parse_sadp_response(data):
    text = data.decode("utf-8", errors="ignore")
    if "ProbeMatch" not in text and "DeviceType" not in text:
        return None
    mac = _tag(text, "MAC").replace("-", ":").upper()
    info = {"device_type": _tag(text, "DeviceType"),
            "description": _tag(text, "DeviceDescription"),
            "mac": mac, "ip": _tag(text, "IPv4Address"),
            "firmware": _tag(text, "SoftwareVersion"),
            "serial": _tag(text, "DeviceSN")}
    return info if any(info.values()) else None


def sadp_sweep(local_ip="", timeout=2.0):
    probe = (f'<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>{str(uuid.uuid4()).upper()}'
             "</Uuid><Types>inquiry</Types></Probe>").encode()
    found = []
    for ip, data in _udp_sweep(probe, SADP_GROUP, local_ip, timeout,
                               listen_port=SADP_GROUP[1], group=SADP_GROUP[0]):
        parsed = parse_sadp_response(data)
        if parsed:
            parsed.setdefault("source_ip", ip)
            found.append(parsed)
    return found


# ---------------------------------------------------------------------------
# Ubiquiti discovery (UDP 10001) and MikroTik MNDP (UDP 5678)
# ---------------------------------------------------------------------------

def _tlv(data, offset, type_bytes, length_bytes):
    items = []
    while offset + type_bytes + length_bytes <= len(data):
        kind = int.from_bytes(data[offset:offset + type_bytes], "big")
        length = int.from_bytes(data[offset + type_bytes:offset + type_bytes + length_bytes], "big")
        offset += type_bytes + length_bytes
        if length < 0 or offset + length > len(data):
            break
        items.append((kind, data[offset:offset + length]))
        offset += length
    return items


def _text_value(raw):
    return raw.split(b"\x00")[0].decode("utf-8", errors="ignore").strip()


def _mac_text(raw):
    return ":".join(f"{part:02X}" for part in raw[:6]) if len(raw) >= 6 else ""


def parse_ubnt_response(data):
    if len(data) < 4 or data[0] not in (1, 2):
        return None
    info = {}
    for kind, raw in _tlv(data, 4, 1, 2):
        if kind == 0x01 and len(raw) == 6:
            info["mac"] = _mac_text(raw)
        elif kind == 0x02 and len(raw) >= 10:
            info["mac"] = _mac_text(raw)
            info["ip"] = socket.inet_ntoa(raw[6:10])
        elif kind == 0x03:
            info["firmware"] = _text_value(raw)
        elif kind == 0x0B:
            info["hostname"] = _text_value(raw)
        elif kind in (0x0C, 0x14):
            info["model"] = _text_value(raw) if kind == 0x14 else info.get("model") or _text_value(raw)
    return info if info.get("model") or info.get("hostname") else None


def ubnt_sweep(local_ip="", timeout=2.0):
    found = []
    for ip, data in _udp_sweep(b"\x01\x00\x00\x00", ("255.255.255.255", UBNT_PORT), local_ip, timeout):
        parsed = parse_ubnt_response(data)
        if parsed:
            parsed.setdefault("source_ip", ip)
            found.append(parsed)
    return found


def parse_mndp_response(data):
    if len(data) < 6:
        return None
    info = {}
    for kind, raw in _tlv(data, 4, 2, 2):
        if kind == 1 and len(raw) == 6:
            info["mac"] = _mac_text(raw)
        elif kind == 5:
            info["hostname"] = _text_value(raw)
        elif kind == 7:
            info["firmware"] = _text_value(raw)
        elif kind == 8:
            info["platform"] = _text_value(raw)
        elif kind == 0x0C:
            info["model"] = _text_value(raw)
        elif kind == 0x0F and len(raw) == 4:
            info["ip"] = socket.inet_ntoa(raw)
    return info if info.get("mac") and (info.get("platform") or info.get("model")) else None


def mndp_sweep(local_ip="", timeout=2.0):
    found = []
    for ip, data in _udp_sweep(b"\x00\x00\x00\x00", ("255.255.255.255", MNDP_PORT), local_ip,
                               timeout, listen_port=MNDP_PORT):
        parsed = parse_mndp_response(data)
        if parsed:
            parsed.setdefault("source_ip", ip)
            found.append(parsed)
    return found


# ---------------------------------------------------------------------------
# mDNS reverse lookup (unicast "legacy" query, answers many Apple/Chromecast hosts)
# ---------------------------------------------------------------------------

def build_mdns_ptr_query(ip):
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    question = b"".join(bytes([len(label)]) + label.encode() for label in reverse.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x4D44, 0, 1, 0, 0, 0) + question + struct.pack(">HH", 12, 1)


def _read_name(data, offset, depth=0):
    labels = []
    jumped_end = None
    while offset < len(data) and depth < 12:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if jumped_end is None:
                jumped_end = offset + 2
            offset = pointer
            depth += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), (jumped_end if jumped_end is not None else offset)


def parse_dns_ptr_names(data):
    if len(data) < 12:
        return []
    _, _, questions, answers, authority, additional = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(questions):
        _, offset = _read_name(data, offset)
        offset += 4
    names = []
    for _ in range(min(answers + authority + additional, 32)):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        record_type, _, _, length = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if record_type == 12:
            name, _ = _read_name(data, offset)
            if name:
                names.append(name)
        offset += length
    return names


def mdns_reverse_name(ip, timeout=0.5):
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_mdns_ptr_query(ip), (ip, 5353))
        data, _ = sock.recvfrom(4096)
        for name in parse_dns_ptr_names(data):
            name = name.rstrip(".")
            if name.lower().endswith(".local"):
                name = name[:-6]
            if name and not name.endswith("in-addr.arpa"):
                return name[:120]
    except OSError:
        pass
    finally:
        sock.close()
    return ""


# ---------------------------------------------------------------------------
# Scan-wide sweeps
# ---------------------------------------------------------------------------

def run_scan_sweeps(local_ip="", seconds=3.0, broadcast=True):
    """Run SSDP, SADP, Ubiquiti and MNDP discovery in parallel; never raises."""
    shared = SharedDiscovery()
    if not broadcast:
        return shared

    def run(label, function):
        try:
            return label, function(local_ip, seconds)
        except Exception as exc:  # pragma: no cover - depends on the host network stack
            log.warning("Descubrimiento %s falló: %s", label, exc)
            return label, None

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(run, "ssdp", ssdp_sweep), pool.submit(run, "sadp", sadp_sweep),
                   pool.submit(run, "ubnt", ubnt_sweep), pool.submit(run, "mndp", mndp_sweep)]
        for future in futures:
            label, result = future.result()
            if not result:
                continue
            if label == "ssdp":
                for ip, items in result.items():
                    for item in items:
                        shared.add("ssdp", item, ip=ip)
            else:
                for item in result:
                    shared.add(label, item, ip=item.get("ip") or item.get("source_ip"),
                               mac=item.get("mac"))
    return shared
