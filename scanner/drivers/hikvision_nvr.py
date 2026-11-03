"""Hikvision NVR driver: lists the IP cameras registered in the recorder (ISAPI).

PoE NVRs (``DS-76xxNI-xx/8P``...) put their cameras on an internal switch, usually
192.168.254.0/24, that the scanned LAN cannot reach: those cameras never answer a ping.
The recorder knows them, so we ask it (``/ISAPI/ContentMgmt/InputProxy/channels``) and
publish each channel as a ``peer`` camera.

Credentials are per NVR (``NvrCredentialRepository``): the first scan registers each
recorder as "pending", the operator assigns an account in the NVR page, and later scans
reuse it. ``NVR_USER`` / ``NVR_PASS`` / ``NVR_PORT`` remain as an optional global fallback.
A rejected account (HTTP 401) is not retried until the operator changes it, so a scan
never locks the recorder's user out.
"""

import logging
import os
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from scanner.drivers.base import Driver, DriverResult

log = logging.getLogger("netmap.identity")

CHANNELS = "/ISAPI/ContentMgmt/InputProxy/channels"
STATUS = "/ISAPI/ContentMgmt/InputProxy/channels/status"
_RECORDER = re.compile(r"\b(?:i?DS-(?:7|8|9)\d|NVR|DVR|XVR)", re.I)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _records(xml_text, wanted):
    """Yield one dict per ``wanted`` element, with its nested leaves flattened."""
    root = ET.fromstring(xml_text)
    for node in root.iter():
        if _local(node.tag) != wanted:
            continue
        row = {}
        for child in node.iter():
            if child is not node and len(child) == 0 and (child.text or "").strip():
                row.setdefault(_local(child.tag), child.text.strip())
        yield row


def parse_channels(channels_xml, status_xml=""):
    online = {}
    if status_xml:
        for row in _records(status_xml, "InputProxyChannelStatus"):
            online[row.get("id", "")] = (row.get("online") or "").lower() == "true"
    peers = []
    for row in _records(channels_xml, "InputProxyChannel"):
        ip = row.get("ipAddress") or row.get("ipv4Address") or ""
        if not ip or ip == "0.0.0.0":
            continue
        channel = row.get("id", "")
        peers.append({
            "ip": ip, "mac": "", "device_type": "CAMERA", "source": "nvr",
            "hostname": row.get("name") or f"Canal {channel}",
            "model": row.get("model", ""), "serial": row.get("serialNumber", ""),
            "channel": channel, "online": online.get(channel),
        })
    return peers



def _get(ip, path, user, password, port):
    manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, f"http://{ip}:{port}/", user, password)
    opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(manager),
                                         urllib.request.HTTPBasicAuthHandler(manager))
    with opener.open(f"http://{ip}:{port}{path}", timeout=5) as response:
        return response.read().decode("utf-8", "replace")


def fetch_cameras(ip, user, password, port=80):
    """Ask one NVR for its cameras. Returns ``(status, detail, peers)``.

    status: ok | auth_failed | no_isapi | unreachable
    """
    try:
        channels = _get(ip, CHANNELS, user, password, port)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return "auth_failed", "Usuario o clave rechazados por el NVR", []
        return "no_isapi", f"El NVR respondio HTTP {exc.code} a ISAPI", []
    except Exception as exc:
        return "unreachable", f"No se pudo conectar: {exc}", []
    try:
        status_xml = _get(ip, STATUS, user, password, port)
    except Exception:
        status_xml = ""
    try:
        peers = parse_channels(channels, status_xml)
    except ET.ParseError as exc:
        return "no_isapi", f"Respuesta ISAPI invalida: {exc}", []
    for peer in peers:
        peer["nvr_ip"] = ip
    return "ok", f"{len(peers)} camaras registradas en el NVR", peers


class HikvisionNvrDriver(Driver):
    name = "hikvision-nvr-isapi"
    priority = 25

    def __init__(self):
        self.store = None            # NvrCredentialRepository, set by the application
        self._seen = set()

    def begin_scan(self):
        self._seen = set()

    def matches(self, facts):
        if "hikvision" not in (facts.vendor or "").lower():
            return False
        return facts.base_type == "NVR" or bool(_RECORDER.search(facts.hostname or ""))

    def _credentials(self, facts):
        """Return (user, password, port) or None when this NVR must be skipped."""
        if self.store:
            row = self.store.seen(facts.ip, facts.mac)
            if row["status"] == "auth_failed":
                return None                      # wait for the operator to fix it
            if row["has_credentials"]:
                return row["username"], row["password"], row["port"] or 80
        user, password = os.environ.get("NVR_USER"), os.environ.get("NVR_PASS")
        if user and password:
            return user, password, int(os.environ.get("NVR_PORT", "80") or 80)
        return None

    def probe(self, facts):
        if facts.ip in self._seen:
            return None
        self._seen.add(facts.ip)
        credentials = self._credentials(facts)
        if not credentials:
            return None
        status, detail, peers = fetch_cameras(facts.ip, *credentials)
        if self.store:
            self.store.set_result(facts.ip, facts.mac, status, detail, len(peers))
        if status != "ok":
            log.warning("NVR %s: %s", facts.ip, detail)
            return None
        if not peers:
            return None
        return DriverResult(device_type="NVR", weight=85, vendor="Hikvision", peers=peers,
                            detail=f"ISAPI: {len(peers)} camaras registradas")
