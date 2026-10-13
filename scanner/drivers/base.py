"""Contracts shared by built-in, Python-plugin and native (DLL) identification drivers.

A driver looks at what the scan already knows about one host (``HostFacts``) and
may return a ``DriverResult``: a device type, vendor/model/serial/firmware and
how much the driver trusts its own answer (``weight``, 0-100). The identity
engine combines every result; drivers never write to the database.
"""

from dataclasses import dataclass, field

from scanner.vendor import is_locally_administered_mac


@dataclass
class HostFacts:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    ttl: int = None
    snmp: dict = field(default_factory=dict)
    web: dict = field(default_factory=dict)
    base_type: str = "UNKNOWN"
    base_source: str = ""
    is_gateway: bool = False
    credentials: dict = field(default_factory=dict)
    shared: object = None  # SharedDiscovery filled once per scan

    @property
    def private_mac(self):
        clean = "".join(char for char in (self.mac or "") if char.isalnum())
        return bool(clean) and is_locally_administered_mac(clean)

    def to_request(self):
        """JSON-safe view for native plugins. Credentials are never included."""
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "hostname": self.hostname, "open_ports": list(self.open_ports or []),
            "ttl": self.ttl, "base_type": self.base_type,
            "sys_descr": self.snmp.get("sys_descr") or "",
            "sys_object_id": self.snmp.get("sys_object_id") or "",
            "sys_name": self.snmp.get("sys_name") or "",
            "web_title": self.web.get("web_title") or "",
        }


@dataclass
class DriverResult:
    device_type: str = None
    weight: int = 80
    vendor: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    hostname: str = ""
    detail: str = ""
    extra: dict = field(default_factory=dict)
    clients: list = field(default_factory=list)   # wireless clients seen by a controller
    peers: list = field(default_factory=list)     # other devices described by this one


class Driver:
    """Base class. Override ``matches`` (cheap, no I/O) and ``probe`` (may do I/O)."""

    name = "driver"
    priority = 100          # lower runs first
    debug_dir = None        # set by the registry; drivers may dump raw data there

    def begin_scan(self):
        """Called once before each scan so drivers can reset per-scan state."""

    def matches(self, facts):
        return False

    def probe(self, facts):
        return None
