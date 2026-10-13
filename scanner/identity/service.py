"""Run every identification source for a host and resolve one answer.

Sources: the existing fingerprint/classifier result, the driver registry
(vendor protocols, SNMP, UPnP, mDNS, plugins), host-name and OUI hints, and the
operator's overrides. ``begin_scan`` runs the broadcast sweeps once; ``identify``
is thread-safe.
"""

import csv
import io
import logging
import os
import threading

from scanner.drivers.base import HostFacts
from scanner.drivers.hostnames import classify_hostname
from scanner.drivers.protocols import SharedDiscovery, normalize_mac, run_scan_sweeps
from scanner.drivers.registry import DriverRegistry
from scanner.drivers.vendors import vendor_hint, vendor_role
from scanner.identity.engine import Evidence, MIN_SCORE, resolve
from scanner.identity.overrides import OverridesStore
from scanner.identity.unidentified import UnidentifiedLog, manual_entries

log = logging.getLogger("netmap.identity")

BASE_WEIGHTS = {"fingerprint": 70, "classifier": 50}


class IdentityService:
    def __init__(self, data_dir, plugin_dir="", mdns=True, broadcast=True, sweep_seconds=3.0,
                 registry=None):
        self.broadcast = broadcast
        self.sweep_seconds = sweep_seconds
        self.registry = registry or DriverRegistry()
        if registry is None:
            self.registry.load_builtin(mdns_enabled=mdns)
            self.registry.load_plugins(plugin_dir)
        self.registry.set_debug_dir(os.path.join(data_dir, "driver_debug"))
        self.overrides = OverridesStore(os.path.join(data_dir, "identity_overrides.csv"))
        self.unidentified = UnidentifiedLog(os.path.join(data_dir, "unidentified_devices.csv"))
        self.shared = SharedDiscovery()
        self._lock = threading.Lock()
        self.peers = []
        self.clients = []

    # -- scan lifecycle -----------------------------------------------------
    def begin_scan(self, local_ip=""):
        for kind, value, device_type, vendor, model in self.unidentified.collect_manual():
            self.overrides.upsert(kind, value, device_type, vendor, model, "desde reporte")
        self.unidentified.begin_scan()
        self.peers, self.clients = [], []
        self.registry.begin_scan()
        self.shared = run_scan_sweeps(local_ip, self.sweep_seconds, self.broadcast)

    def finish_scan(self):
        return self.unidentified.write()

    # -- per host -----------------------------------------------------------
    def identify(self, facts, base_model=""):
        facts.shared = self.shared
        evidences = []
        weight = BASE_WEIGHTS.get(facts.base_source)
        if facts.base_type != "UNKNOWN" and weight:
            evidences.append(Evidence(facts.base_source, weight, facts.base_type,
                                      model=base_model, detail="clasificación base"))
        hint = classify_hostname(facts.hostname)
        if hint:
            evidences.append(Evidence("hostname", hint[1], hint[0], detail=hint[2]))
        role = None if facts.private_mac else vendor_role(facts.vendor)
        if role:
            evidences.append(Evidence("oui", role[1], role[0], detail=role[2]))
        for driver, result in self.registry.run(facts):
            evidences.append(Evidence(
                driver.name, result.weight, result.device_type, vendor=result.vendor,
                model=result.model, serial=result.serial, firmware=result.firmware,
                hostname=result.hostname, detail=result.detail))
            if result.peers or result.clients:
                with self._lock:
                    self.peers.extend(result.peers)
                    self.clients.extend(result.clients)

        override = self.overrides.match(facts)
        if override:
            evidences.append(Evidence(
                "override", 100, override.get("device_type") or None,
                vendor=override.get("vendor", ""), model=override.get("model", ""),
                detail=f"{override.get('match_type')}={override.get('match_value')}"))

        identity = resolve(evidences)
        if identity.device_type == "UNKNOWN" or identity.score < MIN_SCORE:
            identity.device_type = "UNKNOWN"
            self.unidentified.add(facts, vendor_hint(facts.vendor))
        return identity

    # -- operator feedback --------------------------------------------------
    def import_feedback(self, content):
        """Store the classifications typed into a (possibly re-uploaded) report."""
        text = content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        entries = manual_entries(rows)
        for kind, value, device_type, vendor, model in entries:
            self.overrides.upsert(kind, value, device_type, vendor, model, "importado")
        return {"rows": len(rows), "imported": len(entries)}

    def override_for(self, ip="", mac="", hostname="", sys_object_id=""):
        facts = HostFacts(ip=ip, mac=mac, hostname=hostname,
                          snmp={"sys_object_id": sys_object_id})
        return self.overrides.match(facts)

    # -- scan-wide results --------------------------------------------------
    def clients_by_mac(self):
        return {normalize_mac(client.get("mac")): client for client in self.clients
                if client.get("mac")}
