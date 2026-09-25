"""Build distinct physical, logical and inventory maps for one installation."""

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from repositories.network_detail_repository import NetworkDetailRepository
from repositories.ap_association_repository import ApAssociationRepository
from repositories.network_repository import NetworkRepository
from scanner.network import get_local_connection_medium, get_routing_ip


class TopologyService:
    def __init__(self, device_repo, connection_repo, site_repo,
                 network_repo=None, detail_repo=None, ap_association_repo=None):
        self.device_repo = device_repo
        self.connection_repo = connection_repo
        self.site_repo = site_repo
        self.network_repo = network_repo or NetworkRepository(device_repo.db_path)
        self.detail_repo = detail_repo or NetworkDetailRepository(device_repo.db_path)
        self.ap_association_repo = ap_association_repo or ApAssociationRepository(device_repo.db_path)

    def _mac_associations(self, site_id, devices):
        """Associate MACs using switch ports, AP radios, or a recent imported snapshot."""
        def normalized(mac):
            return "".join(char for char in (mac or "").upper() if char in "0123456789ABCDEF")

        port_macs = defaultdict(set)
        switch_sightings = defaultdict(list)
        ap_sightings = defaultdict(list)
        for row in self.detail_repo.get_infrastructure_mac_learnings(site_id):
            mac = normalized(row["mac"])
            if len(mac) != 12:
                continue
            if row["device_type"] == "SWITCH":
                port = (row["infrastructure_id"], row["interface_id"])
                port_macs[port].add(mac)
                switch_sightings[mac].append(row)
            elif any(re.match(r"^(?:wlan|wifi|wi-fi|wireless|radio|ath|ssid|vap|wl)(?=$|[-_./:\s\d])",
                              str(row.get(field) or ""), re.I)
                     for field in ("port", "description")):
                ap_sightings[mac].append(row)
        visible_switches = {device["id"] for device in devices
                            if device["device_type"] == "SWITCH"}
        visible_aps = {device["id"]: device for device in devices
                       if device["device_type"] == "ACCESS_POINT"}
        switch_associations = {}
        ap_associations = {}
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
        for device in devices:
            mac = normalized(device.get("mac"))
            candidates = [row for row in switch_sightings.get(mac, [])
                          if row["infrastructure_id"] in visible_switches
                          and row["infrastructure_id"] != device["id"]
                          and len(port_macs[(row["infrastructure_id"], row["interface_id"])]) == 1]
            switches = {row["infrastructure_id"] for row in candidates}
            if len(switches) == 1:
                switch_associations[device["id"]] = {
                    "switch_id": str(candidates[0]["infrastructure_id"]),
                    "port": candidates[0]["port"],
                    "evidence": "MAC aprendida en un puerto del switch; no confirma cable directo.",
                }
            recent = []
            for row in ap_sightings.get(mac, []):
                if row["infrastructure_id"] not in visible_aps:
                    continue
                try:
                    observed = datetime.fromisoformat(row["observed_at"])
                    if observed.tzinfo:
                        observed = observed.astimezone(timezone.utc).replace(tzinfo=None)
                except (TypeError, ValueError):
                    continue
                if observed >= cutoff:
                    recent.append((observed, row))
            if not recent:
                continue
            latest = max(observed for observed, _ in recent)
            latest_rows = [row for observed, row in recent if observed == latest]
            locations = {(row["infrastructure_id"], row["interface_id"])
                         for row in latest_rows}
            if len(locations) != 1:
                continue
            ap = latest_rows[0]
            ap_device = visible_aps[ap["infrastructure_id"]]
            ap_associations[device["id"]] = {
                "ap_id": str(ap["infrastructure_id"]),
                "ap_name": ap_device["hostname"] or ap_device["ip"],
                "radio": ap["port"],
                "observed_at": ap["observed_at"],
                "evidence": "MAC observada en radio del AP; no confirma asociación Wi-Fi actual.",
            }
        devices_by_mac = defaultdict(list)
        for device in devices:
            devices_by_mac[normalized(device.get("mac"))].append(device)
        for row in self.ap_association_repo.get_by_site(site_id):
            try:
                observed = datetime.fromisoformat(row["observed_at"])
                if observed.tzinfo:
                    observed = observed.astimezone(timezone.utc).replace(tzinfo=None)
            except (TypeError, ValueError):
                continue
            if observed < cutoff:
                continue
            ap_device = visible_aps.get(row["ap_device_id"])
            if not ap_device:
                continue
            for device in devices_by_mac.get(row["client_mac"], []):
                if device["id"] == ap_device["id"]:
                    continue
                ap_associations[device["id"]] = {
                    "ap_id": str(ap_device["id"]),
                    "ap_name": ap_device["hostname"] or ap_device["ip"],
                    "observed_at": row["observed_at"],
                    "source": "ap_client_csv",
                    "evidence": "Asociación cliente–AP declarada en CSV; la fecha indica cuándo se importó.",
                }
        return switch_associations, ap_associations

    def get_cytoscape_data(self, site_id, network_cidr=None, view="physical",
                           status="ONLINE", vlan=None, method=None, search=None):
        if view not in {"physical", "logical", "inventory"}:
            raise ValueError("Vista de mapa no válida")
        if status not in {"ONLINE", "ALL"}:
            raise ValueError("Filtro de estado no válido")
        all_devices = self.device_repo.get_all(site_id=site_id)
        networks = self.network_repo.get_by_site(site_id)
        device_vlans = self.detail_repo.get_device_vlans(site_id)
        target_net = None
        if network_cidr:
            target_net = ipaddress.IPv4Network(network_cidr, strict=False)
        port_matches = self.detail_repo.find_devices_by_port(site_id, search) if search else set()
        devices = []
        for device in all_devices:
            if status == "ONLINE" and device["status"] != "ONLINE":
                continue
            if target_net and ipaddress.IPv4Address(device["ip"]) not in target_net:
                continue
            if vlan is not None and vlan not in device_vlans.get(device["id"], set()):
                continue
            if search:
                haystack = " ".join(str(device.get(key) or "") for key in
                                    ("ip", "mac", "hostname", "vendor", "model"))
                if search.lower() not in haystack.lower() and device["id"] not in port_matches:
                    continue
            devices.append(device)

        ids = {device["id"] for device in devices}
        switch_associations, ap_associations = (
            self._mac_associations(site_id, devices) if view == "physical" else ({}, {})
        )
        physical_links = self.detail_repo.get_links(site_id)
        medium_by_id = {}
        for device_id, association in ap_associations.items():
            if association.get("source") == "ap_client_csv":
                medium_by_id[device_id] = (
                    "WIFI", f"Asociación con AP importada el {association['observed_at']}.")
        for link in physical_links:
            if link["protocol"] not in ("LLDP", "CDP"):
                continue
            for device_id in (link["source_device_id"], link["target_device_id"]):
                if device_id in ids:
                    medium_by_id.setdefault(device_id, (
                        "WIRED", f"Enlace {link['protocol']} observado en {link['observed_at']}; el medio actual puede haber cambiado."
                    ))
        visible_by_ip = {device["ip"]: device for device in devices}
        local_device = visible_by_ip.get(get_routing_ip()) if devices else None
        if local_device:
            medium, evidence = get_local_connection_medium(local_device["ip"])
            if medium != "UNKNOWN":
                medium_by_id[local_device["id"]] = (medium, evidence)
        elements = []
        for device in devices:
            medium, medium_evidence = medium_by_id.get(device["id"], ("UNKNOWN", "Sin evidencia del medio de conexión."))
            medium_label = {"WIFI": "Wi-Fi", "WIRED": "Cable"}.get(medium)
            elements.append({"group": "nodes", "data": {
                "id": str(device["id"]), "kind": "device",
                "label": f"{device['hostname'] or device['ip']}\n({device['ip']})"
                         + (f"\n{medium_label}" if medium_label else ""),
                "name": device["hostname"] or device["ip"], "ip": device["ip"],
                "network_cidr": device.get("network_cidr"),
                "switch_association": switch_associations.get(device["id"]),
                "ap_association": ap_associations.get(device["id"]),
                "mac": device["mac"] or "", "hostname": device["hostname"] or "",
                "vendor": device["vendor"] or "", "model": device["model"] or "",
                "device_type": device["device_type"], "status": device["status"],
                "last_seen": device["last_seen"], "latency_ms": device["latency_ms"],
                "uptime_seconds": device.get("uptime_seconds"),
                "os_info": device["os_info"], "open_ports_list": device["open_ports_list"],
                "workgroup": device["workgroup"], "security_status": device["security_status"],
                "location": device["location"], "rack": device["rack"],
                "floor": device["floor"], "vlans": sorted(device_vlans.get(device["id"], set())),
                "is_manual": bool(device["is_manual"]),
                "connection_medium": medium, "medium_evidence": medium_evidence,
            }})

        if view == "physical":
            for link in physical_links:
                if link["source_device_id"] in ids and link["target_device_id"] in ids:
                    if method and link["protocol"] != method:
                        continue
                    elements.append({"group": "edges", "data": {
                        "id": f"p{link['id']}", "source": str(link["source_device_id"]),
                        "target": str(link["target_device_id"]),
                        "source_port": link["source_port"], "target_port": link["target_port"],
                        "discovery_method": link["protocol"], "confidence": "HIGH",
                        "observed_at": link["observed_at"], "evidence": link["evidence"],
                        "connection_type": "PHYSICAL",
                    }})
            for link in self.connection_repo.get_by_site(site_id):
                if link["discovery_method"] != "MANUAL" or method not in (None, "MANUAL"):
                    continue
                if link["source_device_id"] in ids and link["target_device_id"] in ids:
                    elements.append({"group": "edges", "data": {
                        "id": f"m{link['id']}", "source": str(link["source_device_id"]),
                        "target": str(link["target_device_id"]),
                        "discovery_method": "MANUAL", "confidence": link["confidence"],
                        "connection_type": link["connection_type"],
                    }})
        elif view == "logical":
            by_network = {network["id"]: network for network in networks}
            used_networks = {device["network_id"] for device in devices if device["network_id"]}
            devices_by_network = {}
            for device in devices:
                devices_by_network.setdefault(device["network_id"], []).append(device)
            for network_id in sorted(used_networks):
                network = by_network.get(network_id)
                if not network:
                    continue
                network_node_id = f"network:{network_id}"
                elements.append({"group": "nodes", "data": {
                    "id": network_node_id, "kind": "network",
                    "label": network["cidr"], "name": network["cidr"],
                    "gateway": network["gateway"],
                }})
                members = devices_by_network.get(network_id, [])
                gateway_ip = network.get("gateway")
                try:
                    valid_gateway = bool(gateway_ip) and (
                        ipaddress.IPv4Address(gateway_ip)
                        in ipaddress.IPv4Network(network["cidr"], strict=False)
                    )
                except ValueError:
                    valid_gateway = False
                if not valid_gateway:
                    for device in members:
                        elements.append({"group": "edges", "data": {
                            "id": f"network-member:{device['id']}",
                            "source": network_node_id,
                            "target": str(device["id"]),
                            "discovery_method": "NETWORK_MEMBERSHIP",
                        }})
                    continue

                gateway_device = next((device for device in members if device["ip"] == gateway_ip), None)
                gateway_node_id = str(gateway_device["id"]) if gateway_device else f"gateway:{network_id}"
                if not gateway_device:
                    elements.append({"group": "nodes", "data": {
                        "id": gateway_node_id, "kind": "gateway",
                        "label": f"Gateway configurado\n{gateway_ip}",
                        "name": "Gateway configurado", "ip": gateway_ip,
                        "gateway": gateway_ip,
                        "evidence": "Configurado para esta subred; equipo no visible con los filtros actuales.",
                    }})
                elements.append({"group": "edges", "data": {
                    "id": f"network-gateway:{network_id}",
                    "source": network_node_id, "target": gateway_node_id,
                    "discovery_method": "NETWORK_GATEWAY",
                    "gateway_ip": gateway_ip,
                    "evidence": "Gateway configurado para la subred.",
                }})
                for device in members:
                    if gateway_device and device["id"] == gateway_device["id"]:
                        continue
                    elements.append({"group": "edges", "data": {
                        "id": f"gateway-member:{network_id}:{device['id']}",
                        "source": gateway_node_id, "target": str(device["id"]),
                        "discovery_method": "GATEWAY_CONFIG",
                        "gateway_ip": gateway_ip,
                        "evidence": "Gateway del rango escaneado; no se verificó la ruta predeterminada del equipo ni un cable directo.",
                    }})
            used_vlans = {number for device in devices
                          for number in device_vlans.get(device["id"], set())}
            for number in sorted(used_vlans):
                elements.append({"group": "nodes", "data": {
                    "id": f"vlan:{number}", "kind": "vlan", "label": f"VLAN {number}",
                    "name": f"VLAN {number}",
                }})
            for device in devices:
                for number in device_vlans.get(device["id"], set()):
                    elements.append({"group": "edges", "data": {
                        "id": f"vlan-member:{number}:{device['id']}",
                        "source": f"vlan:{number}", "target": str(device["id"]),
                        "discovery_method": "VLAN_MEMBERSHIP",
                    }})
        else:
            for device_type in sorted({device["device_type"] for device in devices}):
                elements.append({"group": "nodes", "data": {
                    "id": f"type:{device_type}", "kind": "type",
                    "label": device_type, "name": device_type,
                }})
            for device in devices:
                elements.append({"group": "edges", "data": {
                    "id": f"type-member:{device['id']}",
                    "source": f"type:{device['device_type']}", "target": str(device["id"]),
                    "discovery_method": "INVENTORY_GROUP",
                }})

        counts = {}
        for device in devices:
            counts[device["device_type"]] = counts.get(device["device_type"], 0) + 1
        counts["TOTAL"] = len(devices)
        return {
            "site_id": site_id, "view": view, "elements": elements, "counts": counts,
            "available_subnets": sorted({network["cidr"] for network in networks}),
            "available_vlans": self.detail_repo.get_vlans(site_id),
            "unresolved_neighbors": self.detail_repo.get_unresolved(site_id),
            "physical_link_count": len(physical_links),
        }
