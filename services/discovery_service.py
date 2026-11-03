"""Coordinate discovery and persist each observable fact."""

import ipaddress
import json
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config
from repositories.network_detail_repository import NetworkDetailRepository
from repositories.ap_association_repository import ApAssociationRepository
from services.ap_association_service import ApAssociationService
from scanner.arp import get_arp_table
from scanner.diagnostics import read_dhcp_leases
from scanner.classifier import (
    classify_device, classify_lldp_neighbor, is_client_endpoint_type
)
from scanner.drivers.base import HostFacts
from scanner.drivers.hostnames import classify_hostname
from scanner.enricher import (detect_os_info, evaluate_security_status,
                              format_open_ports_summary, query_netbios_details)
from scanner.fingerprint import fingerprint_device
from scanner.network import detect_network_config
from scanner.nmap_scanner import identify_open_services, scan_host_services
from scanner.ping import ping_sweep
from scanner.snmp_inventory import collect_gateway_neighbors, collect_snmp_inventory
from scanner.topology import resolve_neighbor
from scanner.vendor import lookup_vendor


def scan_size(cidr, max_hosts=Config.MAX_SCAN_HOSTS):
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError("El rango CIDR no es válido.") from exc
    size = max(network.num_addresses - (2 if network.prefixlen < 31 else 0), 0)
    if size > max_hosts:
        raise ValueError(f"El rango contiene {size} IP; el límite configurado es {max_hosts}.")
    return network, size


class DiscoveryService:
    def __init__(self, device_repo, network_repo, connection_repo, scan_job_repo,
                 site_repo, detail_repo=None, max_hosts=None, host_workers=None,
                 identity_service=None):
        self.device_repo = device_repo
        self.network_repo = network_repo
        self.connection_repo = connection_repo
        self.scan_job_repo = scan_job_repo
        self.site_repo = site_repo
        self.detail_repo = detail_repo or NetworkDetailRepository(device_repo.db_path)
        self.ap_association_service = (ApAssociationService(
            device_repo, ApAssociationRepository(device_repo.db_path)) if device_repo else None)
        self.max_hosts = max_hosts or Config.MAX_SCAN_HOSTS
        self.host_workers = host_workers or Config.SCAN_HOST_WORKERS
        self.identity = identity_service  # built by create_app; None disables it

    def start_scan_async(self, site_id, custom_cidr=None, custom_gateway=None,
                         snmp_community="public", clean_previous_subnets=False,
                         snmp_credentials=None):
        detected = detect_network_config()
        cidr = (custom_cidr or detected["cidr"]).strip()
        network, _ = scan_size(cidr, self.max_hosts)
        gateway = (custom_gateway or detected["gateway"] or "").strip()
        if gateway:
            try:
                gateway_ip = ipaddress.IPv4Address(gateway)
            except ValueError as exc:
                raise ValueError("El gateway no es una dirección IPv4 válida.") from exc
            if gateway_ip not in network:
                raise ValueError("El gateway debe pertenecer al rango CIDR seleccionado.")
        if not self.site_repo.get_by_id(site_id):
            raise ValueError("La sede seleccionada no existe.")

        credentials = snmp_credentials or {"version": "2c", "community": snmp_community}
        job_id = self.scan_job_repo.create(site_id, str(network))
        thread = threading.Thread(
            target=self._run_scan_pipeline,
            args=(job_id, site_id, str(network), gateway, detected["local_ip"],
                  detected.get("local_mac", ""), credentials),
            daemon=True,
        )
        thread.start()
        return job_id

    def _inspect_host(self, ip, gateway, local_ip, local_mac, arp_table,
                      ping_details, credentials, network_id):
        mac = arp_table.get(ip, "") or (local_mac if ip == local_ip else "")
        vendor = lookup_vendor(mac) if mac else "Desconocido"
        dns_name = ""
        try:
            dns_name = socket.gethostbyaddr(ip)[0]
            hostname = dns_name
        except (OSError, socket.herror):
            hostname = socket.gethostname() if ip == local_ip else ""
        nb_name, workgroup = query_netbios_details(ip)
        hostname = hostname or nb_name or ""
        open_ports = scan_host_services(ip)
        snmp = {"has_snmp": False}
        warning = None
        try:
            snmp = collect_snmp_inventory(ip, credentials)
        except Exception as exc:
            warning = f"SNMP {ip}: {exc.__class__.__name__}"
        if snmp.get("sys_name") and not hostname:
            hostname = snmp["sys_name"]
        observed_hostname = hostname
        ping = ping_details.get(ip, {})
        web_evidence = {}
        device_type, fp_host, fp_model = fingerprint_device(
            ip=ip, mac=mac, hostname=hostname, vendor=vendor, open_ports=open_ports,
            is_gateway=ip == gateway, is_local=ip == local_ip, snmp_info=snmp,
            diagnostics=web_evidence,
        )
        classification_source = "fingerprint" if device_type != "UNKNOWN" else "unidentified"
        if device_type == "UNKNOWN":
            device_type = classify_device(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                open_ports=open_ports, is_gateway=ip == gateway, snmp_info=snmp,
            )
            if device_type != "UNKNOWN":
                classification_source = "classifier"
        hostname = fp_host or hostname
        detected_model = snmp.get("model") or fp_model or (snmp.get("sys_descr") or "")[:80]
        serial_number = snmp.get("serial_number") or ""
        identity_evidence = {}
        if self.identity:
            facts = HostFacts(
                ip=ip, mac=mac, vendor=vendor, hostname=hostname, open_ports=open_ports,
                ttl=ping.get("ttl"), snmp=snmp, web=web_evidence, base_type=device_type,
                base_source=classification_source, is_gateway=ip == gateway,
                credentials=credentials)
            identity = self.identity.identify(facts, detected_model)
            if identity.device_type != "UNKNOWN":
                if identity.device_type != device_type:
                    classification_source = identity.source
                device_type = identity.device_type
                if identity.model and (not detected_model or identity.model_weight >= 80):
                    detected_model = identity.model
                if identity.vendor and (vendor in ("", "Desconocido") or identity.vendor_weight >= 85):
                    vendor = identity.vendor
            serial_number = serial_number or identity.serial
            hostname = hostname or identity.hostname
            identity_evidence = {
                "identity_score": identity.score, "identity_confidence": identity.confidence,
                "identity_sources": identity.sources, "identity_evidence": identity.evidence,
                "identity_firmware": identity.firmware,
            }
        # Only identify equipment up to APs and fixed infrastructure; do not promote client endpoints.
        if is_client_endpoint_type(device_type):
            device_type = "UNKNOWN"
            classification_source = "excluded_client_endpoint"
            hostname = observed_hostname
            detected_model = snmp.get("model") or ""
            if identity_evidence:
                identity_evidence["identity_confidence"] = "none"
        evidence = {
            "services": identify_open_services(ip, open_ports)
            if device_type == "UNKNOWN" and classification_source != "excluded_client_endpoint" else [],
            "detected_type": device_type,
            "detected_model": detected_model,
            "classification_source": classification_source,
            "dns_name": dns_name,
            "netbios_name": nb_name or "",
            "icmp_ttl": ping.get("ttl"),
            "snmp_status": "error" if warning else ("available" if snmp.get("has_snmp") else "no_response"),
            "snmp_sys_name": snmp.get("sys_name") or "",
            "snmp_sys_descr": (snmp.get("sys_descr") or "")[:500],
            "snmp_sys_object_id": snmp.get("sys_object_id") or "",
            "snmp_model": snmp.get("model") or "",
            "snmp_interface_count": len(snmp.get("interfaces") or []),
            "snmp_neighbor_count": len(snmp.get("neighbors") or []),
            "snmp_neighbors": (snmp.get("neighbors") or [])[:256],
            "snmp_warning": warning or "",
            **identity_evidence,
            **web_evidence,
        }
        payload = {
            "network_id": network_id, "ip": ip, "mac": mac, "hostname": hostname,
            "vendor": vendor, "model": detected_model,
            "serial_number": serial_number,
            "uptime_seconds": snmp.get("uptime_seconds"),
            "device_type": device_type, "latency_ms": ping.get("latency_ms"),
            "os_info": detect_os_info(ping.get("ttl", 0), open_ports, vendor,
                                      device_type, hostname),
            "open_ports_list": format_open_ports_summary(open_ports),
            "scan_evidence": json.dumps(evidence, ensure_ascii=False),
            "workgroup": workgroup or "", "security_status": evaluate_security_status(open_ports),
        }
        neighbors = [dict(neighbor, source_ip=ip) for neighbor in snmp.get("neighbors", [])]
        return payload, snmp, neighbors, warning

    def _enrich_neighbor_identities(self, site_id, neighbors, devices):
        """Upgrade unknown or matching infrastructure devices when an LLDP/CDP neighbor resolves uniquely."""
        candidates = {}
        for neighbor in neighbors:
            target = resolve_neighbor(neighbor, devices)
            if not target or target["ip"] == neighbor.get("source_ip"):
                continue
            device_type = classify_lldp_neighbor(neighbor)
            if device_type == "UNKNOWN" or is_client_endpoint_type(device_type):
                continue
            candidates.setdefault(target["id"], []).append((device_type, neighbor))
        updated = 0
        for device_id, observations in candidates.items():
            if len({device_type for device_type, _ in observations}) != 1:
                continue
            observations.sort(key=lambda item: (
                0 if item[1].get("protocol", "LLDP") == "LLDP" else 1,
                0 if item[1].get("description") else 1,
            ))
            device_type, neighbor = observations[0]
            if self.device_repo.apply_observed_identity(device_id, device_type, neighbor):
                updated += 1
        return updated

    def reconcile_stored_neighbors(self, site_id):
        """Re-apply stored SNMP LLDP/CDP neighbor tables to enrich infrastructure identities and links."""
        devices = self.device_repo.get_all(site_id=site_id)
        active_devices = [device for device in devices if device["status"] == "ONLINE"]
        stored_neighbors = []
        snmp_sources = []
        for device in active_devices:
            try:
                evidence = json.loads(device.get("scan_evidence") or "{}")
            except (TypeError, ValueError):
                evidence = {}
            if not isinstance(evidence, dict):
                continue
            raw_neighbors = evidence.get("snmp_neighbors") or []
            if not raw_neighbors:
                continue
            snmp_sources.append(device["ip"])
            for neighbor in raw_neighbors:
                if isinstance(neighbor, dict):
                    stored_neighbors.append(dict(neighbor, source_ip=device["ip"]))
        if not stored_neighbors:
            return 0
        updated = self._enrich_neighbor_identities(site_id, stored_neighbors, active_devices)
        devices = self.device_repo.get_all(site_id=site_id)
        by_ip = {device["ip"]: device for device in devices}
        active_devices = [device for device in devices if device["status"] == "ONLINE"]
        if self.detail_repo:
            for source_ip in snmp_sources:
                if source_ip in by_ip:
                    self.detail_repo.save_neighbors(
                        site_id, by_ip[source_ip],
                        [n for n in stored_neighbors if n.get("source_ip") == source_ip],
                        active_devices,
                    )
        return updated

    def _apply_controller_data(self, site_id):
        """Use what a wireless controller published about its APs."""
        for peer in self.identity.peers:
            if peer.get("source") == "nvr":
                self._save_nvr_camera(site_id, peer)
                continue
            device = self.device_repo.get_by_ip(site_id, peer.get("ip") or "")
            if device:
                self.device_repo.confirm_access_point(device["id"], "aruba_instant")

    def import_nvr_cameras(self, site_id, peers):
        for peer in peers:
            self._save_nvr_camera(site_id, peer)
        return len(peers)

    def _save_nvr_camera(self, site_id, peer):
        """Cameras behind an NVR's PoE switch are unreachable; store what the NVR reports."""
        evidence = {"classification_source": "nvr", "detected_type": "CAMERA",
                    "nvr_ip": peer.get("nvr_ip", ""), "nvr_channel": peer.get("channel", "")}
        device_id = self.device_repo.upsert_discovered(site_id, {
            "ip": peer["ip"], "mac": peer.get("mac") or "", "hostname": peer.get("hostname", ""),
            "vendor": "Hikvision", "model": peer.get("model", ""),
            "serial_number": peer.get("serial", ""), "device_type": "CAMERA",
            "os_info": "", "scan_evidence": json.dumps(evidence, ensure_ascii=False),
            "description": f"Canal {peer.get('channel', '?')} del NVR {peer.get('nvr_ip', '')}",
        })
        if device_id and peer.get("online") is False:
            self.device_repo.set_status(device_id, "OFFLINE")

    def _run_scan_pipeline(self, job_id, site_id, cidr, gateway, local_ip,
                           local_mac, credentials):
        try:
            self.scan_job_repo.update_progress(job_id, 10, f"Preparando {cidr}...")
            network_id = self.network_repo.get_or_create(site_id, cidr, gateway=gateway)

            def sweep_progress(done, total):
                if done % 100 == 0 or done == total:
                    percent = 10 + round(30 * done / max(total, 1))
                    self.scan_job_repo.update_progress(
                        job_id, percent, f"Buscando equipos: {done}/{total} IP")

            sweep = ping_sweep(cidr, progress_callback=sweep_progress)
            alive = set(sweep)
            network = ipaddress.IPv4Network(cidr, strict=False)
            if local_ip and ipaddress.IPv4Address(local_ip) in network:
                alive.add(local_ip)
            self.device_repo.mark_offline_or_cleanup(site_id, alive, cidr=cidr)
            arp_table = get_arp_table()
            warnings = []
            gateway_neighbors = {}
            if gateway:
                try:
                    gateway_neighbors = collect_gateway_neighbors(gateway, credentials)
                except Exception as exc:
                    warnings.append(f"Vecinos del gateway: {type(exc).__name__}")
            local_neighbors = dict(arp_table)
            arp_table = {**gateway_neighbors, **{ip: mac for ip, mac in arp_table.items() if mac}}
            try:
                leases = read_dhcp_leases(network.network_address)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                leases = {}
                warnings.append(f"Concesiones DHCP: {type(exc).__name__}")
            ips = sorted(alive, key=ipaddress.IPv4Address)
            if self.identity:
                self.scan_job_repo.update_progress(job_id, 44, "Descubriendo fabricantes...")
                self.identity.begin_scan(local_ip)
            self.scan_job_repo.update_progress(
                job_id, 45, f"Analizando {len(ips)} equipos...", len(ips))

            neighbors = []
            snmp_devices = []
            with ThreadPoolExecutor(max_workers=self.host_workers) as pool:
                futures = {pool.submit(self._inspect_host, ip, gateway, local_ip,
                                       local_mac, arp_table, sweep.details,
                                       credentials, network_id): ip for ip in ips}
                for done, future in enumerate(as_completed(futures), 1):
                    ip = futures[future]
                    try:
                        payload, inventory, found_neighbors, warning = future.result()
                        evidence = json.loads(payload.get("scan_evidence") or "{}")
                        if gateway_neighbors.get(ip) and not local_neighbors.get(ip) and ip != local_ip:
                            evidence["mac_source"] = "Tabla de vecinos SNMP del gateway"
                        if ip in leases:
                            evidence["dhcp_lease"] = leases[ip]
                        payload["scan_evidence"] = json.dumps(evidence, ensure_ascii=False)
                        device_id = self.device_repo.upsert_discovered(site_id, payload)
                        if inventory.get("has_snmp"):
                            self.detail_repo.save_inventory(site_id, device_id, inventory)
                            snmp_devices.append(ip)
                        neighbors.extend(found_neighbors)
                        if warning:
                            warnings.append(warning)
                    except Exception as exc:
                        warnings.append(f"{ip}: {exc.__class__.__name__}: {exc}")
                    if done % 5 == 0 or done == len(ips):
                        percent = 45 + round(43 * done / max(len(ips), 1))
                        self.scan_job_repo.update_progress(
                            job_id, percent, f"Analizando equipos: {done}/{len(ips)}",
                            len(ips))

            self.scan_job_repo.update_progress(job_id, 90, "Resolviendo vecinos y puertos...")
            if self.identity:
                self._apply_controller_data(site_id)
                self.identity.finish_scan()
            self.ap_association_service.refresh_recent_aps(site_id)
            devices = self.device_repo.get_all(site_id=site_id)
            active_devices = [device for device in devices if device["status"] == "ONLINE"]
            self._enrich_neighbor_identities(site_id, neighbors, active_devices)
            devices = self.device_repo.get_all(site_id=site_id)
            by_ip = {device["ip"]: device for device in devices}
            active_devices = [device for device in devices if device["status"] == "ONLINE"]
            for source_ip in snmp_devices:
                self.detail_repo.save_neighbors(
                    site_id, by_ip[source_ip],
                    [neighbor for neighbor in neighbors if neighbor["source_ip"] == source_ip],
                    active_devices,
                )
            self.connection_repo.clear_discovered_for_site(site_id)
            self.scan_job_repo.complete(job_id, len(ips), "; ".join(warnings[:20]))
        except Exception as exc:
            self.scan_job_repo.fail(job_id, str(exc))
