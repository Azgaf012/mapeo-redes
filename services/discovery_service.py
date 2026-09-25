"""Coordinate discovery and persist each observable fact."""

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config
from repositories.network_detail_repository import NetworkDetailRepository
from scanner.arp import get_arp_table
from scanner.classifier import classify_device
from scanner.enricher import (detect_os_info, evaluate_security_status,
                              format_open_ports_summary, query_netbios_details)
from scanner.fingerprint import fingerprint_device
from scanner.network import detect_network_config
from scanner.nmap_scanner import scan_host_services
from scanner.ping import ping_sweep
from scanner.snmp_inventory import collect_snmp_inventory
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
                 site_repo, detail_repo=None, max_hosts=None, host_workers=None):
        self.device_repo = device_repo
        self.network_repo = network_repo
        self.connection_repo = connection_repo
        self.scan_job_repo = scan_job_repo
        self.site_repo = site_repo
        self.detail_repo = detail_repo or NetworkDetailRepository(device_repo.db_path)
        self.max_hosts = max_hosts or Config.MAX_SCAN_HOSTS
        self.host_workers = host_workers or Config.SCAN_HOST_WORKERS

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
        try:
            hostname = socket.gethostbyaddr(ip)[0]
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
        ping = ping_details.get(ip, {})
        device_type, fp_host, fp_model = fingerprint_device(
            ip=ip, mac=mac, hostname=hostname, vendor=vendor, open_ports=open_ports,
            is_gateway=ip == gateway, is_local=ip == local_ip, snmp_info=snmp,
        )
        if device_type == "UNKNOWN":
            device_type = classify_device(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                open_ports=open_ports, is_gateway=ip == gateway, snmp_info=snmp,
            )
        hostname = fp_host or hostname
        payload = {
            "network_id": network_id, "ip": ip, "mac": mac, "hostname": hostname,
            "vendor": vendor, "model": snmp.get("model") or fp_model or (snmp.get("sys_descr") or "")[:80],
            "serial_number": snmp.get("serial_number") or "",
            "uptime_seconds": snmp.get("uptime_seconds"),
            "device_type": device_type, "latency_ms": ping.get("latency_ms"),
            "os_info": detect_os_info(ping.get("ttl", 0), open_ports, vendor,
                                      device_type, hostname),
            "open_ports_list": format_open_ports_summary(open_ports),
            "workgroup": workgroup or "", "security_status": evaluate_security_status(open_ports),
        }
        neighbors = [dict(neighbor, source_ip=ip) for neighbor in snmp.get("neighbors", [])]
        return payload, snmp, neighbors, warning

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
            ips = sorted(alive, key=ipaddress.IPv4Address)
            self.scan_job_repo.update_progress(
                job_id, 45, f"Analizando {len(ips)} equipos...", len(ips))

            neighbors = []
            snmp_devices = []
            warnings = []
            with ThreadPoolExecutor(max_workers=self.host_workers) as pool:
                futures = {pool.submit(self._inspect_host, ip, gateway, local_ip,
                                       local_mac, arp_table, sweep.details,
                                       credentials, network_id): ip for ip in ips}
                for done, future in enumerate(as_completed(futures), 1):
                    ip = futures[future]
                    try:
                        payload, inventory, found_neighbors, warning = future.result()
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
