import csv
import io
import json
from datetime import datetime, timedelta, timezone

class DeviceService:
    def __init__(self, device_repo, connection_repo, detail_repo=None, ap_association_repo=None):
        self.device_repo = device_repo
        self.connection_repo = connection_repo
        self.detail_repo = detail_repo
        self.ap_association_repo = ap_association_repo

    def list_devices(self, site_id=None, device_type=None, search=None, status=None):
        return self.device_repo.get_all(site_id=site_id, device_type=device_type, search=search, status=status)

    def get_device_detail(self, device_id):
        device = self.device_repo.get_by_id(device_id)
        if not device:
            return None
        
        # Get all connections involving this device
        all_conns = self.connection_repo.get_by_site(device["site_id"])
        device_conns = []
        for c in all_conns:
            if c["source_device_id"] == device_id:
                device_conns.append({
                    "id": c["id"],
                    "peer_id": c["target_device_id"],
                    "peer_ip": c["target_ip"],
                    "peer_name": c["target_hostname"] or c["target_ip"],
                    "peer_type": c["target_type"],
                    "relation": "Conectado hacia",
                    "type": c["connection_type"],
                    "method": c["discovery_method"],
                    "confidence": c["confidence"]
                })
            elif c["target_device_id"] == device_id:
                device_conns.append({
                    "id": c["id"],
                    "peer_id": c["source_device_id"],
                    "peer_ip": c["source_ip"],
                    "peer_name": c["source_hostname"] or c["source_ip"],
                    "peer_type": c["source_type"],
                    "relation": "Conectado desde",
                    "type": c["connection_type"],
                    "method": c["discovery_method"],
                    "confidence": c["confidence"]
                })

        return {
            "device": device,
            "connections": device_conns
        }

    def update_manual_info(self, device_id, form_data):
        fields = {
            "hostname": form_data.get("hostname", "").strip(),
            "device_type": form_data.get("device_type", "").strip(),
            "vendor": form_data.get("vendor", "").strip(),
            "model": form_data.get("model", "").strip(),
            "serial_number": form_data.get("serial_number", "").strip(),
            "location": form_data.get("location", "").strip(),
            "rack": form_data.get("rack", "").strip(),
            "floor": form_data.get("floor", "").strip(),
            "description": form_data.get("description", "").strip(),
        }
        return self.device_repo.update_manual_fields(device_id, fields)

    def export_csv(self, site_id=None):
        devices = self.device_repo.get_all(site_id=site_id)
        vlan_by_device = self.detail_repo.get_device_vlans(site_id) if self.detail_repo and site_id else {}
        devices_by_id = {device["id"]: device for device in devices}
        ap_by_mac = {}
        if self.ap_association_repo and site_id:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
            for association in self.ap_association_repo.get_by_site(site_id):
                try:
                    observed = datetime.fromisoformat(association["observed_at"])
                    if observed.tzinfo:
                        observed = observed.astimezone(timezone.utc).replace(tzinfo=None)
                except (TypeError, ValueError):
                    continue
                ap = devices_by_id.get(association["ap_device_id"])
                if observed >= cutoff and ap and ap["device_type"] == "ACCESS_POINT":
                    ap_by_mac[association["client_mac"]] = (ap, association["observed_at"])
        output = io.StringIO()
        writer = csv.writer(output, delimiter=",")
        
        # Headers
        writer.writerow([
            "ID", "Sede", "Subred", "VLAN", "IP", "MAC", "Hostname", "Tipo", "Fabricante", 
            "Modelo", "Sistema Operativo", "Latencia (ms)", "Seguridad",
            "Grupo de Trabajo", "Serial", "Estado", "Ubicación", "Rack", "Piso", 
            "Modo Manual", "Última Conexión", "Descripción",
            "Puertos TCP abiertos", "Tipo detectado", "Origen detección",
            "DNS inverso", "Nombre NetBIOS", "TTL ICMP", "Estado SNMP",
            "SNMP sysName", "SNMP sysDescr", "SNMP modelo",
            "Interfaces SNMP", "Vecinos SNMP", "Título web", "Puerto web",
            "Advertencia SNMP", "Sondeos web (JSON)", "Modelo detectado",
            "SNMP sysObjectID", "Vecinos LLDP (JSON)", "Identidad vecino (JSON)",
            "AP asociado", "Fuente AP", "Importado AP"
        ])
        
        for d in devices:
            normalized_mac = "".join(char for char in (d.get("mac") or "").upper()
                                     if char in "0123456789ABCDEF")
            ap_match = ap_by_mac.get(normalized_mac)
            try:
                evidence = json.loads(d.get("scan_evidence") or "{}")
                if not isinstance(evidence, dict):
                    evidence = {}
            except (TypeError, ValueError):
                evidence = {}
            try:
                ports = json.loads(d.get("open_ports_list") or "[]")
                port_numbers = ";".join(str(item["port"]) for item in ports
                                        if isinstance(item, dict) and "port" in item)
            except (TypeError, ValueError):
                port_numbers = ""
            writer.writerow([
                d["id"],
                d.get("site_name", ""),
                d.get("network_cidr") or "",
                ";".join(str(v) for v in sorted(vlan_by_device.get(d["id"], set()))),
                d["ip"],
                d["mac"] or "",
                d["hostname"] or "",
                d["device_type"],
                d["vendor"] or "",
                d["model"] or "",
                d.get("os_info") or "",
                d.get("latency_ms") or 0.0,
                d.get("security_status") or "SECURE",
                d.get("workgroup") or "",
                d["serial_number"] or "",
                d["status"],
                d["location"] or "",
                d["rack"] or "",
                d["floor"] or "",
                "Sí" if d["is_manual"] else "No",
                d["last_seen"] or "",
                d["description"] or "",
                port_numbers,
                evidence.get("detected_type", ""),
                evidence.get("classification_source", ""),
                evidence.get("dns_name", ""),
                evidence.get("netbios_name", ""),
                evidence.get("icmp_ttl", ""),
                evidence.get("snmp_status", ""),
                evidence.get("snmp_sys_name", ""),
                evidence.get("snmp_sys_descr", ""),
                evidence.get("snmp_model", ""),
                evidence.get("snmp_interface_count", ""),
                evidence.get("snmp_neighbor_count", ""),
                evidence.get("web_title", ""),
                evidence.get("web_port", ""),
                evidence.get("snmp_warning", ""),
                json.dumps(evidence["web_probes"], ensure_ascii=False)
                if "web_probes" in evidence else "",
                evidence.get("detected_model", ""),
                evidence.get("snmp_sys_object_id", ""),
                json.dumps(evidence["snmp_neighbors"], ensure_ascii=False)
                if "snmp_neighbors" in evidence else "",
                json.dumps(evidence["neighbor_identity"], ensure_ascii=False)
                if "neighbor_identity" in evidence else "",
                (ap_match[0]["hostname"] or ap_match[0]["ip"]) if ap_match else "",
                "CSV cliente-AP" if ap_match else "",
                ap_match[1] if ap_match else "",
            ])
            
        output.seek(0)
        return output.getvalue()
