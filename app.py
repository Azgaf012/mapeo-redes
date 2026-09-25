import ipaddress
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response
from config import Config
from database.connection import init_db
from repositories.site_repository import SiteRepository
from repositories.network_repository import NetworkRepository
from repositories.device_repository import DeviceRepository
from repositories.connection_repository import ConnectionRepository
from repositories.scan_job_repository import ScanJobRepository
from repositories.network_detail_repository import NetworkDetailRepository
from services.discovery_service import DiscoveryService, scan_size
from services.topology_service import TopologyService
from services.device_service import DeviceService
from services.site_service import SiteService
from scanner.network import detect_network_config

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite Database & default seeds
    init_db(app.config["DATABASE_PATH"])

    # Instantiate repositories
    site_repo = SiteRepository(app.config["DATABASE_PATH"])
    network_repo = NetworkRepository(app.config["DATABASE_PATH"])
    device_repo = DeviceRepository(app.config["DATABASE_PATH"])
    connection_repo = ConnectionRepository(app.config["DATABASE_PATH"])
    scan_job_repo = ScanJobRepository(app.config["DATABASE_PATH"])
    detail_repo = NetworkDetailRepository(app.config["DATABASE_PATH"])

    # Instantiate services
    discovery_service = DiscoveryService(
        device_repo=device_repo,
        network_repo=network_repo,
        connection_repo=connection_repo,
        scan_job_repo=scan_job_repo,
        site_repo=site_repo,
        detail_repo=detail_repo,
        max_hosts=app.config.get("MAX_SCAN_HOSTS", Config.MAX_SCAN_HOSTS),
        host_workers=app.config.get("SCAN_HOST_WORKERS", Config.SCAN_HOST_WORKERS)
    )
    topology_service = TopologyService(
        device_repo=device_repo,
        connection_repo=connection_repo,
        site_repo=site_repo,
        network_repo=network_repo,
        detail_repo=detail_repo
    )
    device_service = DeviceService(
        device_repo=device_repo,
        connection_repo=connection_repo,
        detail_repo=detail_repo
    )
    site_service = SiteService(
        site_repo=site_repo,
        device_repo=device_repo
    )

    # Context processor to inject sites into all templates
    @app.context_processor
    def inject_global_data():
        sites = site_service.list_sites()
        return dict(all_sites=sites)

    def active_site_id():
        sites = site_service.list_sites()
        return sites[0]["id"] if sites else None

    # -------------------------------------------------------------
    # WEB ROUTES
    # -------------------------------------------------------------

    @app.route("/")
    def index():
        sites = site_service.list_sites()
        selected_site_id = active_site_id()
        
        network_info = detect_network_config()
        stats = device_repo.count_by_type(selected_site_id)
        latest_job = scan_job_repo.get_latest_by_site(selected_site_id) if selected_site_id else None

        devices = device_repo.get_all(site_id=selected_site_id)
        online_devices = [d for d in devices if d["status"] == "ONLINE"]
        active_latencies = [d["latency_ms"] for d in online_devices if d.get("latency_ms")]
        avg_latency = round(sum(active_latencies) / len(active_latencies), 1) if active_latencies else None

        network = ipaddress.IPv4Network(network_info["cidr"], strict=False)
        total_ips = max(network.num_addresses - (2 if network.prefixlen < 31 else 0), 0)
        used_ips = 0
        for device in online_devices:
            try:
                used_ips += ipaddress.IPv4Address(device["ip"]) in network
            except ValueError:
                pass
        utilization_pct = round(used_ips / total_ips * 100, 1) if total_ips else 0

        return render_template(
            "index.html",
            sites=sites,
            selected_site_id=selected_site_id,
            network_info=network_info,
            stats=stats,
            known_networks=network_repo.get_by_site(selected_site_id) if selected_site_id else [],
            latest_job=latest_job,
            avg_latency=avg_latency,
            used_ips=used_ips,
            total_ips=total_ips,
            utilization_pct=utilization_pct,
            online_count=len(online_devices),
            offline_count=len(devices) - len(online_devices),
            unresolved_count=len(detail_repo.get_unresolved(selected_site_id)) if selected_site_id else 0,
            link_count=len(detail_repo.get_links(selected_site_id)) if selected_site_id else 0,
            max_scan_hosts=app.config.get("MAX_SCAN_HOSTS", Config.MAX_SCAN_HOSTS)
        )

    @app.route("/topology")
    def topology():
        sites = site_service.list_sites()
        selected_site_id = active_site_id()
            
        stats = device_repo.count_by_type(selected_site_id)
        return render_template(
            "topology.html",
            sites=sites,
            selected_site_id=selected_site_id,
            stats=stats
        )

    @app.route("/devices")
    def devices():
        sites = site_service.list_sites()
        selected_site_id = active_site_id()
        device_type = request.args.get("type", "").strip() or None
        search = request.args.get("q", "").strip() or None
        status_filter = request.args.get("status", "ONLINE").upper()
        if status_filter not in ("ONLINE", "ALL"):
            status_filter = "ONLINE"

        device_list = device_service.list_devices(
            site_id=selected_site_id,
            device_type=device_type,
            search=search,
            status=None if status_filter == "ALL" else status_filter
        )
        subnet_filter = request.args.get("cidr", "").strip()
        vlan_filter = request.args.get("vlan", type=int)
        if subnet_filter:
            try:
                selected_network = ipaddress.IPv4Network(subnet_filter, strict=False)
                device_list = [d for d in device_list
                               if ipaddress.IPv4Address(d["ip"]) in selected_network]
            except ValueError:
                subnet_filter = ""
        if vlan_filter is not None:
            memberships = detail_repo.get_device_vlans(selected_site_id)
            device_list = [d for d in device_list if vlan_filter in memberships.get(d["id"], set())]
        counts = device_repo.count_by_type(selected_site_id)

        return render_template(
            "devices.html",
            sites=sites,
            selected_site_id=selected_site_id,
            devices=device_list,
            device_type=device_type,
            search=search,
            counts=counts,
            status_filter=status_filter,
            subnet_filter=subnet_filter,
            vlan_filter=vlan_filter,
            available_subnets=network_repo.get_by_site(selected_site_id),
            available_vlans=detail_repo.get_vlans(selected_site_id)
        )

    @app.route("/devices/<int:device_id>", methods=["GET", "POST"])
    def device_detail(device_id):
        if request.method == "POST":
            success = device_service.update_manual_info(device_id, request.form)
            if success:
                flash("Información del dispositivo actualizada correctamente.", "success")
            else:
                flash("Error al actualizar el dispositivo.", "danger")
            return redirect(url_for("device_detail", device_id=device_id))

        detail = device_service.get_device_detail(device_id)
        if not detail:
            flash("Dispositivo no encontrado.", "warning")
            return redirect(url_for("devices"))

        # Fetch other devices in same site to allow manual connection
        site_id = detail["device"]["site_id"]
        other_devices = [d for d in device_repo.get_all(site_id=site_id) if d["id"] != device_id]

        return render_template(
            "device_detail.html",
            device=detail["device"],
            connections=detail["connections"],
            other_devices=other_devices,
            interfaces=detail_repo.get_interfaces(device_id),
            mac_learnings=detail_repo.get_mac_learnings(device_id),
            physical_links=[link for link in detail_repo.get_links(site_id)
                            if device_id in (link["source_device_id"], link["target_device_id"])],
            unresolved_neighbors=[neighbor for neighbor in detail_repo.get_unresolved(site_id)
                                  if neighbor["source_device_id"] == device_id],
        )

    @app.route("/devices/<int:device_id>/delete", methods=["POST"])
    def delete_device(device_id):
        device = device_repo.get_by_id(device_id)
        site_id = device["site_id"] if device else None
        device_repo.delete(device_id)
        flash("Dispositivo eliminado del inventario.", "info")
        return redirect(url_for("devices", site_id=site_id))

    @app.route("/devices/export")
    def export_devices():
        site_id = active_site_id()
        csv_data = device_service.export_csv(site_id=site_id)
        filename = f"inventario_red_sede_{site_id if site_id else 'todas'}.csv"
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    @app.route("/sites", methods=["GET", "POST"])
    def sites():
        return redirect(url_for("index"))

    @app.route("/sites/<int:site_id>/delete", methods=["POST"])
    def delete_site(site_id):
        site = site_repo.get_by_id(site_id)
        if site:
            site_service.delete_site(site_id)
            flash(f"Sede '{site['name']}' y sus dispositivos fueron eliminados.", "info")
        return redirect(url_for("sites"))

    # -------------------------------------------------------------
    # REST API ENDPOINTS
    # -------------------------------------------------------------

    @app.route("/api/network/detect")
    def api_detect_network():
        return jsonify(detect_network_config())

    @app.route("/api/scan/estimate")
    def api_scan_estimate():
        cidr = request.args.get("cidr") or detect_network_config()["cidr"]
        try:
            network, count = scan_size(cidr, app.config.get("MAX_SCAN_HOSTS", Config.MAX_SCAN_HOSTS))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"cidr": str(network), "host_count": count,
                        "estimated_minutes": round(count / 64 * 0.15 + 1, 1)})

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        data = request.get_json() or {}
        site_id = active_site_id()
        if not site_id:
            return jsonify({"error": "Debe especificar un site_id"}), 400

        custom_cidr = data.get("cidr")
        custom_gateway = data.get("gateway")
        credentials = {"version": data.get("snmp_version", "2c"),
                       "community": data.get("snmp_community", "public"),
                       "username": data.get("snmp_username", ""),
                       "auth_key": data.get("snmp_auth_key", ""),
                       "priv_key": data.get("snmp_priv_key", ""),
                       "auth_protocol": data.get("snmp_auth_protocol", "SHA256")}
        if credentials["version"] not in ("2c", "3"):
            return jsonify({"error": "Versión SNMP no válida."}), 400
        if credentials["version"] == "3" and not credentials["username"]:
            return jsonify({"error": "SNMPv3 requiere nombre de usuario."}), 400
        if credentials["version"] == "3":
            for key in ("auth_key", "priv_key"):
                value = credentials[key]
                if value and not 8 <= len(value) <= 32:
                    return jsonify({"error": "Las claves SNMPv3 deben tener entre 8 y 32 caracteres."}), 400
            if credentials["priv_key"] and not credentials["auth_key"]:
                return jsonify({"error": "SNMPv3 con clave AES requiere autenticación."}), 400
        try:
            job_id = discovery_service.start_scan_async(
                site_id=site_id, custom_cidr=custom_cidr,
                custom_gateway=custom_gateway, snmp_credentials=credentials)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"job_id": job_id, "status": "RUNNING"})

    @app.route("/api/scan/status/<int:job_id>")
    def api_scan_status(job_id):
        job = scan_job_repo.get_by_id(job_id)
        if not job:
            return jsonify({"error": "Trabajo de escaneo no encontrado"}), 404
        return jsonify(job)

    @app.route("/api/topology/data")
    def api_topology_data():
        site_id = active_site_id()
        cidr = request.args.get("cidr")
        if not site_id:
            return jsonify({"elements": [], "counts": {}, "available_subnets": []})

        try:
            vlan = request.args.get("vlan", type=int)
            data = topology_service.get_cytoscape_data(
                site_id, network_cidr=cidr, view=request.args.get("view", "physical"),
                status=request.args.get("status", "ONLINE"), vlan=vlan,
                method=request.args.get("method"), search=request.args.get("q"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(data)

    @app.route("/api/sites/<int:site_id>/clear-devices", methods=["POST"])
    def api_clear_site_devices(site_id):
        device_repo.clear_all_for_site(site_id)
        return jsonify({"success": True})

    @app.route("/api/connections/create", methods=["POST"])
    def api_create_connection():
        data = request.get_json() or {}
        site_id = data.get("site_id")
        source_id = data.get("source_id")
        target_id = data.get("target_id")
        conn_type = data.get("connection_type", "ETHERNET")

        if not site_id or not source_id or not target_id:
            return jsonify({"error": "Parámetros incompletos"}), 400

        conn_id = connection_repo.create_or_update(
            site_id=int(site_id),
            source_id=int(source_id),
            target_id=int(target_id),
            connection_type=conn_type,
            discovery_method="MANUAL",
            confidence="HIGH"
        )
        return jsonify({"success": True, "connection_id": conn_id})

    @app.route("/api/connections/<int:conn_id>/delete", methods=["POST"])
    def api_delete_connection(conn_id):
        connection_repo.delete(conn_id)
        return jsonify({"success": True})

    return app

if __name__ == "__main__":
    app = create_app()
    port = Config.DEFAULT_PORT
    print(f"\n=======================================================")
    print(f"🚀 Iniciando Sistema de Mapeo de Red Escolar")
    print(f"🌐 Servidor Web disponible en: http://localhost:{port}")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
