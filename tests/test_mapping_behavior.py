import os
import tempfile
import sqlite3
import json
from contextlib import closing
from types import SimpleNamespace

import pytest

from database.connection import init_db
from repositories.connection_repository import ConnectionRepository
from repositories.device_repository import DeviceRepository
from repositories.network_repository import NetworkRepository
from repositories.network_detail_repository import NetworkDetailRepository
from repositories.site_repository import SiteRepository
from repositories.scan_job_repository import ScanJobRepository
from scanner.ping import ping_sweep
from scanner.topology import build_topology
from scanner.snmp_inventory import build_inventory
from services.discovery_service import DiscoveryService, scan_size
from services.topology_service import TopologyService


@pytest.fixture
def mapping_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    os.remove(path)


def test_absent_devices_are_retained_and_can_be_filtered(mapping_db):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    devices = DeviceRepository(mapping_db)
    kept = devices.upsert_discovered(site_id, {"ip": "10.0.0.2", "device_type": "SWITCH"})
    missing = devices.upsert_discovered(site_id, {"ip": "10.0.0.3", "device_type": "PC"})

    devices.mark_offline_or_cleanup(site_id, {"10.0.0.2"}, cidr="10.0.0.0/24")

    assert devices.get_by_id(missing)["status"] == "OFFLINE"
    assert [d["id"] for d in devices.get_all(site_id=site_id, status="ONLINE")] == [kept]


def test_large_sweep_is_not_silently_truncated(monkeypatch):
    import scanner.ping as ping

    seen = []
    monkeypatch.setattr(ping, "ping_host_icmp", lambda ip, timeout_ms: seen.append(ip) or ping.PingResult())
    monkeypatch.setattr(ping, "get_arp_table", lambda: {})
    ping_sweep("10.0.0.0/22", max_workers=8)
    assert len(seen) == 1022


def test_unconfirmed_topology_has_no_physical_links(mapping_db):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    devices = DeviceRepository(mapping_db)
    connections = ConnectionRepository(mapping_db)
    devices.upsert_discovered(site_id, {"ip": "10.0.0.1", "device_type": "ROUTER"})
    devices.upsert_discovered(site_id, {"ip": "10.0.0.2", "device_type": "SWITCH"})
    build_topology(site_id, devices.get_all(site_id=site_id), connections, gateway_ip="10.0.0.1")
    assert connections.get_by_site(site_id) == []


def test_logical_view_groups_by_registered_network(mapping_db):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    network_id = NetworkRepository(mapping_db).get_or_create(site_id, "10.2.0.0/23")
    devices = DeviceRepository(mapping_db)
    devices.upsert_discovered(site_id, {"network_id": network_id, "ip": "10.2.1.5"})
    service = TopologyService(devices, ConnectionRepository(mapping_db), SiteRepository(mapping_db), NetworkRepository(mapping_db))

    data = service.get_cytoscape_data(site_id, view="logical")

    assert "10.2.0.0/23" in data["available_subnets"]
    assert any(e["data"].get("kind") == "network" for e in data["elements"])


def test_logical_view_routes_pc_through_configured_gateway(mapping_db, monkeypatch):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    networks = NetworkRepository(mapping_db)
    network_id = networks.get_or_create(site_id, "192.168.18.0/24", gateway="192.168.18.1")
    devices = DeviceRepository(mapping_db)
    gateway_id = devices.upsert_discovered(site_id, {
        "network_id": network_id, "ip": "192.168.18.1", "device_type": "ROUTER"})
    pc_id = devices.upsert_discovered(site_id, {
        "network_id": network_id, "ip": "192.168.18.3", "device_type": "LAPTOP"})
    monkeypatch.setattr("services.topology_service.get_routing_ip", lambda: "192.168.18.3")
    monkeypatch.setattr("services.topology_service.get_local_connection_medium",
                        lambda ip: ("WIFI", "Adaptador Wi-Fi local"))
    service = TopologyService(devices, ConnectionRepository(mapping_db),
                              SiteRepository(mapping_db), networks)

    data = service.get_cytoscape_data(site_id, view="logical")
    edges = {element["data"]["id"]: element["data"] for element in data["elements"]
             if element["group"] == "edges"}
    pc = next(element["data"] for element in data["elements"]
              if element["group"] == "nodes" and element["data"]["id"] == str(pc_id))

    assert edges[f"network-gateway:{network_id}"]["target"] == str(gateway_id)
    assert edges[f"gateway-member:{network_id}:{pc_id}"]["source"] == str(gateway_id)
    assert edges[f"gateway-member:{network_id}:{pc_id}"]["target"] == str(pc_id)
    assert "network-member:" + str(pc_id) not in edges
    assert pc["connection_medium"] == "WIFI"
    assert "Wi-Fi" in pc["label"]


def test_logical_view_keeps_gateway_context_when_device_is_not_visible(mapping_db, monkeypatch):
    monkeypatch.setattr("services.topology_service.get_routing_ip", lambda: "127.0.0.1")
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    networks = NetworkRepository(mapping_db)
    network_id = networks.get_or_create(site_id, "192.168.18.0/24", gateway="192.168.18.1")
    devices = DeviceRepository(mapping_db)
    pc_id = devices.upsert_discovered(site_id, {"network_id": network_id, "ip": "192.168.18.3"})
    service = TopologyService(devices, ConnectionRepository(mapping_db),
                              SiteRepository(mapping_db), networks)

    data = service.get_cytoscape_data(site_id, view="logical")
    node_ids = {element["data"]["id"] for element in data["elements"]
                if element["group"] == "nodes"}
    edges = {element["data"]["id"]: element["data"] for element in data["elements"]
             if element["group"] == "edges"}
    assert f"gateway:{network_id}" in node_ids
    assert edges[f"gateway-member:{network_id}:{pc_id}"]["source"] == f"gateway:{network_id}"


def test_rescanning_updates_the_gateway_for_an_existing_network(mapping_db):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    networks = NetworkRepository(mapping_db)
    network_id = networks.get_or_create(site_id, "192.168.18.0/24", gateway="192.168.18.254")
    assert networks.get_or_create(site_id, "192.168.18.0/24", gateway="192.168.18.1") == network_id
    assert networks.get_by_site(site_id)[0]["gateway"] == "192.168.18.1"


def test_windows_adapter_medium_distinguishes_wifi_and_ethernet(monkeypatch):
    import scanner.network as network

    adapters = [
        {"Name": "Wi-Fi", "NdisPhysicalMedium": 9},
        {"Name": "Ethernet", "NdisPhysicalMedium": 14},
        {"Name": "vEthernet", "NdisPhysicalMedium": 0},
    ]
    monkeypatch.setattr(network.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(adapters)))
    network._windows_adapter_medium.cache_clear()
    assert network._windows_adapter_medium("Wi-Fi") == "WIFI"
    assert network._windows_adapter_medium("Ethernet") == "WIRED"
    assert network._windows_adapter_medium("vEthernet") is None
    network._windows_adapter_medium.cache_clear()


def test_scan_limit_is_explicit():
    with pytest.raises(ValueError, match="límite configurado"):
        scan_size("10.0.0.0/20", max_hosts=1000)


def test_snmp_tables_include_ports_vlans_and_neighbors():
    class Octets:
        def __init__(self, content):
            self.content = content

        def asOctets(self):
            return self.content

    tables = {
        "if_name": {"12": "Gi0/12"}, "if_oper": {"12": "1"},
        "bridge_if": {"1": "12"}, "vlan_name": {"20": "Laboratorio"},
        "vlan_egress": {"20": Octets(b"\x80")},
        "vlan_untagged": {"20": Octets(b"\x80")},
        "fdb_port": {"20.170.187.204.221.238.255": "1"},
        "lldp_local_port": {"1": "Gi0/12"},
        "lldp_name": {"0.1.1": "SW-CORE"},
        "lldp_port": {"0.1.1": "Gi0/24"},
    }
    inventory = build_inventory(tables)
    assert inventory["interfaces"][0]["oper_status"] == "UP"
    assert inventory["interface_vlans"] == [{"if_index": 12, "vlan": 20, "mode": "UNTAGGED"}]
    assert inventory["mac_learnings"][0]["if_index"] == 12
    assert inventory["neighbors"][0]["source_port"] == "Gi0/12"


def test_two_observed_ports_between_same_devices_are_retained(mapping_db):
    site_id = SiteRepository(mapping_db).get_all()[0]["id"]
    devices = DeviceRepository(mapping_db)
    details = NetworkDetailRepository(mapping_db)
    source_id = devices.upsert_discovered(site_id, {"ip": "10.0.0.2", "hostname": "SW-A"})
    target_id = devices.upsert_discovered(site_id, {"ip": "10.0.0.3", "hostname": "SW-B"})
    details.save_inventory(site_id, source_id, {"interfaces": [
        {"if_index": 1, "name": "Gi0/1"}, {"if_index": 2, "name": "Gi0/2"}]})
    details.save_inventory(site_id, target_id, {"interfaces": [
        {"if_index": 1, "name": "Gi0/1"}, {"if_index": 2, "name": "Gi0/2"}]})
    known = devices.get_all(site_id=site_id)
    details.save_neighbors(site_id, devices.get_by_id(source_id), [
        {"neighbor_name": "SW-B", "source_port": "Gi0/1", "remote_port": "Gi0/1"},
        {"neighbor_name": "SW-B", "source_port": "Gi0/2", "remote_port": "Gi0/2"},
        {"neighbor_name": "UNKNOWN", "source_port": "Gi0/3"},
    ], known)
    assert len(details.get_links(site_id)) == 2
    assert len(details.get_unresolved(site_id)) == 1


def test_migration_adds_new_columns_to_old_tables():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("CREATE TABLE interfaces (id INTEGER PRIMARY KEY, device_id INTEGER, name TEXT)")
            conn.execute("CREATE TABLE scan_jobs (id INTEGER PRIMARY KEY, site_id INTEGER, target_cidr TEXT, status TEXT)")
        init_db(path)
        with closing(sqlite3.connect(path)) as conn:
            interface_columns = {row[1] for row in conn.execute("PRAGMA table_info(interfaces)")}
            job_columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_jobs)")}
        assert {"if_index", "observed_at", "speed_bps"} <= interface_columns
        assert "warnings" in job_columns
    finally:
        os.remove(path)


def test_scan_pipeline_preserves_absent_devices_and_completes(mapping_db, monkeypatch):
    import services.discovery_service as discovery
    from scanner.ping import SweepResult

    site_repo = SiteRepository(mapping_db)
    site_id = site_repo.get_all()[0]["id"]
    devices = DeviceRepository(mapping_db)
    devices.upsert_discovered(site_id, {"ip": "10.1.0.3", "device_type": "PC"})
    jobs = ScanJobRepository(mapping_db)
    job_id = jobs.create(site_id, "10.1.0.0/24")
    monkeypatch.setattr(discovery, "ping_sweep", lambda cidr, progress_callback:
                        SweepResult(["10.1.0.2"], {"10.1.0.2": {"latency_ms": 3, "ttl": 64}}))
    monkeypatch.setattr(discovery, "get_arp_table", lambda: {"10.1.0.2": "00:11:22:33:44:55"})
    monkeypatch.setattr(discovery.socket, "gethostbyaddr", lambda ip: ("SW-LOCAL", [], [ip]))
    monkeypatch.setattr(discovery, "query_netbios_details", lambda ip: (None, None))
    monkeypatch.setattr(discovery, "scan_host_services", lambda ip: [])
    monkeypatch.setattr(discovery, "collect_snmp_inventory", lambda ip, credentials: {"has_snmp": False})
    monkeypatch.setattr(discovery, "fingerprint_device", lambda **kwargs: ("SWITCH", "SW-LOCAL", ""))
    service = DiscoveryService(devices, NetworkRepository(mapping_db),
                               ConnectionRepository(mapping_db), jobs, site_repo)

    service._run_scan_pipeline(job_id, site_id, "10.1.0.0/24", "", "", "",
                               {"version": "2c", "community": "public"})

    assert jobs.get_by_id(job_id)["status"] == "COMPLETED"
    assert devices.get_by_ip(site_id, "10.1.0.3")["status"] == "OFFLINE"
    assert devices.get_by_ip(site_id, "10.1.0.2")["status"] == "ONLINE"
