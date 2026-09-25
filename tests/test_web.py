import os
import tempfile
import pytest
from app import create_app
from database.connection import init_db
from repositories.device_repository import DeviceRepository

class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    DATABASE_PATH = None

@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    TestConfig.DATABASE_PATH = path
    app = create_app(TestConfig)

    with app.test_client() as client:
        yield client

    if os.path.exists(path):
        os.remove(path)

def test_routes_status_code(client):
    # Index
    r = client.get("/")
    assert r.status_code == 200
    assert b"NetMap Escolar" in r.data

    # Topology
    r = client.get("/topology")
    assert r.status_code == 200
    assert b"Mapa de red" in r.data

    # Devices
    r = client.get("/devices")
    assert r.status_code == 200
    assert b"Inventario" in r.data

    # Legacy multisite route now returns to the single-site dashboard.
    r = client.get("/sites")
    assert r.status_code == 302

def test_api_network_detect(client):
    r = client.get("/api/network/detect")
    assert r.status_code == 200
    json_data = r.get_json()
    assert "local_ip" in json_data
    assert "cidr" in json_data
    assert "interface" in json_data

def test_api_topology_data(client):
    r = client.get("/api/topology/data?site_id=1")
    assert r.status_code == 200
    json_data = r.get_json()
    assert "elements" in json_data
    assert "counts" in json_data


def test_map_views_and_offline_filter(client):
    devices = DeviceRepository(TestConfig.DATABASE_PATH)
    devices.upsert_discovered(1, {"ip": "10.3.0.2", "device_type": "SWITCH"})
    devices.upsert_discovered(1, {"ip": "10.3.0.3", "device_type": "PC"})
    devices.mark_offline_or_cleanup(1, {"10.3.0.2"}, cidr="10.3.0.0/24")

    for view in ("physical", "logical", "inventory"):
        response = client.get(f"/api/topology/data?view={view}")
        assert response.status_code == 200
        assert response.get_json()["counts"]["TOTAL"] == 1
    response = client.get("/api/topology/data?view=inventory&status=ALL")
    assert response.get_json()["counts"]["TOTAL"] == 2
    assert client.get("/devices").data.count(b"10.3.0.3") == 0
    assert b"10.3.0.3" in client.get("/devices?status=ALL").data


def test_scan_estimate_rejects_invalid_and_too_large_ranges(client):
    assert client.get("/api/scan/estimate?cidr=invalid").status_code == 400
    assert client.get("/api/scan/estimate?cidr=10.0.0.0/8").status_code == 400
    response = client.get("/api/scan/estimate?cidr=10.0.0.0/23")
    assert response.get_json()["host_count"] == 510

def test_device_csv_export(client):
    r = client.get("/devices/export?site_id=1")
    assert r.status_code == 200
    assert "text/csv" in r.content_type
    assert b"Subred,VLAN,IP,MAC,Hostname,Tipo" in r.data
