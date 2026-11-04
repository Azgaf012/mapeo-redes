import sqlite3

import pytest

from app import create_app
from config import Config
from repositories.device_repository import DeviceRepository
from repositories.switch_credential_repository import SwitchCredentialRepository
from repositories.network_repository import NetworkRepository
from repositories.connection_repository import ConnectionRepository
from repositories.scan_job_repository import ScanJobRepository
from repositories.site_repository import SiteRepository
from services.discovery_service import DiscoveryService
from scanner.ping import SweepResult


@pytest.fixture
def switch_app(tmp_path):
    class TestConfig(Config):
        DATABASE_PATH = str(tmp_path / "switches.db")
        TESTING = True
        IDENTITY_ENABLED = False
    return create_app(TestConfig), TestConfig.DATABASE_PATH


def test_profile_is_encrypted_and_html_never_contains_secret(switch_app):
    app, path = switch_app
    devices = DeviceRepository(path)
    device_id = devices.upsert_discovered(1, {"ip": "192.168.48.82", "device_type": "UNKNOWN"})
    with app.test_client() as client:
        response = client.post("/switches/credentials", data={
            "ip": "192.168.48.82", "version": "2c", "community": "test-only-secret",
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"test-only-secret" not in response.data
    with sqlite3.connect(path) as conn:
        encrypted = conn.execute("SELECT credentials_enc FROM switch_credentials").fetchone()[0]
        conn.execute("INSERT INTO sites(name) VALUES ('Other')")
    assert "test-only-secret" not in encrypted
    store = SwitchCredentialRepository(path)
    assert "credentials" not in store.list_by_site(1)[0]
    assert store.list_by_site(1, True)[0]["credentials"]["community"] == "test-only-secret"
    assert store.list_by_site(2, True) == []
    assert devices.get_by_id(device_id)["device_type"] == "SWITCH"


def test_out_of_range_switch_is_polled_without_ping_and_links_saved(switch_app, monkeypatch):
    import services.discovery_service as discovery

    app, path = switch_app
    store = SwitchCredentialRepository(path)
    store.save(1, "198.51.100.82", {"version": "3", "username": "reader"})
    devices = DeviceRepository(path)
    devices.upsert_discovered(1, {"ip": "192.0.2.10", "device_type": "ACCESS_POINT"})
    calls = []
    def collect(ip, credentials):
        calls.append((ip, credentials))
        return {
            "has_snmp": True, "sys_name": "SW-REGISTERED",
            "table_results": {"if_name": {"status": "rows", "rows": 1}},
            "interfaces": [{"if_index": 1, "name": "1"}],
            "neighbors": [{"target_ip": "192.0.2.10", "protocol": "LLDP", "source_port": "1"}],
        }
    monkeypatch.setattr(discovery, "collect_snmp_inventory", collect)
    monkeypatch.setattr(discovery, "ping_sweep", lambda *args, **kwargs: SweepResult(["192.0.2.10"]))
    monkeypatch.setattr(discovery, "get_arp_table", lambda: {})
    monkeypatch.setattr(discovery, "read_dhcp_leases", lambda scope: {})
    jobs = ScanJobRepository(path)
    service = DiscoveryService(devices, NetworkRepository(path), ConnectionRepository(path),
                               jobs, SiteRepository(path))
    monkeypatch.setattr(service, "_inspect_host", lambda *args: (
        {"ip": "192.0.2.10", "device_type": "ACCESS_POINT"}, {}, [], None))
    job_id = jobs.create(1, "192.0.2.0/24")
    service._run_scan_pipeline(job_id, 1, "192.0.2.0/24", "", "", "", {"version": "2c"})
    assert jobs.get_by_id(job_id)["status"] == "COMPLETED"
    assert calls == [("198.51.100.82", {"version": "3", "username": "reader"})]
    assert devices.get_by_ip(1, "198.51.100.82")["device_type"] == "SWITCH"
    assert len(service.detail_repo.get_links(1)) == 1
    assert store.list_by_site(1)[0]["tables"]["if_name"]["rows"] == 1
    with app.test_client() as client:
        assert b"Datos recibidos" in client.get("/switches").data


def test_no_snmp_response_does_not_mark_switch_online(switch_app, monkeypatch):
    import services.discovery_service as discovery

    app, path = switch_app
    store = SwitchCredentialRepository(path)
    store.save(1, "198.51.100.82", {"version": "2c", "community": "test-only"})
    monkeypatch.setattr(discovery, "collect_snmp_inventory", lambda *args: {"has_snmp": False})
    service = DiscoveryService(DeviceRepository(path), None, None, None, None)
    assert service.read_registered_switch(1, store.list_by_site(1, True)[0]) is None
    assert service.device_repo.get_by_ip(1, "198.51.100.82") is None
    assert store.list_by_site(1)[0]["status"] == "no_response"
