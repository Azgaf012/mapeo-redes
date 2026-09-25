import csv
import io

from database.connection import get_db, init_db
from repositories.device_repository import DeviceRepository
from repositories.site_repository import SiteRepository
from services.device_service import DeviceService
from services.discovery_service import DiscoveryService


def test_scan_evidence_is_exported_and_manual_type_is_distinct(tmp_path, monkeypatch):
    db_path = str(tmp_path / "inventory.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)

    monkeypatch.setattr("services.discovery_service.lookup_vendor", lambda mac: "HPE")
    monkeypatch.setattr("services.discovery_service.query_netbios_details", lambda ip: ("", ""))
    monkeypatch.setattr("services.discovery_service.scan_host_services", lambda ip: [443, 22])
    monkeypatch.setattr("services.discovery_service.collect_snmp_inventory", lambda ip, credentials: {
        "has_snmp": True,
        "sys_name": "AP-AULA",
        "sys_descr": "Aruba Instant AP-505",
        "model": "AP-505",
        "interfaces": [{"name": "eth0"}],
        "neighbors": [],
    })
    monkeypatch.setattr("services.discovery_service.socket.gethostbyaddr",
                        lambda ip: ("ap-aula.local", [], [ip]))

    def fingerprint(**kwargs):
        kwargs["diagnostics"].update({"web_title": "Aruba AP-505", "web_port": 443})
        return "ACCESS_POINT", kwargs["hostname"], "AP-505"

    monkeypatch.setattr("services.discovery_service.fingerprint_device", fingerprint)
    discovery = DiscoveryService(None, None, None, None, None, detail_repo=object())
    payload, _, _, _ = discovery._inspect_host(
        "192.168.50.55", "", "", "", {"192.168.50.55": "24:F2:7F:CF:A8:56"},
        {"192.168.50.55": {"ttl": 64, "latency_ms": 2.5}},
        {"version": "2c", "community": "secret-community"}, None,
    )
    assert "secret-community" not in payload["scan_evidence"]
    device_id = devices.upsert_discovered(site_id, payload)
    devices.update_manual_fields(device_id, {"device_type": "SWITCH"})
    devices.upsert_discovered(site_id, payload)

    rows = list(csv.DictReader(io.StringIO(DeviceService(devices, None).export_csv(site_id))))
    row = rows[0]
    assert row["Tipo"] == "SWITCH"
    assert row["Tipo detectado"] == "ACCESS_POINT"
    assert row["Origen detección"] == "fingerprint"
    assert row["Puertos TCP abiertos"] == "22;443"
    assert row["TTL ICMP"] == "64"
    assert row["Estado SNMP"] == "available"
    assert row["SNMP sysDescr"] == "Aruba Instant AP-505"
    assert row["Interfaces SNMP"] == "1"
    assert row["Título web"] == "Aruba AP-505"
    assert row["Puerto web"] == "443"


def test_legacy_devices_export_empty_evidence_columns(tmp_path):
    db_path = str(tmp_path / "inventory.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)
    devices.upsert_discovered(site_id, {"ip": "192.168.50.8", "device_type": "UNKNOWN"})

    reader = csv.DictReader(io.StringIO(DeviceService(devices, None).export_csv(site_id)))
    assert reader.fieldnames[:22] == [
        "ID", "Sede", "Subred", "VLAN", "IP", "MAC", "Hostname", "Tipo",
        "Fabricante", "Modelo", "Sistema Operativo", "Latencia (ms)",
        "Seguridad", "Grupo de Trabajo", "Serial", "Estado", "Ubicación",
        "Rack", "Piso", "Modo Manual", "Última Conexión", "Descripción",
    ]
    row = next(reader)
    assert row["Tipo detectado"] == ""
    assert row["SNMP sysDescr"] == ""
    assert row["Puertos TCP abiertos"] == ""


def test_init_db_adds_scan_evidence_to_existing_devices_table(tmp_path):
    db_path = str(tmp_path / "inventory.db")
    init_db(db_path)
    with get_db(db_path) as conn:
        conn.execute("ALTER TABLE devices DROP COLUMN scan_evidence")
    init_db(db_path)
    with get_db(db_path) as conn:
        names = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
    assert "scan_evidence" in names
