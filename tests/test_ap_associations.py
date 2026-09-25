import io
import json

from app import create_app
from database.connection import init_db
from database.connection import get_db
from repositories.ap_association_repository import ApAssociationRepository
from repositories.connection_repository import ConnectionRepository
from repositories.device_repository import DeviceRepository
from repositories.site_repository import SiteRepository
from services.ap_association_service import ApAssociationService
from services.topology_service import TopologyService


def test_import_groups_clients_under_confirmed_ap_and_replaces_snapshot(tmp_path):
    db_path = str(tmp_path / "associations.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)
    ap_id = devices.upsert_discovered(site_id, {
        "ip": "192.168.50.55", "hostname": "AP-AULA", "device_type": "UNKNOWN"})
    client_id = devices.upsert_discovered(site_id, {
        "ip": "192.168.50.60", "mac": "AA:BB:CC:DD:EE:01", "device_type": "UNKNOWN"})
    associations = ApAssociationRepository(db_path)
    importer = ApAssociationService(devices, associations)

    result = importer.import_csv(site_id, b"client_mac,ap_ip\nAA-BB-CC-DD-EE-01,192.168.50.55\n")
    assert result["imported"] == 1
    assert devices.get_by_id(ap_id)["device_type"] == "ACCESS_POINT"
    assert json.loads(devices.get_by_id(ap_id)["scan_evidence"])["classification_source"] == "ap_client_csv"

    topology = TopologyService(devices, ConnectionRepository(db_path), SiteRepository(db_path),
                               ap_association_repo=associations)
    data = topology.get_cytoscape_data(site_id, view="physical")
    client = next(item["data"] for item in data["elements"]
                  if item["group"] == "nodes" and item["data"]["id"] == str(client_id))
    assert client["ap_association"]["ap_id"] == str(ap_id)
    assert client["ap_association"]["source"] == "ap_client_csv"

    devices.upsert_discovered(site_id, {"ip": "192.168.50.55", "device_type": "UNKNOWN"})
    assert devices.get_by_id(ap_id)["device_type"] == "UNKNOWN"
    importer.refresh_recent_aps(site_id)
    assert devices.get_by_id(ap_id)["device_type"] == "ACCESS_POINT"

    importer.import_csv(site_id, b"client_mac,ap_ip\n")
    data = topology.get_cytoscape_data(site_id, view="physical")
    client = next(item["data"] for item in data["elements"]
                  if item["group"] == "nodes" and item["data"]["id"] == str(client_id))
    assert client["ap_association"] is None


def test_imported_association_expires_after_one_day(tmp_path):
    db_path = str(tmp_path / "expired.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)
    devices.upsert_discovered(site_id, {
        "ip": "192.168.50.55", "device_type": "ACCESS_POINT"})
    client_id = devices.upsert_discovered(site_id, {
        "ip": "192.168.50.60", "mac": "AA:BB:CC:DD:EE:01"})
    associations = ApAssociationRepository(db_path)
    ApAssociationService(devices, associations).import_csv(
        site_id, b"client_mac,ap_ip\nAA:BB:CC:DD:EE:01,192.168.50.55\n")
    with get_db(db_path) as conn:
        conn.execute("UPDATE ap_client_associations SET observed_at='2000-01-01 00:00:00'")

    topology = TopologyService(devices, ConnectionRepository(db_path), SiteRepository(db_path),
                               ap_association_repo=associations)
    data = topology.get_cytoscape_data(site_id, view="physical")
    client = next(item["data"] for item in data["elements"]
                  if item["group"] == "nodes" and item["data"]["id"] == str(client_id))
    assert client["ap_association"] is None


def test_import_rejects_conflicting_ap_rows_without_overwriting_snapshot(tmp_path):
    db_path = str(tmp_path / "conflicts.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)
    for ip in ("192.168.50.55", "192.168.50.56"):
        devices.upsert_discovered(site_id, {"ip": ip, "device_type": "ACCESS_POINT"})
    associations = ApAssociationRepository(db_path)
    importer = ApAssociationService(devices, associations)
    importer.import_csv(site_id, b"client_mac,ap_ip\nAA:BB:CC:DD:EE:01,192.168.50.55\n")

    result = importer.import_csv(site_id, (
        b"client_mac,ap_ip\nAA:BB:CC:DD:EE:01,192.168.50.55\n"
        b"AA:BB:CC:DD:EE:01,192.168.50.56\n"))
    assert result["ambiguous"] == 1
    assert result["imported"] == 0
    assert len(associations.get_by_site(site_id)) == 1


def test_import_accepts_semicolon_csv_from_excel(tmp_path):
    db_path = str(tmp_path / "excel.db")
    init_db(db_path)
    site_id = SiteRepository(db_path).get_all()[0]["id"]
    devices = DeviceRepository(db_path)
    devices.upsert_discovered(site_id, {
        "ip": "192.168.50.55", "device_type": "ACCESS_POINT"})
    importer = ApAssociationService(devices, ApAssociationRepository(db_path))

    result = importer.import_csv(
        site_id, b"client_mac;ap_ip\nAA:BB:CC:DD:EE:01;192.168.50.55\n")
    assert result["imported"] == 1


def test_topology_upload_accepts_aruba_style_columns(tmp_path):
    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-secret"
        DATABASE_PATH = str(tmp_path / "web.db")

    app = create_app(TestConfig)
    devices = DeviceRepository(TestConfig.DATABASE_PATH)
    devices.upsert_discovered(1, {
        "ip": "192.168.50.55", "hostname": "AP-AULA", "device_type": "ACCESS_POINT"})
    devices.upsert_discovered(1, {
        "ip": "192.168.50.60", "mac": "AA:BB:CC:DD:EE:01"})
    with app.test_client() as client:
        assert b'ap-association-upload' in client.get('/topology').data
        response = client.post('/api/ap-associations/import', data={
            'file': (io.BytesIO(b'MAC address,Access Point\nAA:BB:CC:DD:EE:01,AP-AULA\n'),
                     'clients.csv')}, content_type='multipart/form-data')
        assert response.status_code == 200
        assert response.get_json()['imported'] == 1
        elements = client.get('/api/topology/data?view=physical').get_json()['elements']
        client_node = next(item['data'] for item in elements if item['group'] == 'nodes'
                           and item['data'].get('ip') == '192.168.50.60')
        assert client_node['ap_association']['ap_name'] == 'AP-AULA'
