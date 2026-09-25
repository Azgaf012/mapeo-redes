import os
import tempfile
import pytest
from database.connection import init_db
from repositories.site_repository import SiteRepository
from repositories.device_repository import DeviceRepository
from repositories.connection_repository import ConnectionRepository
from scanner.topology import build_topology

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_topology_hierarchy_generation(temp_db):
    site_repo = SiteRepository(temp_db)
    dev_repo = DeviceRepository(temp_db)
    conn_repo = ConnectionRepository(temp_db)

    site_id = site_repo.get_by_name("Sede local")["id"]

    # 1. Gateway
    g_id = dev_repo.upsert_discovered(site_id, {
        "ip": "192.168.1.1", "device_type": "FIREWALL", "hostname": "FW-GATEWAY"
    })
    # 2. Core switch
    sw_id = dev_repo.upsert_discovered(site_id, {
        "ip": "192.168.1.2", "device_type": "SWITCH", "hostname": "SW-CORE"
    })
    # 3. Access Point
    ap_id = dev_repo.upsert_discovered(site_id, {
        "ip": "192.168.1.20", "device_type": "ACCESS_POINT", "hostname": "AP-01"
    })
    # 4. PC Client
    pc_id = dev_repo.upsert_discovered(site_id, {
        "ip": "192.168.1.50", "device_type": "PC", "hostname": "PC-SALA1"
    })

    devices = dev_repo.get_all(site_id=site_id)
    links = build_topology(site_id, devices, conn_repo, gateway_ip="192.168.1.1")

    assert links == []  # Device types and IP order do not prove physical cabling.
