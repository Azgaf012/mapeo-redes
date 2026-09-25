import os
import tempfile
import pytest
from database.connection import init_db
from repositories.site_repository import SiteRepository
from repositories.device_repository import DeviceRepository
from repositories.connection_repository import ConnectionRepository
from repositories.scan_job_repository import ScanJobRepository

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_site_seeding_and_crud(temp_db):
    repo = SiteRepository(temp_db)
    sites = repo.get_all()
    assert len(sites) >= 1
    names = [s["name"] for s in sites]
    assert "Sede local" in names

    # Create new site
    new_id = repo.create("Sede Anexo", "Nuevo campus de laboratorio")
    assert new_id > 0
    anexo = repo.get_by_id(new_id)
    assert anexo["name"] == "Sede Anexo"

def test_device_upsert_and_manual_preservation(temp_db):
    site_repo = SiteRepository(temp_db)
    device_repo = DeviceRepository(temp_db)
    
    site = site_repo.get_by_name("Sede local")
    site_id = site["id"]

    # 1. First automatic discovery of a switch
    data_1 = {
        "ip": "192.168.1.2",
        "mac": "00:1A:2B:3C:4D:5E",
        "hostname": "SW-CORE-TEMP",
        "vendor": "Cisco",
        "model": "Catalyst 2960",
        "device_type": "SWITCH"
    }
    dev_id = device_repo.upsert_discovered(site_id, data_1)
    assert dev_id is not None

    dev = device_repo.get_by_id(dev_id)
    assert dev["ip"] == "192.168.1.2"
    assert dev["device_type"] == "SWITCH"
    assert dev["is_manual"] == 0

    # 2. Administrator updates manual fields (Rack, Floor, Location, custom note)
    device_repo.update_manual_fields(dev_id, {
        "location": "Datacenter Piso 2",
        "rack": "Rack-01",
        "floor": "2",
        "description": "Switch de distribución principal"
    })

    dev_updated = device_repo.get_by_id(dev_id)
    assert dev_updated["is_manual"] == 1
    assert dev_updated["location"] == "Datacenter Piso 2"
    assert dev_updated["rack"] == "Rack-01"

    # 3. Subsequent scan occurs with updated hostname or status
    data_2 = {
        "ip": "192.168.1.2",
        "mac": "00:1A:2B:3C:4D:5E",
        "hostname": "SW-CORE-NEWNAME",
        "vendor": "Cisco Systems",
        "device_type": "SWITCH"
    }
    device_repo.upsert_discovered(site_id, data_2)

    # 4. Verify manual annotations are preserved!
    dev_final = device_repo.get_by_id(dev_id)
    assert dev_final["location"] == "Datacenter Piso 2"
    assert dev_final["rack"] == "Rack-01"
    assert dev_final["floor"] == "2"
    assert dev_final["description"] == "Switch de distribución principal"
    assert dev_final["is_manual"] == 1

def test_connection_management(temp_db):
    site_repo = SiteRepository(temp_db)
    dev_repo = DeviceRepository(temp_db)
    conn_repo = ConnectionRepository(temp_db)

    site_id = site_repo.get_by_name("Sede local")["id"]
    d1 = dev_repo.upsert_discovered(site_id, {"ip": "192.168.1.1", "device_type": "ROUTER"})
    d2 = dev_repo.upsert_discovered(site_id, {"ip": "192.168.1.2", "device_type": "SWITCH"})

    # Create link
    c_id = conn_repo.create_or_update(site_id, d1, d2, discovery_method="LLDP", confidence="HIGH")
    assert c_id is not None

    links = conn_repo.get_by_site(site_id)
    assert len(links) == 1
    assert links[0]["source_ip"] == "192.168.1.1"
    assert links[0]["target_ip"] == "192.168.1.2"
