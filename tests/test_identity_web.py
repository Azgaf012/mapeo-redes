import json
import os
import tempfile

import pytest

from app import create_app
from repositories.device_repository import DeviceRepository
from repositories.site_repository import SiteRepository


@pytest.fixture
def app_env(tmp_path):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class IdentityTestConfig:
        TESTING = True
        SECRET_KEY = "test"
        DATABASE_PATH = path
        IDENTITY_DATA_DIR = str(tmp_path)
        PLUGIN_DIR = str(tmp_path / "plugins")
        IDENTITY_BROADCAST = False

    app = create_app(IdentityTestConfig)
    yield app, path, tmp_path
    os.remove(path)


def _site_id(path):
    return SiteRepository(path).get_all()[0]["id"]


def test_unidentified_export_and_feedback_updates_devices(app_env):
    app, path, tmp_path = app_env
    site_id = _site_id(path)
    repo = DeviceRepository(path)
    repo.upsert_discovered(site_id, {
        "ip": "10.1.1.9", "mac": "02:AA:BB:CC:DD:EE", "device_type": "UNKNOWN",
        "scan_evidence": json.dumps({"detected_type": "UNKNOWN"})})
    client = app.test_client()

    export = client.get("/identity/unidentified.csv")
    assert export.status_code == 200
    assert export.mimetype == "text/csv"
    assert b"manual_type" in export.data

    report = ("ip,mac,manual_type,manual_vendor,manual_model\n"
              "10.1.1.9,02:AA:BB:CC:DD:EE,Impresora,Acme,X1\n").encode()
    from io import BytesIO
    response = client.post("/api/identity/feedback",
                           data={"file": (BytesIO(report), "r.csv")},
                           content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["updated"] == 1

    device = repo.get_by_ip(site_id, "10.1.1.9")
    assert device["device_type"] == "PRINTER"
    assert device["vendor"] == "Acme" and device["model"] == "X1"
    assert (tmp_path / "identity_overrides.csv").exists()


def test_feedback_rejects_missing_file_and_keeps_manual_devices(app_env):
    app, path, _ = app_env
    site_id = _site_id(path)
    repo = DeviceRepository(path)
    device_id = repo.upsert_discovered(site_id, {"ip": "10.1.1.10", "mac": "AA:AA:AA:00:00:01",
                                                "device_type": "UNKNOWN"})
    repo.update_manual_fields(device_id, {"device_type": "SERVER"})
    client = app.test_client()
    assert client.post("/api/identity/feedback").status_code == 400

    from io import BytesIO
    report = b"ip,mac,manual_type\n10.1.1.10,AA:AA:AA:00:00:01,PC\n"
    result = client.post("/api/identity/feedback", data={"file": (BytesIO(report), "r.csv")},
                         content_type="multipart/form-data").get_json()
    assert result["updated"] == 0
    assert repo.get_by_ip(site_id, "10.1.1.10")["device_type"] == "SERVER"


def test_reclassify_uses_current_rules_without_scanning(app_env):
    app, path, _ = app_env
    site_id = _site_id(path)
    repo = DeviceRepository(path)
    repo.upsert_discovered(site_id, {
        "ip": "10.2.0.5", "mac": "50:BB:B5:00:00:01", "vendor": "Desconocido",
        "device_type": "UNKNOWN"})
    repo.upsert_discovered(site_id, {
        "ip": "10.2.0.6", "mac": "02:00:00:00:00:09", "vendor": "MAC privada/aleatoria",
        "device_type": "UNKNOWN"})
    result = app.test_client().post("/api/identity/reclassify").get_json()
    assert result["examined"] == 2 and result["updated"] == 1
    device = repo.get_by_ip(site_id, "10.2.0.5")
    assert device["device_type"] == "WIFI_CLIENT"
    assert device["vendor"] == "AzureWave Technology"
    assert repo.get_by_ip(site_id, "10.2.0.6")["device_type"] == "UNKNOWN"


def test_stale_purge_previews_then_deletes_only_old_offline_random_macs(app_env):
    app, path, _ = app_env
    site_id = _site_id(path)
    repo = DeviceRepository(path)
    from database.connection import get_db
    old = repo.upsert_discovered(site_id, {"ip": "10.3.0.1", "mac": "02:11:11:11:11:11",
                                          "device_type": "UNKNOWN"})
    real_mac = repo.upsert_discovered(site_id, {"ip": "10.3.0.2", "mac": "50:BB:B5:11:11:11",
                                               "device_type": "UNKNOWN"})
    recent = repo.upsert_discovered(site_id, {"ip": "10.3.0.3", "mac": "02:22:22:22:22:22",
                                             "device_type": "UNKNOWN"})
    with get_db(path) as conn:
        conn.execute("UPDATE devices SET status='OFFLINE', last_seen='2026-01-01 00:00:00' WHERE id IN (?,?)",
                     (old, real_mac))
        conn.execute("UPDATE devices SET status='OFFLINE' WHERE id=?", (recent,))
    client = app.test_client()
    assert client.post("/api/devices/stale", json={"days": 0}).status_code == 400
    assert client.post("/api/devices/stale", json={"days": 30}).get_json()["count"] == 1
    assert repo.get_by_ip(site_id, "10.3.0.1") is not None
    assert client.post("/api/devices/stale", json={"days": 30, "confirm": True}).get_json()["deleted"] == 1
    assert repo.get_by_ip(site_id, "10.3.0.1") is None
    assert repo.get_by_ip(site_id, "10.3.0.2") is not None
    assert repo.get_by_ip(site_id, "10.3.0.3") is not None
