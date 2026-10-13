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
