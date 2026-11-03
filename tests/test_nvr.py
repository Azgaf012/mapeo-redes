import os
import tempfile

import pytest

import app as app_module
from app import create_app
from database.connection import init_db
from repositories.nvr_credential_repository import NvrCredentialRepository, nvr_key
from scanner.drivers.base import HostFacts
from scanner.drivers import hikvision_nvr
from scanner.drivers.hikvision_nvr import HikvisionNvrDriver, parse_channels

CHANNELS = (
    '<InputProxyChannelList xmlns="http://www.hikvision.com/ver20/XMLSchema">'
    "<InputProxyChannel><id>1</id><name>Entrada</name><sourceInputPortDescriptor>"
    "<ipAddress>192.168.254.10</ipAddress><model>DS-2CD1121-I</model>"
    "</sourceInputPortDescriptor></InputProxyChannel></InputProxyChannelList>")
STATUS = ("<L><InputProxyChannelStatus><id>1</id><online>false</online>"
          "</InputProxyChannelStatus></L>")


@pytest.fixture
def repo(tmp_path):
    db = str(tmp_path / "t.db")
    init_db(db)
    return NvrCredentialRepository(db, key_path=str(tmp_path / "k.key"))


def facts():
    return HostFacts(ip="192.168.50.5", mac="28:57:BE:90:D1:03", vendor="Hikvision",
                     hostname="DS-7616NI-E2/8P", base_type="NVR")


def test_parse_channels():
    peers = parse_channels(CHANNELS, STATUS)
    assert peers[0]["ip"] == "192.168.254.10"
    assert peers[0]["online"] is False


def test_password_is_encrypted_at_rest(repo):
    repo.save_credentials("192.168.50.5", "28:57:BE:90:D1:03", "ro", "secreto", 80)
    row = repo.get("192.168.50.5", "28:57:BE:90:D1:03")
    assert row["password"] == "secreto" and row["has_credentials"]
    import sqlite3
    raw = sqlite3.connect(repo.db_path).execute("SELECT password_enc FROM nvr_credentials").fetchone()[0]
    assert "secreto" not in raw


def test_driver_registers_pending_without_credentials(repo, monkeypatch):
    monkeypatch.delenv("NVR_USER", raising=False)
    driver = HikvisionNvrDriver()
    driver.store = repo
    assert driver.matches(facts())
    assert driver.probe(facts()) is None
    assert repo.get("192.168.50.5", "28:57:BE:90:D1:03")["status"] == "pending"


def test_driver_uses_stored_credentials_and_skips_rejected(repo, monkeypatch):
    calls = []
    results = iter([("ok", "1 camaras", parse_channels(CHANNELS, STATUS)),
                    ("auth_failed", "rechazado", [])])
    monkeypatch.setattr(hikvision_nvr, "fetch_cameras",
                        lambda *args: calls.append(args) or next(results))
    repo.save_credentials("192.168.50.5", "28:57:BE:90:D1:03", "ro", "pw", 80)
    driver = HikvisionNvrDriver()
    driver.store = repo
    result = driver.probe(facts())
    assert result and result.peers[0]["ip"] == "192.168.254.10"
    assert calls[0][:2] == ("192.168.50.5", "ro")
    driver.begin_scan()
    assert driver.probe(facts()) is None                  # rejected now
    driver.begin_scan()
    assert driver.probe(facts()) is None and len(calls) == 2  # not retried: no lockout
    repo.save_credentials("192.168.50.5", "28:57:BE:90:D1:03", "ro", "nueva", 80)
    assert repo.get("192.168.50.5", "28:57:BE:90:D1:03")["status"] == "pending"


def test_apply_to_unresolved(repo):
    repo.seen("192.168.50.5", "28:57:BE:90:D1:03")
    repo.seen("192.168.60.5", "")
    assert repo.apply_to_unresolved("ro", "pw", 80) == 2
    assert repo.get("192.168.60.5")["username"] == "ro"
    assert nvr_key("1.1.1.1", "") == "ip:1.1.1.1"


def test_nvr_page_saves_and_imports_cameras(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class Cfg:
        TESTING = True
        SECRET_KEY = "x"
        DATABASE_PATH = path
        IDENTITY_ENABLED = False

    app = create_app(Cfg)
    from repositories.device_repository import DeviceRepository
    from repositories.site_repository import SiteRepository
    site_id = SiteRepository(path).get_all()[0]["id"]
    DeviceRepository(path).upsert_discovered(site_id, {
        "ip": "192.168.50.5", "mac": "28:57:BE:90:D1:03", "device_type": "NVR", "hostname": "NVR"})
    monkeypatch.setattr(app_module, "fetch_cameras",
                        lambda *a: ("ok", "1 camaras registradas", parse_channels(CHANNELS, STATUS)))
    client = app.test_client()
    assert b"Pendiente de credenciales" in client.get("/nvr").data
    response = client.post("/nvr/credentials", data={
        "ip": "192.168.50.5", "mac": "28:57:BE:90:D1:03", "username": "ro", "password": "pw"},
        follow_redirects=True)
    assert b"importadas 1" in response.data
    cameras = DeviceRepository(path).get_all(device_type="CAMERA")
    assert cameras[0]["ip"] == "192.168.254.10" and cameras[0]["status"] == "OFFLINE"
    assert b"Conectado" in client.get("/nvr").data
    os.remove(path)
