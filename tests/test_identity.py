import csv

from scanner.drivers.base import HostFacts
from scanner.drivers.hostnames import classify_hostname
from scanner.drivers.protocols import (SharedDiscovery, parse_mndp_response,
                                       parse_sadp_response, parse_upnp_description)
from scanner.drivers.registry import DriverRegistry
from scanner.drivers.vendors import match_sys_object_id
from scanner.identity import Evidence, IdentityService, resolve
from scanner.identity.overrides import OverridesStore, normalize_type


def make_service(tmp_path, registry=None):
    service = IdentityService(str(tmp_path), broadcast=False, registry=registry or _builtin())
    service.shared = SharedDiscovery()
    return service


def _builtin():
    registry = DriverRegistry()
    registry.load_builtin(mdns_enabled=False)
    return registry


def test_engine_picks_strongest_type_and_rewards_corroboration():
    identity = resolve([Evidence("fingerprint", 70, "SWITCH", model="2530"),
                        Evidence("sysobjectid", 85, "SWITCH", vendor="HPE"),
                        Evidence("hostname", 55, "PC")])
    assert identity.device_type == "SWITCH"
    assert identity.confidence == "high"
    assert identity.vendor == "HPE" and identity.model == "2530"
    assert identity.sources[0] == "sysobjectid"


def test_engine_leaves_weak_or_missing_evidence_unknown():
    assert resolve([]).device_type == "UNKNOWN"
    assert resolve([Evidence("oui", 5, "PHONE")]).device_type == "UNKNOWN"


def test_engine_typeless_evidence_still_supplies_vendor():
    identity = resolve([Evidence("upnp", 0, None, vendor="Samsung")])
    assert identity.device_type == "UNKNOWN" and identity.vendor == "Samsung"


def test_sys_object_id_longest_prefix():
    assert match_sys_object_id("1.3.6.1.4.1.11.2.3.7.11.123")[2] == "SWITCH"
    assert match_sys_object_id(".1.3.6.1.4.1.11.2.3.9.1.1")[2] == "PRINTER"
    assert match_sys_object_id("1.3.6.1.4.1.99999.1") is None


def test_parsers_extract_fields_without_network():
    assert parse_upnp_description(
        "<root><device><friendlyName>TV Sala</friendlyName><manufacturer>Samsung</manufacturer>"
        "</device></root>") == {"friendly_name": "TV Sala", "manufacturer": "Samsung"}
    sadp = parse_sadp_response(b"<ProbeMatch><DeviceType>DS-2CD2143</DeviceType>"
                               b"<MAC>aa-bb-cc-dd-ee-ff</MAC><DeviceSN>SN1</DeviceSN></ProbeMatch>")
    assert sadp["mac"] == "AA:BB:CC:DD:EE:FF" and sadp["serial"] == "SN1"
    assert parse_sadp_response(b"garbage") is None
    assert parse_mndp_response(b"\x00") is None


def test_hostname_hints():
    assert classify_hostname("Andrees-iPhone")[0] == "PHONE"
    assert classify_hostname("MacBook-Pro-de-Ana")[0] == "LAPTOP"
    assert classify_hostname("NPI1A2B3C")[0] == "PRINTER"
    assert classify_hostname("Celular / Móvil") is None
    assert classify_hostname("server-xyz") is None


def test_overrides_match_priority_and_persistence(tmp_path):
    store = OverridesStore(str(tmp_path / "ov.csv"))
    store.upsert("oui", "AA:BB:CC", "CAMERA", "Acme", "")
    store.upsert("mac", "AA:BB:CC:00:00:01", "PRINTER", "Acme", "P1")
    host = HostFacts(ip="10.0.0.5", mac="aa:bb:cc:00:00:01")
    assert store.match(host)["device_type"] == "PRINTER"
    other = HostFacts(ip="10.0.0.6", mac="AA:BB:CC:00:00:02")
    assert store.match(other)["device_type"] == "CAMERA"
    assert store.match(HostFacts(ip="10.0.0.7", mac="11:22:33:44:55:66")) is None
    assert OverridesStore(str(tmp_path / "ov.csv")).count() == 2


def test_normalize_type_accepts_spanish_aliases():
    assert normalize_type("cámara") is None or normalize_type("cámara") == "CAMERA"
    assert normalize_type("Impresora") == "PRINTER"
    assert normalize_type("punto de acceso") == "ACCESS_POINT"
    assert normalize_type("lavadora") is None


def test_service_override_wins_and_unidentified_report_round_trip(tmp_path):
    service = make_service(tmp_path)
    service.begin_scan()
    mystery = HostFacts(ip="10.0.0.9", mac="02:11:22:33:44:55", vendor="Desconocido",
                        open_ports=[8081])
    assert service.identify(mystery).device_type == "UNKNOWN"
    assert service.finish_scan() == 1

    path = tmp_path / "unidentified_devices.csv"
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig", newline="")))
    assert rows[0]["ip"] == "10.0.0.9" and rows[0]["open_ports"] == "8081"
    rows[0].update(manual_type="Impresora", manual_vendor="Acme", manual_model="X1")
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    service.begin_scan()
    identity = service.identify(mystery)
    assert identity.device_type == "PRINTER"
    assert identity.vendor == "Acme" and identity.model == "X1"
    assert identity.source == "override"
    assert service.finish_scan() == 0


def test_failing_driver_does_not_abort_identification(tmp_path):
    class Broken:
        name, priority, debug_dir = "broken", 1, None

        def begin_scan(self):
            raise RuntimeError("boom")

        def matches(self, facts):
            return True

        def probe(self, facts):
            raise RuntimeError("boom")

    registry = _builtin()
    registry.register(Broken())
    service = make_service(tmp_path, registry)
    service.begin_scan()
    host = HostFacts(ip="10.0.0.2", hostname="NPI1A2B3C")
    assert service.identify(host).device_type == "PRINTER"


def test_network_vendor_with_telnet_is_a_low_confidence_switch(tmp_path):
    service = make_service(tmp_path)
    service.begin_scan()
    host = HostFacts(ip="192.168.48.83", mac="D8:94:03:C2:73:91",
                     vendor="Hewlett Packard Enterprise", open_ports=[23, 80])
    identity = service.identify(host)
    assert identity.device_type == "SWITCH"
    assert identity.confidence == "low"
    web_only = HostFacts(ip="192.168.48.84", mac="D8:94:03:C2:73:92",
                         vendor="Hewlett Packard Enterprise", open_ports=[80])
    assert service.identify(web_only).device_type == "UNKNOWN"
