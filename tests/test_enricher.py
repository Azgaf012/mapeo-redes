import json
from scanner.enricher import (
    format_open_ports_summary,
    evaluate_security_status,
    detect_os_info,
    SERVICE_CATALOG
)
from scanner.ping import PingResult, SweepResult

def test_ping_result_behavior():
    res_alive = PingResult(alive=True, latency_ms=1.8, ttl=64)
    assert bool(res_alive) is True
    assert res_alive.latency_ms == 1.8
    assert res_alive.ttl == 64

    # Tuple unpacking check
    alive, lat, ttl = res_alive
    assert alive is True and lat == 1.8 and ttl == 64

    res_dead = PingResult(alive=False, latency_ms=0.0, ttl=0)
    assert bool(res_dead) is False

def test_sweep_result_behavior():
    ips = ["192.168.1.1", "192.168.1.5"]
    details = {
        "192.168.1.1": {"latency_ms": 1.2, "ttl": 64},
        "192.168.1.5": {"latency_ms": 15.0, "ttl": 128}
    }
    sweep = SweepResult(ips, details=details)
    assert len(sweep) == 2
    assert "192.168.1.1" in sweep
    assert sweep.details["192.168.1.5"]["ttl"] == 128

def test_format_open_ports_summary():
    ports = [80, 443, 8001]
    res_json = format_open_ports_summary(ports)
    items = json.loads(res_json)
    assert len(items) == 3
    port_nums = [i["port"] for i in items]
    assert port_nums == [80, 443, 8001]
    assert items[0]["name"] == "HTTP"
    assert items[2]["name"] == "Samsung TV API"

def test_evaluate_security_status():
    # Telnet should trigger CRITICAL
    assert evaluate_security_status([23, 80]) == "CRITICAL"

    # FTP should trigger CRITICAL
    assert evaluate_security_status([21]) == "CRITICAL"

    # RDP or NetBIOS should trigger WARNING
    assert evaluate_security_status([3389, 443]) == "WARNING"
    assert evaluate_security_status([139]) == "WARNING"

    # Standard web and DNS should be SECURE
    assert evaluate_security_status([80, 443, 53, 22]) == "SECURE"

def test_detect_os_info():
    # Smart TVs
    assert "Tizen" in detect_os_info(open_ports=[8001], device_type="SMART_TV")
    assert "Roku" in detect_os_info(open_ports=[8060], device_type="SMART_TV")
    assert "webOS" in detect_os_info(open_ports=[3000], device_type="SMART_TV")

    # Windows Workstations and Servers
    assert "Windows Server" in detect_os_info(open_ports=[445], hostname="SRV-ACAD-01")
    assert "Windows" in detect_os_info(open_ports=[445], hostname="PC-AULA1")
    assert "Windows" in detect_os_info(ttl=128)

    # Linux / Embedded Network Firmware
    assert "Linux" in detect_os_info(ttl=64)
    assert "FortiOS" in detect_os_info(device_type="FIREWALL", vendor="Fortinet")
    assert "Cisco IOS" in detect_os_info(device_type="SWITCH", vendor="Cisco Systems")

    # Mobile Phones
    assert "iOS" in detect_os_info(device_type="PHONE", vendor="Apple, Inc.")
    assert "Android" in detect_os_info(device_type="PHONE", vendor="Xiaomi")
