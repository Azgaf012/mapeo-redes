from scanner.classifier import classify_device

def test_classify_gateway():
    # Gateway standard router
    dev_type = classify_device("192.168.1.1", is_gateway=True, vendor="TP-Link")
    assert dev_type == "ROUTER"

    # Gateway firewall
    dev_type = classify_device("192.168.1.1", is_gateway=True, vendor="Fortinet")
    assert dev_type == "FIREWALL"

def test_classify_by_ports():
    # RTSP Camera
    dev_type = classify_device("192.168.1.50", open_ports=[554, 80], vendor="Hikvision")
    assert dev_type == "CAMERA"

    # JetDirect Printer
    dev_type = classify_device("192.168.1.60", open_ports=[9100], vendor="Epson")
    assert dev_type == "PRINTER"

    # SNMP Cisco Switch
    dev_type = classify_device("192.168.1.2", open_ports=[161, 22], vendor="Cisco")
    assert dev_type == "SWITCH"

    # SMB Workstation
    dev_type = classify_device("192.168.1.100", open_ports=[445], vendor="Dell")
    assert dev_type == "PC"

def test_classify_by_snmp_sysdescr():
    dev_type = classify_device("192.168.1.10", snmp_info={"sys_descr": "Cisco Catalyst 3850 Series Switch"})
    assert dev_type == "SWITCH"

    dev_type = classify_device("192.168.1.20", snmp_info={"sys_descr": "UniFi AP-AC-Pro 4.3.24"})
    assert dev_type == "ACCESS_POINT"

def test_classify_by_hostname():
    assert classify_device("192.168.1.3", hostname="SW-PISO2") == "SWITCH"
    assert classify_device("192.168.1.4", hostname="AP-AULA-101") == "ACCESS_POINT"
    assert classify_device("192.168.1.5", hostname="SRV-ACADEMICO") == "SERVER"
    assert classify_device("192.168.1.6", hostname="PRN-DIRECCION") == "PRINTER"

def test_classify_smart_tv_and_phone():
    # Samsung TV via port 8001
    assert classify_device("192.168.1.40", open_ports=[8001]) == "SMART_TV"

    # Roku TV via port 8060
    assert classify_device("192.168.1.41", open_ports=[8060]) == "SMART_TV"

    # Roku by vendor
    assert classify_device("192.168.1.42", vendor="Roku, Inc.") == "SMART_TV"

    # Phone by randomized / private MAC
    assert classify_device("192.168.1.43", vendor="Dispositivo Móvil (MAC Privada)") == "PHONE"

    # Phone by mobile brand
    assert classify_device("192.168.1.44", vendor="Xiaomi Communications") == "PHONE"

from scanner.fingerprint import fingerprint_device

def test_fingerprint_smart_tv():
    # TV port detection
    dev_type, name, model = fingerprint_device("192.168.1.50", open_ports=[8001, 8002])
    assert dev_type == "SMART_TV"

    # Roku vendor detection
    dev_type, name, model = fingerprint_device("192.168.1.51", vendor="Roku, Inc.")
    assert dev_type == "SMART_TV"
    assert "Roku" in model

    # Amazon FireTV detection
    dev_type, name, model = fingerprint_device("192.168.1.52", vendor="Amazon Technologies Inc.")
    assert dev_type == "SMART_TV"

def test_fingerprint_phone():
    # Randomized MAC
    dev_type, name, model = fingerprint_device("192.168.1.70", vendor="Dispositivo Móvil (MAC Privada)")
    assert dev_type == "PHONE"

    # Apple iPhone/iPad without PC ports
    dev_type, name, model = fingerprint_device("192.168.1.71", vendor="Apple, Inc.", hostname="iPhone-de-Carlos")
    assert dev_type == "PHONE"

    # Xiaomi Smartphone
    dev_type, name, model = fingerprint_device("192.168.1.72", vendor="Xiaomi")
    assert dev_type == "PHONE"

def test_fingerprint_local_laptop():
    # Local scanning device inspection
    dev_type, name, model = fingerprint_device("127.0.0.1", is_local=True)
    assert dev_type in ["LAPTOP", "PC"]
    assert len(name) > 0
