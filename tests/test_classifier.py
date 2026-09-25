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

    # A switch description is evidence; the Cisco vendor alone is not.
    dev_type = classify_device("192.168.1.2", open_ports=[161, 22], vendor="Cisco",
                               snmp_info={"sys_descr": "Cisco Catalyst 2960 Switch"})
    assert dev_type == "SWITCH"
    assert classify_device("192.168.1.2", open_ports=[161], vendor="Cisco") == "UNKNOWN"
    assert classify_device("192.168.1.3", vendor="Aruba, a Hewlett Packard Enterprise Company") == "UNKNOWN"
    assert classify_device("192.168.1.4", vendor="Ubiquiti Networks") == "UNKNOWN"
    assert classify_device("192.168.1.5", hostname="UniFi-USW-24") == "UNKNOWN"

    # SMB Workstation
    dev_type = classify_device("192.168.1.100", open_ports=[445], vendor="Dell")
    assert dev_type == "PC"

def test_classify_by_snmp_sysdescr():
    dev_type = classify_device("192.168.1.10", snmp_info={"sys_descr": "Cisco Catalyst 3850 Series Switch"})
    assert dev_type == "SWITCH"

    dev_type = classify_device("192.168.1.20", snmp_info={"sys_descr": "UniFi AP-AC-Pro 4.3.24"})
    assert dev_type == "ACCESS_POINT"


def test_access_point_identity_wins_over_generic_snmp_switch_heuristic(monkeypatch):
    import scanner.fingerprint as fingerprint
    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)
    monkeypatch.setattr(fingerprint, "grab_http_title_and_model", lambda ip, ports, timeout_s=0.6: {})
    samples = [
        {"sys_descr": "Cisco Aironet 1830 Access Point", "sys_name": "AP-LIBRARY"},
        {"sys_descr": "Aruba Instant AP-515", "sys_name": "WIFI-PISO-2"},
        {"sys_descr": "Ubiquiti UniFi UAP-AC-Pro", "sys_name": "UAP-AC-PRO"},
    ]
    for snmp in samples:
        result = fingerprint.fingerprint_device("10.0.0.8", vendor="Cisco",
                                               open_ports=[161, 80], snmp_info=snmp)
        assert result[0] == "ACCESS_POINT"
        assert classify_device("10.0.0.8", vendor="Cisco", open_ports=[161],
                               snmp_info=snmp) == "ACCESS_POINT"

    assert classify_device("10.0.0.10", hostname="device.local", vendor="Cisco",
                           snmp_info={"sys_name": "AP-LIBRARY"}) == "ACCESS_POINT"

    switch = {"sys_descr": "Ubiquiti UniFi Switch USW-24", "sys_name": "SW-CORE"}
    assert fingerprint.fingerprint_device("10.0.0.9", vendor="Ubiquiti",
                                          open_ports=[161], snmp_info=switch)[0] == "UNKNOWN"
    assert classify_device("10.0.0.9", vendor="Ubiquiti",
                           open_ports=[161], snmp_info=switch) == "SWITCH"


def test_hpe_access_point_is_identified_from_https_title(monkeypatch):
    from scanner import fingerprint

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b"<html><title>Aruba AP-505 Access Point</title></html>"

    def fake_urlopen(request, timeout_s, secure=False):
        assert request.full_url == "https://192.168.50.55:443/"
        assert secure
        return Response()

    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)
    monkeypatch.setattr(fingerprint, "_open_device_url", fake_urlopen)
    diagnostics = {}
    result = fingerprint.fingerprint_device(
        "192.168.50.55", mac="24:F2:7F:CF:A8:56",
        vendor="Hewlett Packard Enterprise", open_ports=[443],
        diagnostics=diagnostics)
    assert result[0] == "ACCESS_POINT"
    assert "AP-505" in result[2]
    assert diagnostics == {"web_title": "Aruba AP-505 Access Point", "web_port": 443,
                           "web_probes": [{"port": 443}]}


def test_unrecognized_web_title_is_available_for_later_review(monkeypatch):
    from scanner import fingerprint

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b"<html><title>Device Management Console</title></html>"

    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)
    monkeypatch.setattr(fingerprint, "_open_device_url", lambda *args, **kwargs: Response())
    diagnostics = {}
    result = fingerprint.fingerprint_device("192.168.50.55", open_ports=[443],
                                            diagnostics=diagnostics)
    assert result[0] == "UNKNOWN"
    assert diagnostics == {"web_title": "Device Management Console", "web_port": 443,
                           "web_probes": [{"port": 443}]}


def test_aruba_controller_redirect_identifies_ap_and_records_other_web_ports(monkeypatch):
    import io
    import urllib.error
    from scanner import fingerprint

    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)
    requested_ports = []

    def fake_open(request, timeout_s, secure=False):
        port = 443 if secure else int(request.full_url.split(":")[2].split("/")[0])
        requested_ports.append(port)
        if port == 8080:
            raise urllib.error.HTTPError(request.full_url, 403, "Access denied",
                                         {"Server": "tinyproxy/1.8.2"},
                                         io.BytesIO(b"<title>403 Access denied</title>"))
        raise urllib.error.HTTPError(
            request.full_url, 302, "Found",
            {"Location": "https://192.168.50.13:4343/", "Content-Type": "text/html"},
            io.BytesIO(b"<TITLE>302 </TITLE><A HREF='http://www.arubanetworks.com'></A>"),
        )

    monkeypatch.setattr(fingerprint, "_open_device_url", fake_open)
    diagnostics = {}
    result = fingerprint.fingerprint_device(
        "192.168.50.55", vendor="Hewlett Packard Enterprise",
        open_ports=[22, 80, 443, 8080], diagnostics=diagnostics)
    assert result[0] == "ACCESS_POINT"
    assert result[2] == "Aruba Instant AP"
    assert requested_ports == [443, 80, 8080]
    assert diagnostics["web_probes"][0] == {
        "port": 443, "status": 302, "content_type": "text/html",
        "redirect_host": "192.168.50.13", "redirect_port": 4343,
        "aruba_marker": True,
    }
    assert diagnostics["web_probes"][2] == {
        "port": 8080, "status": 403, "server": "tinyproxy/1.8.2",
    }


def test_redirect_to_4343_alone_does_not_imply_access_point(monkeypatch):
    import io
    import urllib.error
    from scanner import fingerprint

    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)

    def fake_open(request, timeout_s, secure=False):
        raise urllib.error.HTTPError(
            request.full_url, 302, "Found", {"Location": "https://192.168.50.13:4343/"},
            io.BytesIO(b"<title>302</title>"),
        )

    monkeypatch.setattr(fingerprint, "_open_device_url", fake_open)
    assert fingerprint.fingerprint_device("192.168.50.55", open_ports=[80])[0] == "UNKNOWN"


def test_web_probe_bypasses_proxy_and_keeps_redirect_on_device(monkeypatch):
    from scanner import fingerprint

    handlers_seen = []

    class Opener:
        def open(self, request, timeout):
            return "response"

    def fake_build_opener(*handlers):
        handlers_seen.extend(handlers)
        return Opener()

    monkeypatch.setattr(fingerprint.urllib.request, "build_opener", fake_build_opener)
    request = fingerprint.urllib.request.Request("http://192.168.50.55/")
    assert fingerprint._open_device_url(request, 0.6) == "response"
    assert any(isinstance(h, fingerprint.urllib.request.ProxyHandler) and not h.proxies
               for h in handlers_seen)
    assert any(isinstance(h, fingerprint._NoDeviceRedirect) for h in handlers_seen)


def test_hpe_vendor_and_mac_alone_do_not_imply_ap(monkeypatch):
    from scanner import fingerprint
    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)
    assert fingerprint.fingerprint_device(
        "192.168.50.55", mac="24:F2:7F:CF:A8:56",
        vendor="Hewlett Packard Enterprise", open_ports=[])[0] == "UNKNOWN"
    assert fingerprint.fingerprint_device(
        "192.168.50.13", vendor="Aruba, a Hewlett Packard Enterprise Company",
        open_ports=[])[0] == "UNKNOWN"

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

    # A private MAC does not identify the device as a phone.
    assert classify_device("192.168.1.43", vendor="MAC privada/aleatoria") == "UNKNOWN"
    assert classify_device("192.168.1.43", vendor="Dispositivo Móvil (MAC Privada)") == "UNKNOWN"

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

def test_fingerprint_phone(monkeypatch):
    from scanner import fingerprint
    monkeypatch.setattr(fingerprint, "query_netbios_name", lambda ip: None)

    # Randomized MACs can belong to many types of equipment.
    dev_type, name, model = fingerprint_device("192.168.1.70", vendor="Dispositivo Móvil (MAC Privada)")
    assert dev_type == "UNKNOWN"

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
