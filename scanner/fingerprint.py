import socket
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import psutil
from scanner.classifier import is_access_point_identity

# Specific TV & media streaming ports
TV_PORTS = {
    8001: "Samsung Tizen Smart TV API",
    8002: "Samsung Tizen WebSocket API",
    8008: "Google Cast / Android TV",
    8009: "Google Cast TLS",
    8060: "Roku External Control Protocol",
    3000: "LG webOS TV Remote",
    7000: "Apple AirPlay Video",
    5000: "Apple AirPlay Audio",
    9000: "Sony Bravia / Philips TV API"
}


class _NoDeviceRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _open_device_url(request, timeout_s, secure=False):
    """Probe the device itself, without a system proxy or redirect to another host."""
    handlers = [urllib.request.ProxyHandler({}), _NoDeviceRedirect()]
    if secure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout_s)


def _web_response_details(response, port):
    details = {"port": port}
    status = getattr(response, "status", None) or getattr(response, "code", None)
    if status is not None:
        details["status"] = status
    headers = getattr(response, "headers", None)
    if headers:
        for header, key in (("Server", "server"), ("Content-Type", "content_type")):
            value = headers.get(header)
            if value:
                details[key] = value[:120]
        location = headers.get("Location")
        if location:
            target = urllib.parse.urlsplit(location)
            if target.hostname:
                details["redirect_host"] = target.hostname
                if target.port:
                    details["redirect_port"] = target.port
            elif target.path:
                details["redirect_path"] = target.path[:80]
    return details


def _read_web_html(response, probe):
    try:
        return response.read(8192).decode("utf-8", errors="ignore")
    except Exception as exc:
        probe["body_error"] = exc.__class__.__name__
        return ""

def query_netbios_name(ip, timeout_s=0.4):
    """Sends a NetBIOS Node Status request (UDP 137) to obtain the computer name."""
    query = (
        b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) > 56:
            num_names = data[56]
            for i in range(min(num_names, 8)):
                offset = 57 + (i * 18)
                if offset + 15 <= len(data):
                    name = data[offset : offset + 15].decode("latin1", errors="ignore").strip()
                    name_clean = re.sub(r"[^\w\-]", "", name)
                    if name_clean and not name_clean.startswith("IS~") and name_clean != "WORKGROUP":
                        return name_clean
    except Exception:
        pass
    finally:
        sock.close()
    return None

def grab_http_title_and_model(ip, open_ports, timeout_s=0.6):
    """
    Probes open web and TV ports to extract device title, model, and metadata.
    """
    candidate_ports = [p for p in open_ports if p in [80, 443, 8443, 8001, 8008, 8060, 8080, 3000, 5000, 7000]]
    if not candidate_ports:
        return {}

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10) NetMapper/1.0"}

    # 1. Check Roku ECP (port 8060)
    if 8060 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:8060/query/device-info", headers=headers)
            with _open_device_url(req, timeout_s) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                m_model = re.search(r"<model-name>([^<]+)</model-name>", content)
                m_friendly = re.search(r"<user-device-name>([^<]+)</user-device-name>", content)
                model_name = m_model.group(1).strip() if m_model else "Roku Streaming Device"
                friendly = m_friendly.group(1).strip() if m_friendly else "Roku TV"
                return {
                    "device_type": "SMART_TV",
                    "model": model_name,
                    "hostname": friendly
                }
        except Exception:
            return {"device_type": "SMART_TV", "model": "Roku Player"}

    # 2. Check Samsung Smart TV (port 8001)
    if 8001 in open_ports or 8002 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:8001/api/v2/", headers=headers)
            with _open_device_url(req, timeout_s) as resp:
                import json
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                dev = data.get("device", {})
                name = dev.get("name") or dev.get("modelName") or "Samsung Smart TV"
                return {
                    "device_type": "SMART_TV",
                    "model": dev.get("modelName") or "Samsung Tizen TV",
                    "hostname": name
                }
        except Exception:
            return {"device_type": "SMART_TV", "model": "Samsung Smart TV"}

    # 3. Check Google Cast / Android TV (port 8008)
    if 8008 in open_ports or 8009 in open_ports:
        try:
            req = urllib.request.Request(f"http://{ip}:8008/setup/eureka_info", headers=headers)
            with _open_device_url(req, timeout_s) as resp:
                import json
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                name = data.get("name") or "Google Cast Device"
                model = data.get("model_name") or "Android TV / Chromecast"
                return {
                    "device_type": "SMART_TV",
                    "model": model,
                    "hostname": name
                }
        except Exception:
            return {"device_type": "SMART_TV", "model": "Google Cast / Android TV"}

    # 4. Device web titles, including local self-signed HTTPS management pages.
    first_web_title = {}
    web_probes = []
    classification = {}
    for port in [443, 8443, 80, 8080]:
        if port in open_ports:
            secure = port in (443, 8443)
            scheme = "https" if secure else "http"
            req = urllib.request.Request(f"{scheme}://{ip}:{port}/", headers=headers)
            try:
                with _open_device_url(req, timeout_s, secure=secure) as resp:
                    probe = _web_response_details(resp, port)
                    html = _read_web_html(resp, probe)
            except urllib.error.HTTPError as exc:
                probe = _web_response_details(exc, port)
                html = _read_web_html(exc, probe)
            except Exception as exc:
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
                probe = {"port": port, "error": reason.__class__.__name__}
                html = ""

            web_probes.append(probe)
            m_title = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
            title = m_title.group(1).strip() if m_title else ""
            web_evidence = {"web_title": title[:200], "web_port": port} if title else {}
            if web_evidence and not first_web_title:
                first_web_title = web_evidence

            # Aruba APs may redirect to management on 4343; the port does not identify the platform.
            if (probe.get("status") in (301, 302, 303, 307, 308)
                    and probe.get("redirect_port") == 4343
                    and "arubanetworks.com" in html.lower()):
                probe["aruba_marker"] = True
                if not classification:
                    classification = {"device_type": "ACCESS_POINT", "model": "Aruba AP (modelo sin confirmar)",
                                      **web_evidence}

            t_low = title.lower()
            if not classification and any(w in t_low for w in ["tv", "webos", "bravia", "tizen", "roku", "chromecast"]):
                classification = {"device_type": "SMART_TV", "model": title[:60], **web_evidence}
            elif not classification and title and is_access_point_identity(snmp_info={"model": title}):
                classification = {"device_type": "ACCESS_POINT", "model": title[:60], **web_evidence}
            elif not classification and any(w in t_low for w in ["router", "wireless", "gateway", "tp-link", "mikrotik", "d-link", "netgear", "asus", "zte", "huawei"]):
                classification = {"device_type": "ROUTER", "model": title[:60], **web_evidence}
            elif not classification and any(w in t_low for w in ["printer", "laserjet", "deskjet", "epson", "brother", "kyocera", "xerox", "canon"]):
                classification = {"device_type": "PRINTER", "model": title[:60], **web_evidence}
            elif not classification and any(w in t_low for w in ["camera", "hikvision", "dahua", "nvr", "dvr", "ip camera", "web service"]):
                classification = {"device_type": "CAMERA", "model": title[:60], **web_evidence}

    return {**first_web_title, **classification, "web_probes": web_probes}

def fingerprint_device(ip, mac="", hostname="", vendor="", open_ports=None, is_gateway=False, is_local=False, snmp_info=None, diagnostics=None):
    """
    Executes deep fingerprinting combining HTTP banners, NetBIOS, TV ports, battery status, and heuristics.
    Returns: (device_type, updated_hostname, updated_model)
    """
    ports = set(open_ports or [])
    h = hostname or ""
    m = ""

    # 1. Local scanning computer inspection (Battery sensor -> LAPTOP vs PC)
    if is_local:
        has_battery = False
        try:
            batt = psutil.sensors_battery()
            has_battery = bool(batt)
        except Exception:
            pass

        dev_type = "LAPTOP" if has_battery else "PC"
        return dev_type, h or socket.gethostname(), ("Laptop con Batería" if has_battery else "Computadora de Escritorio")

    # 2. Check Gateway / Router
    if is_gateway:
        v_low = (vendor or "").lower()
        if any(f in v_low for f in ["fortinet", "palo alto", "sonicwall", "sophos", "checkpoint"]):
            return "FIREWALL", h, "Firewall / Gateway Perimetral"
        return "ROUTER", h, f"Router Gateway ({vendor or 'Genérico'})"

    if is_access_point_identity(h, snmp_info):
        info = snmp_info or {}
        return "ACCESS_POINT", h or info.get("sys_name") or "", info.get("model") or "Punto de acceso"

    # 3. Query NetBIOS name for Windows PCs / Laptops
    nb_name = query_netbios_name(ip)
    if nb_name:
        h = nb_name
        nb_low = nb_name.lower()
        if any(nb_low.startswith(p) for p in ["laptop-", "notebook-", "macbook", "thinkpad"]):
            return "LAPTOP", h, "Laptop Windows/Mac"
        if any(nb_low.startswith(p) for p in ["desktop-", "pc-", "workstation-"]):
            return "PC", h, "Computadora de Escritorio"

    # 4. Probe TV-specific ports & HTTP Titles (Roku, Samsung, Google Cast, webOS, AirPlay)
    http_fp = grab_http_title_and_model(ip, ports)
    if diagnostics is not None:
        diagnostics.update({key: http_fp[key] for key in ("web_title", "web_port", "web_probes") if key in http_fp})
    if http_fp.get("device_type") == "SMART_TV":
        return "SMART_TV", http_fp.get("hostname") or h, http_fp.get("model") or "Smart TV / Streaming"
    elif http_fp.get("device_type"):
        return http_fp["device_type"], http_fp.get("hostname") or h, http_fp.get("model") or ""

    # 5. Check TV ports
    if any(p in ports for p in [8001, 8002, 3000, 8060, 8008, 8009, 7000]):
        return "SMART_TV", h, "Smart TV / Media Player"

    # 6. Check Vendor-based TV detection (Roku, Amazon FireTV, Gaoshengda, TCL, Hisense)
    v_low = (vendor or "").lower()
    if any(tv in v_low for tv in ["roku", "gaoshengda", "hisense", "tcl", "skyworth", "vizio"]):
        return "SMART_TV", h or "Smart TV", f"Smart TV ({vendor})"
    if "amazon" in v_low and not any(p in ports for p in [135, 445, 3389]):
        return "SMART_TV", h or "Fire TV / Echo", "Amazon Media Device"

    # 7. Check PC / Laptop Ports (SMB, RDP, NetBIOS)
    if 445 in ports or 139 in ports or 135 in ports or 3389 in ports:
        h_low = h.lower()
        if any(w in h_low for w in ["laptop", "notebook", "macbook"]):
            return "LAPTOP", h, "Laptop"
        if any(w in h_low for w in ["srv", "server", "dc0", "sql"]):
            return "SERVER", h, "Servidor"
        return "PC", h, "Computadora Personal"

    # 8. Check Printers
    if any(p in ports for p in [9100, 515, 631]) or any(prn in v_low for prn in ["epson", "brother", "kyocera", "canon", "xerox"]):
        return "PRINTER", h, f"Impresora ({vendor})"

    # 9. Check Cameras / NVR
    if 554 in ports or any(cam in v_low for cam in ["hikvision", "dahua"]):
        return "CAMERA", h, f"Cámara IP ({vendor})"

    # 10. Check Smartphones / Mobile Phones
    # If device uses randomized MAC, or vendor is Xiaomi/Oppo/Vivo/Apple/Samsung and has no PC/server ports
    if any(mfg in v_low for mfg in ["xiaomi", "oppo", "vivo", "oneplus", "motorola", "realme"]):
        return "PHONE", h or f"Smartphone {vendor}", f"Teléfono Móvil ({vendor})"

    if "apple" in v_low and not any(p in ports for p in [135, 445, 3389, 22]):
        h_low = h.lower()
        if "iphone" in h_low:
            return "PHONE", h, "Apple iPhone"
        if "ipad" in h_low:
            return "PHONE", h, "Apple iPad"
        if "macbook" in h_low:
            return "LAPTOP", h, "Apple MacBook"
        return "PHONE", h, "Dispositivo Apple (iPhone/iPad)"

    if "samsung" in v_low and not any(p in ports for p in [8001, 8002, 135, 445]):
        return "PHONE", h or "Samsung Galaxy", "Teléfono Samsung Galaxy"

    return "UNKNOWN", h, ""
