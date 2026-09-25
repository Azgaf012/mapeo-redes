import socket
import re
import urllib.request
import xml.etree.ElementTree as ET
from scanner.network import detect_network_config

def probe_ssdp():
    net = detect_network_config()
    local_ip = net["local_ip"]
    print(f"Binding SSDP socket to Wi-Fi IP: {local_ip}")

    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 2\r\n'
        'ST: ssdp:all\r\n\r\n'
    ).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(2.5)
    # Bind to Wi-Fi IP
    sock.bind((local_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))

    devices = {}
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                if ip not in devices:
                    loc_match = re.search(r"LOCATION:\s*(http[^\r\n]+)", text, re.IGNORECASE)
                    server_match = re.search(r"SERVER:\s*([^\r\n]+)", text, re.IGNORECASE)
                    devices[ip] = {
                        "location": loc_match.group(1).strip() if loc_match else None,
                        "server": server_match.group(1).strip() if server_match else None
                    }
            except socket.timeout:
                break
    finally:
        sock.close()

    print(f"SSDP discovered {len(devices)} devices:")
    for ip, info in devices.items():
        print(f"  [{ip}] Location: {info['location']} | Server: {info['server']}")
        if info["location"]:
            try:
                req = urllib.request.Request(info["location"], headers={"User-Agent": "NetMapper/1.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    xml_data = resp.read()
                    root = ET.fromstring(xml_data)
                    friendly = root.find(".//{urn:schemas-upnp-org:device-1-0}friendlyName")
                    if friendly is None:
                        friendly = root.find(".//friendlyName")
                    model = root.find(".//{urn:schemas-upnp-org:device-1-0}modelName")
                    if model is None:
                        model = root.find(".//modelName")
                    dev_type = root.find(".//{urn:schemas-upnp-org:device-1-0}deviceType")
                    if dev_type is None:
                        dev_type = root.find(".//deviceType")
                    f_text = friendly.text if friendly is not None else "-"
                    m_text = model.text if model is not None else "-"
                    t_text = dev_type.text if dev_type is not None else "-"
                    print(f"     -> Friendly: {f_text} | Model: {m_text} | Type: {t_text}")
            except Exception as e:
                print(f"     -> (XML fetch error: {e})")

if __name__ == "__main__":
    probe_ssdp()
