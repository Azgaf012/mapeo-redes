import pkt_core

from services.packet_tracer_export import build_packet_tracer


def test_export_keeps_infrastructure_and_drops_client_devices(monkeypatch):
    added = []
    links = []

    class RecordingLab:
        def drop_seed_devices(self):
            pass

        def add_device(self, model, name, **position):
            added.append(name)
            return name

        def link(self, source, source_port, target, target_port):
            links.append((source, target))

        def auto_layout(self):
            pass

        def save(self, path):
            path.write_bytes(b"test-pkt")

    monkeypatch.setattr(pkt_core, "Lab", RecordingLab)
    types = ["SWITCH", "CAMERA", "NVR", "ACCESS_POINT", "PC", "LAPTOP", "PHONE",
             "WIFI_CLIENT", "SMART_TV", "UNKNOWN"]
    elements = [{"group": "nodes", "data": {
        "id": kind, "kind": "device", "device_type": kind,
    }} for kind in types]
    elements += [{"group": "edges", "data": {
        "source": "SWITCH", "target": kind, "discovery_method": "LLDP",
    }} for kind in ["CAMERA", "PC", "UNKNOWN"]]

    assert build_packet_tracer(elements) == b"test-pkt"
    assert added == ["SWITCH SWITCH", "CAMERA CAMERA", "NVR NVR", "ACCESS_POINT ACCESS_POINT"]
    assert links == [("SWITCH SWITCH", "CAMERA CAMERA")]
