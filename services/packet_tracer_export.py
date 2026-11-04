"""Generate a Packet Tracer lab from the observed physical topology."""

from collections import deque
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.classifier import IDENTIFIED_INFRASTRUCTURE_TYPES

MODELS = {
    "SWITCH": ("2960-24TT", tuple(f"FastEthernet0/{port}" for port in range(1, 25))),
    "ROUTER": ("2911", ("GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2")),
}
GENERIC = ("PC-PT", ("FastEthernet0",))


def build_packet_tracer(elements):
    from pkt_core import Lab

    lab = Lab()
    lab.drop_seed_devices()
    devices = {}
    ports = {}
    nodes = [item["data"] for item in elements
             if item["group"] == "nodes" and item["data"].get("kind") == "device"
             and item["data"].get("device_type") in IDENTIFIED_INFRASTRUCTURE_TYPES]
    for index, node in enumerate(nodes):
        device_id = node["id"]
        device_type = node["device_type"]
        model, interfaces = MODELS.get(device_type, GENERIC)
        name = f"{device_type} {node.get('ip') or device_id}"
        devices[device_id] = lab.add_device(model, name, x=150 + index % 10 * 125,
                                            y=100 + index // 10 * 95)
        ports[device_id] = deque(interfaces)

    linked_pairs = set()
    for item in elements:
        edge = item["data"]
        if item["group"] != "edges" or edge.get("discovery_method") not in {"LLDP", "CDP", "MANUAL"}:
            continue
        if edge.get("connection_type") == "WIFI":
            continue
        source, target = edge["source"], edge["target"]
        pair = frozenset((source, target))
        if source == target or pair in linked_pairs or source not in devices or target not in devices:
            continue
        if ports[source] and ports[target]:
            lab.link(devices[source], ports[source].popleft(), devices[target], ports[target].popleft())
            linked_pairs.add(pair)

    if linked_pairs:
        lab.auto_layout()
    with TemporaryDirectory() as directory:
        output = Path(directory) / "topology.pkt"
        lab.save(output)
        return output.read_bytes()
