const MAP_DEVICE_TYPES = {
    ROUTER: { label: "Router", color: "#b45309", shape: '<rect x="3" y="9" width="18" height="10" rx="2"/><path d="M7 9V5m10 4V5M5 15h.01M9 15h.01M13 15h.01M17 15h.01"/>' },
    FIREWALL: { label: "Firewall", color: "#b91c1c", shape: '<path d="M12 2 20 5v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5z"/><path d="M8 10h8M8 14h8M12 10v4"/>' },
    SWITCH: { label: "Switch", color: "#0e7490", shape: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M5 10h2v3H5zm4 0h2v3H9zm4 0h2v3h-2zm4 0h2v3h-2zM5 16h14"/>' },
    ACCESS_POINT: { label: "Punto de acceso", color: "#047857", shape: '<circle cx="12" cy="18" r="2"/><path d="M7.5 13.5a6.5 6.5 0 0 1 9 0M4.5 10.5a10.5 10.5 0 0 1 15 0"/>' },
    SERVER: { label: "Servidor", color: "#4338ca", shape: '<rect x="4" y="3" width="16" height="5" rx="1"/><rect x="4" y="10" width="16" height="5" rx="1"/><rect x="4" y="17" width="16" height="5" rx="1"/><path d="M7 5.5h.01M7 12.5h.01M7 19.5h.01M11 5.5h6M11 12.5h6M11 19.5h6"/>' },
    PC: { label: "Computador", color: "#1d4ed8", shape: '<rect x="3" y="4" width="18" height="13" rx="1"/><path d="M9 21h6m-3-4v4"/>' },
    LAPTOP: { label: "Portátil", color: "#1d4ed8", shape: '<rect x="5" y="4" width="14" height="12" rx="1"/><path d="m3 20 2-4h14l2 4z"/>' },
    PHONE: { label: "Teléfono", color: "#7c3aed", shape: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>' },
    WIFI_CLIENT: { label: "Cliente Wi-Fi", color: "#64748b", shape: '<path d="M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>' },
    PRINTER: { label: "Impresora", color: "#475569", shape: '<path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 15h12v7H6zM18 12h.01"/>' },
    CAMERA: { label: "Cámara", color: "#be185d", shape: '<rect x="3" y="5" width="15" height="13" rx="2"/><circle cx="10.5" cy="11.5" r="3"/><path d="m18 9 4-2v9l-4-2M8 21h5"/>' },
    SMART_TV: { label: "TV / multimedia", color: "#0369a1", shape: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M9 22h6m-3-3v3M9 2l3 3 3-3"/>' },
    NVR: { label: "Grabador NVR", color: "#6d28d9", shape: '<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="7" cy="12" r="2"/><path d="M12 11h7m-7 3h4"/>' },
    UPS: { label: "UPS", color: "#a16207", shape: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="m13 6-3 6h4l-3 6"/>' },
    CONTROLLER: { label: "Controlador", color: "#0f766e", shape: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M8 7v10m8-10v10M6 10h4m4 4h4"/>' },
    UNKNOWN: { label: "Sin identificar", color: "#475569", shape: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 4 2l-1.5 1.5V14M12 17h.01"/>' },
    network: { label: "Subred", color: "#122c4f", shape: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-3 3-3 15 0 18m0-18c3 3 3 15 0 18M5 7h14M5 17h14"/>' },
    gateway: { label: "Gateway configurado", color: "#b45309", shape: '<rect x="3" y="9" width="18" height="10" rx="2"/><path d="M7 9V5m10 4V5M5 15h.01M9 15h.01M13 15h.01M17 15h.01"/>' },
    vlan: { label: "VLAN", color: "#122c4f", shape: '<rect x="4" y="4" width="16" height="5" rx="1"/><rect x="4" y="10" width="16" height="5" rx="1"/><rect x="4" y="16" width="16" height="5" rx="1"/>' }
};

const mapIconCache = new Map();
const mapBadgeCache = new Map();
function mapDeviceInfo(type) {
    return Object.prototype.hasOwnProperty.call(MAP_DEVICE_TYPES, type)
        ? MAP_DEVICE_TYPES[type] : MAP_DEVICE_TYPES.UNKNOWN;
}
function mapIcon(type) {
    const key = Object.prototype.hasOwnProperty.call(MAP_DEVICE_TYPES, type) ? type : "UNKNOWN";
    if (!mapIconCache.has(key)) {
        const svg = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${MAP_DEVICE_TYPES[key].shape}</svg>`;
        mapIconCache.set(key, `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`);
    }
    return mapIconCache.get(key);
}
function mapCardBadge(type) {
    const key = Object.prototype.hasOwnProperty.call(MAP_DEVICE_TYPES, type) ? type : "UNKNOWN";
    if (!mapBadgeCache.has(key)) {
        const color = MAP_DEVICE_TYPES[key].color;
        const svg = `<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="38" height="38" viewBox="0 0 38 38"><rect x="1" y="1" width="36" height="36" rx="9" fill="${color}"/><g transform="translate(7,7)" fill="none" stroke="#ffffff" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round">${MAP_DEVICE_TYPES[key].shape}</g></svg>`;
        mapBadgeCache.set(key, `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`);
    }
    return mapBadgeCache.get(key);
}

function ipSortValue(ip) {
    const parts = String(ip || "").split(".").map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return Number.MAX_SAFE_INTEGER;
    return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256) + parts[3];
}

function cleanVendorName(vendor) {
    const v = String(vendor || "").trim();
    if (!v || v === "Desconocido" || v.startsWith("MAC privada") || v.startsWith("Dispositivo")) return "";
    if (/aruba/i.test(v)) return "Aruba";
    if (/hewlett packard|hpe|procurve/i.test(v)) return "HPE";
    if (/hikvision/i.test(v)) return "Hikvision";
    if (/tp-link/i.test(v)) return "TP-Link";
    if (/fortinet/i.test(v)) return "Fortinet";
    if (/ricoh/i.test(v)) return "Ricoh";
    return v.split(/[,(]/)[0].trim().slice(0, 16);
}

function cleanModelName(model, serial) {
    let m = String(model || "").trim();
    const s = String(serial || "").trim();
    if (/^\d+$/.test(m) && /^DS-/i.test(s)) {
        const hk = s.match(/^(DS-[A-Z0-9-]+?-[A-Z0-9/]+?)(?=20[12]\d|1620)/i);
        m = hk ? hk[1] : s.slice(0, 16);
    }
    if (!m || m === "0" || /modelo sin confirmar|Cámara IP \(|Impresora \(|Firewall \/ Gateway/i.test(m)) {
        return "";
    }
    return m.slice(0, 22);
}

function buildCardLabel(data) {
    if (data.kind === "network") {
        const extra = data.client_count ? `\n${data.client_count} clientes finales` : (data.gateway ? `\nGW ${data.gateway}` : "");
        return `Subred\n${data.name || data.label}${extra}`;
    }
    if (data.kind === "vlan") {
        return `${data.name || data.label}`;
    }
    if (data.kind === "type") {
        const info = mapDeviceInfo(data.name);
        return `Categoría\n${info.label}`;
    }
    if (data.kind === "gateway") {
        return `Gateway\n${data.ip || data.gateway || ""}`;
    }
    if (data.kind === "map_group") {
        return data.label || data.name || "";
    }
    const info = mapDeviceInfo(data.device_type);
    const vendor = cleanVendorName(data.vendor);
    const model = cleanModelName(data.model, data.serial_number);
    let rawHost = String(data.hostname || "").trim();
    if (rawHost && data.ip && rawHost.endsWith(" " + data.ip)) {
        rawHost = rawHost.slice(0, -(data.ip.length + 1)).trim();
    }
    if (/^HIKVISION\s+/i.test(rawHost)) {
        rawHost = rawHost.replace(/^HIKVISION\s+/i, "").split(" - ")[0].trim();
    }
    let title = (rawHost && rawHost !== data.ip) ? rawHost : "";
    if (!title) {
        if (model) title = model;
        else if (vendor) title = `${info.label} ${vendor}`;
        else title = info.label;
    }
    if (title.length > 21) title = title.slice(0, 20) + "…";

    const ipLine = data.ip || "";
    const metaParts = [];
    if (data.relationship_label) {
        metaParts.push(data.relationship_label);
    }
    if (data.uplink_port) {
        metaParts.push(`Pto ${data.uplink_port}`);
    }
    if (data.client_count > 0) {
        metaParts.push(`${data.client_count} cliente${data.client_count === 1 ? "" : "s"}${data.subnet_client_count ? " en red" : ""}`);
    } else if (model && model !== title) {
        metaParts.push(model);
    } else if (vendor && !title.toLowerCase().includes(vendor.toLowerCase())) {
        metaParts.push(vendor);
    }
    const metaLine = metaParts.join(" · ").slice(0, 25);
    return [title, ipLine, metaLine].filter(Boolean).join("\n");
}

function formatEdgeLabel(edgeData) {
    if (edgeData.discovery_method === "MAC_PORT") return `MAC · Pto ${edgeData.source_port}`;
    if (edgeData.discovery_method === "NVR_CHANNEL") return `Canal ${edgeData.channel}`;
    const srcPort = String(edgeData.source_port || "").trim();
    const dstPort = String(edgeData.target_port || "").trim();
    const cleanDst = (!dstPort || dstPort === "?" || /^0x[0-9a-f]{10,}$/i.test(dstPort) || dstPort === "bond0")
        ? "" : dstPort.replace(/^GigabitEthernet/i, "Gi").replace(/\s+Interface$/i, "");
    if (srcPort && cleanDst) return `Pto ${srcPort} → ${cleanDst}`;
    if (srcPort) return `Pto ${srcPort}`;
    return edgeData.evidence || "";
}

function buildArchitecturalPositions(elements, activeGroup) {
    const nodes = elements.filter(el => el.group === "nodes");
    const edges = elements.filter(el => el.group === "edges");
    const positions = {};
    const CARD_GAP_X = 212;
    const ROW_GAP_Y = 98;
    const TIER_GAP_Y = 136;
    const MAX_COLS = 6;

    const placeRows = (list, startY, cols = MAX_COLS, centerX = 0) => {
        if (!list.length) return startY;
        const totalRows = Math.ceil(list.length / cols);
        for (let r = 0; r < totalRows; r++) {
            const slice = list.slice(r * cols, (r + 1) * cols);
            const rowWidth = (slice.length - 1) * CARD_GAP_X;
            const y = startY + r * ROW_GAP_Y;
            slice.forEach((node, idx) => {
                positions[node.data.id] = {
                    x: Math.round(centerX - rowWidth / 2 + idx * CARD_GAP_X),
                    y: Math.round(y)
                };
            });
        }
        return startY + (totalRows - 1) * ROW_GAP_Y + TIER_GAP_Y;
    };

    if (activeGroup) {
        const memberSet = new Set(activeGroup.visibleMemberIds || []);
        const parentNodes = nodes.filter(n => n.data.id === activeGroup.parentId);
        const members = nodes.filter(n => memberSet.has(n.data.id));
        const others = nodes.filter(n => n.data.id !== activeGroup.parentId && !memberSet.has(n.data.id));
        let y = 0;
        if (parentNodes.length) y = placeRows(parentNodes, y, 4);
        if (members.length) y = placeRows(members, y, MAX_COLS);
        if (others.length) placeRows(others, y, MAX_COLS);
        return positions;
    }

    const physicalDegree = new Map();
    const parentsByChild = new Map();
    const addParent = (child, parent) => {
        if (!parentsByChild.has(child)) parentsByChild.set(child, new Set());
        parentsByChild.get(child).add(parent);
    };
    const byId = new Map(nodes.map(n => [n.data.id, n]));
    for (const edge of edges) {
        const { source, target, discovery_method: method } = edge.data;
        if (method === "MAC_PORT") {
            if (byId.get(target)?.data.device_type === "ACCESS_POINT" &&
                !parentsByChild.has(target)) addParent(target, source);
            continue;
        }
        if (method === "NVR_CHANNEL") {
            addParent(target, source);
            continue;
        }
        if (!["LLDP", "CDP", "MANUAL"].includes(method)) continue;
        physicalDegree.set(source, (physicalDegree.get(source) || 0) + 1);
        physicalDegree.set(target, (physicalDegree.get(target) || 0) + 1);
        const sNode = byId.get(source);
        const tNode = byId.get(target);
        if (sNode?.data.device_type === "ACCESS_POINT" && tNode?.data.device_type === "SWITCH") {
            addParent(source, target);
        }
        if (tNode?.data.device_type === "ACCESS_POINT" && sNode?.data.device_type === "SWITCH") {
            addParent(target, source);
        }
    }

    const sortByPortThenIp = (a, b) => {
        const pA = Number.parseInt(a.data.uplink_port || "", 10);
        const pB = Number.parseInt(b.data.uplink_port || "", 10);
        if (!Number.isNaN(pA) && !Number.isNaN(pB) && pA !== pB) return pA - pB;
        return ipSortValue(a.data.ip) - ipSortValue(b.data.ip);
    };

    const tier0NetVlan = nodes.filter(n => ["network", "vlan", "type"].includes(n.data.kind));
    const tier1Core = nodes.filter(n =>
        n.data.kind === "gateway" ||
        (n.data.kind === "device" && ["FIREWALL", "ROUTER"].includes(n.data.device_type))
    ).sort((a, b) => ipSortValue(a.data.ip) - ipSortValue(b.data.ip));

    const tier2Switches = nodes.filter(n =>
        n.data.kind === "device" && ["SWITCH", "CONTROLLER"].includes(n.data.device_type)
    ).sort((a, b) => (physicalDegree.get(b.data.id) || 0) - (physicalDegree.get(a.data.id) || 0) || ipSortValue(a.data.ip) - ipSortValue(b.data.ip));

    const recorders = nodes.filter(n => n.data.device_type === "NVR");
    const childrenByParent = new Map();
    for (const [child, parents] of parentsByChild) {
        if (parents.size !== 1) continue;
        const [parent] = parents;
        if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
        childrenByParent.get(parent).push(byId.get(child));
    }
    const grouped = new Set([...childrenByParent.values()].flat());
    let currentY = placeRows(tier0NetVlan, 0);
    currentY = placeRows(tier1Core, currentY);
    // Put switch peers on the same row so their links stay above the AP rows.
    const switchWidths = tier2Switches.map(parent =>
        Math.max(1, Math.min(MAX_COLS, childrenByParent.get(parent.data.id)?.length || 0)) * CARD_GAP_X
    );
    let left = -switchWidths.reduce((total, width) => total + width, 0) / 2;
    let afterSwitches = currentY;
    tier2Switches.forEach((parent, index) => {
        const width = switchWidths[index];
        const center = left + width / 2;
        const childY = placeRows([parent], currentY, 1, center);
        const children = childrenByParent.get(parent.data.id) || [];
        afterSwitches = Math.max(afterSwitches,
            placeRows(children.sort(sortByPortThenIp), childY, MAX_COLS, center));
        left += width;
    });
    currentY = afterSwitches;
    for (const recorder of recorders) {
        currentY = placeRows([recorder], currentY);
        const cameras = childrenByParent.get(recorder.data.id) || [];
        currentY = placeRows(cameras.sort(sortByPortThenIp), currentY);
    }

    const remaining = nodes.filter(n => !positions[n.data.id] && !grouped.has(n));
    for (const type of ["ACCESS_POINT", "CAMERA"]) {
        currentY = placeRows(remaining.filter(n => n.data.device_type === type), currentY);
    }
    placeRows(remaining.filter(n => !positions[n.data.id]), currentY);
    return positions;
}

document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById("cy");
    if (!canvas) return;

    const subnet = document.getElementById("topo-subnet-select");
    const vlan = document.getElementById("topo-vlan-select");
    const status = document.getElementById("topo-status-select");
    const method = document.getElementById("topo-method-select");
    const search = document.getElementById("cy-search");
    const groupSelect = document.getElementById("topo-group-select");
    const viewButtons = [...document.querySelectorAll(".map-view-btn")];
    let view = "physical";
    let graph = null;
    let requestNumber = 0;
    let searchTimer;
    let lastData = null;
    let expandedGroup = null;
    let groupPage = 0;
    const hiddenTypes = new Set();

    function setOptions(select, values, label, getValue, getLabel) {
        const selected = select.value;
        select.replaceChildren(new Option(label, ""));
        values.forEach(item => select.add(new Option(getLabel(item), getValue(item))));
        select.value = selected;
    }

    function addDetail(label, value) {
        if (value === null || value === undefined || value === "") return;
        const details = document.getElementById("sp-details");
        const term = document.createElement("dt");
        const description = document.createElement("dd");
        term.textContent = label;
        description.textContent = Array.isArray(value) ? value.join(", ") : String(value);
        details.append(term, description);
    }

    function inspect(data, isEdge) {
        const detailLink = document.getElementById("sp-btn-detail");
        const title = document.getElementById("sp-title");
        document.getElementById("sp-details").replaceChildren();
        document.getElementById("sp-hint").textContent = data.discovery_method === "GATEWAY_CONFIG"
            ? "Gateway registrado para esta subred; no confirma un cable directo ni la ruta de cada equipo."
            : isEdge ? "Origen y evidencia de esta relación."
            : "Información observada durante el último escaneo.";
        detailLink.classList.add("d-none");
        if (isEdge) {
            title.textContent = data.discovery_method === "GATEWAY_CONFIG"
                ? "Relación con el gateway" : "Relación de red";
            addDetail("Método", {
                GATEWAY_CONFIG: "Gateway de la subred (inferido)",
                NETWORK_GATEWAY: "Gateway configurado",
                NETWORK_MEMBERSHIP: "Pertenencia a subred",
                VLAN_MEMBERSHIP: "Pertenencia a VLAN",
                INVENTORY_GROUP: "Agrupación de inventario"
            }[data.discovery_method] || data.discovery_method);
            addDetail("Gateway", data.gateway_ip);
            addDetail("Puerto de origen", data.source_port || "No identificado");
            addDetail("Puerto remoto", data.target_port || "No identificado");
            addDetail("Evidencia", data.evidence || "Registro manual");
            addDetail("Observado", data.observed_at);
            return;
        }
        title.textContent = data.name || data.label || "Elemento";
        addDetail("Tipo", data.device_type || ({ gateway: "Gateway configurado", network: "Subred", vlan: "VLAN", type: "Grupo de equipos" }[data.kind] || data.kind));
        addDetail("IP", data.ip);
        addDetail("MAC", data.mac);
        addDetail("Fabricante", data.vendor);
        addDetail("Modelo", data.model);
        addDetail("Estado", data.status);
        if (data.kind === "device") {
            if (data.client_count) {
                addDetail("Clientes conectados (resumen)", `${data.client_count}${data.associated_client_count ? ` (${data.associated_client_count} asociados por MAC/CSV)` : ""}`);
            }
            addDetail("Medio", { WIFI: "Wi-Fi", WIRED: "Cable", UNKNOWN: "No identificado" }[data.connection_medium] || "No identificado");
            addDetail("Evidencia del medio", data.medium_evidence);
            if (data.switch_association) {
                addDetail("Switch asociado por MAC", data.switch_association.switch_id);
                addDetail("Puerto donde se aprendió la MAC", data.switch_association.port);
                addDetail("MAC observada", data.switch_association.observed_at);
                addDetail("Alcance de la asociación", data.switch_association.evidence);
            }
            if (data.ap_association) {
                addDetail("AP asociado", data.ap_association.ap_name);
                addDetail("Fuente", data.ap_association.source === "ap_client_csv"
                    ? "CSV de asociaciones cliente-AP" : "MAC observada en radio del AP");
                addDetail(data.ap_association.source === "ap_client_csv" ? "Importado" : "Observado",
                    data.ap_association.observed_at);
                addDetail("Radio del AP", data.ap_association.radio);
                addDetail("Alcance de la asociación", data.ap_association.evidence);
            }
        }
        if (data.kind === "device") {
            addDetail("Confianza de identificación", {
                high: "Alta", medium: "Media", low: "Baja", none: "Sin identificar"
            }[data.identity_confidence] || "");
            addDetail("Fuentes de identificación", data.identity_sources);
            addDetail("Firmware", data.identity_firmware);
        }
        addDetail("Evidencia", data.evidence);
        addDetail("Subred / gateway", data.gateway);
        addDetail("VLAN", data.vlans);
        addDetail("Última detección", data.last_seen);
        addDetail("Ubicación", data.location);
        if (data.kind === "device") {
            detailLink.href = `/devices/${data.id}`;
            detailLink.classList.remove("d-none");
        }
    }

    function renderUnresolved(rows) {
        const list = document.getElementById("unresolved-list");
        list.replaceChildren();
        document.getElementById("unresolved-count").textContent = rows.length;
        rows.slice(0, 20).forEach(row => {
            const item = document.createElement("li");
            item.textContent = `${row.neighbor_name || "Vecino sin nombre"} · ${row.source_port || "puerto ?"} → ${row.neighbor_port || "puerto ?"} (${row.protocol})`;
            list.appendChild(item);
        });
        if (!rows.length) {
            const item = document.createElement("li");
            item.textContent = "No hay vecinos pendientes.";
            list.appendChild(item);
        }
    }

    function renderDeviceLegend(counts) {
        const legend = document.getElementById("map-device-legend");
        legend.replaceChildren();
        for (const [type, count] of Object.entries(counts || {})) {
            if (type === "TOTAL" || !count) continue;
            const info = mapDeviceInfo(type);
            const item = document.createElement("span");
            item.className = "map-legend-item";
            item.setAttribute("role", "button");
            item.tabIndex = 0;
            item.title = "Clic para ocultar o mostrar este tipo en el mapa";
            item.setAttribute("aria-pressed", String(!hiddenTypes.has(type)));
            item.style.cursor = "pointer";
            item.style.opacity = hiddenTypes.has(type) ? "0.45" : "1";
            const toggle = () => {
                if (hiddenTypes.has(type)) hiddenTypes.delete(type); else hiddenTypes.add(type);
                item.setAttribute("aria-pressed", String(!hiddenTypes.has(type)));
                item.style.opacity = hiddenTypes.has(type) ? "0.45" : "1";
                applyTypeFilter();
            };
            item.addEventListener("click", toggle);
            item.addEventListener("keydown", event => {
                if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); }
            });
            const badge = document.createElement("span");
            badge.className = "map-legend-icon";
            badge.style.backgroundColor = info.color;
            const icon = document.createElement("img");
            icon.src = mapIcon(type);
            icon.alt = "";
            badge.appendChild(icon);
            const label = document.createElement("span");
            label.textContent = `${info.label} (${count})`;
            item.append(badge, label);
            legend.appendChild(item);
        }
        if (!legend.childElementCount) legend.textContent = "Los tipos de equipos aparecerán después del escaneo.";
    }

    function applyTypeFilter() {
        if (!graph) return;
        graph.batch(() => {
            graph.nodes().forEach(node => {
                const data = node.data();
                const hidden = data.kind === "device" && hiddenTypes.has(data.device_type);
                node.style("display", hidden ? "none" : "element");
            });
        });
    }

    function render(data) {
        if (graph) graph.destroy();
        const deviceCount = data.elements.filter(element => element.data.kind === "device").length;
        const overview = MapOverview.buildPhysicalOverview(
            data.elements, expandedGroup, groupPage, { showClientGroupNodes: false }
        );
        const active = overview.activeGroup;
        document.getElementById("topo-group-filter").classList.remove("d-none");
        groupSelect.replaceChildren(new Option("Resumen de la red", ""));
        overview.groups.forEach(group => groupSelect.add(new Option(
            `${group.parentType === "ap" ? "AP" : group.parentType === "switch" ? "Switch" : "Subred"}: ${group.title} (${group.count} clientes)`, group.id)));
        groupSelect.value = active ? active.id : "";
        const pageLabel = document.getElementById("map-group-page");
        const back = document.getElementById("btn-group-back");
        const previous = document.getElementById("btn-group-prev");
        const next = document.getElementById("btn-group-next");
        pageLabel.classList.toggle("d-none", !active);
        back.classList.toggle("d-none", !active);
        previous.classList.toggle("d-none", !active || active.pages < 2);
        next.classList.toggle("d-none", !active || active.pages < 2);
        if (active) {
            pageLabel.textContent = `${active.title} · ${active.count} equipos · página ${active.page + 1}/${active.pages}`;
            previous.disabled = active.page === 0;
            next.disabled = active.page === active.pages - 1;
        }

        const uplinkPorts = new Map();
        const cameraChannels = new Map();
        const linkedAps = new Set();
        const nodeById = new Map(
            overview.elements.filter(el => el.group === "nodes").map(el => [el.data.id, el])
        );
        for (const el of overview.elements) {
            if (el.group !== "edges") continue;
            if (el.data.discovery_method === "NVR_CHANNEL") {
                cameraChannels.set(el.data.target, el.data.channel);
            }
            if (!["LLDP", "CDP", "MANUAL"].includes(el.data.discovery_method)) continue;
            const srcNode = nodeById.get(el.data.source);
            const dstNode = nodeById.get(el.data.target);
            if (srcNode?.data.device_type === "ACCESS_POINT") linkedAps.add(el.data.source);
            if (dstNode?.data.device_type === "ACCESS_POINT") linkedAps.add(el.data.target);
            if (srcNode?.data.device_type === "SWITCH" && el.data.source_port) {
                uplinkPorts.set(el.data.target, el.data.source_port);
            } else if (dstNode?.data.device_type === "SWITCH" && el.data.target_port) {
                uplinkPorts.set(el.data.source, el.data.target_port);
            }
        }

        const hasSwitchInView = [...nodeById.values()].some(
            el => el.data.kind === "device" && el.data.device_type === "SWITCH"
        );
        const filteredRawElements = overview.elements.filter(el => {
            if (el.group !== "edges") return true;
            if (view === "logical" && !active && el.data.discovery_method === "GATEWAY_CONFIG" && hasSwitchInView) {
                const targetNode = nodeById.get(el.data.target);
                const tType = targetNode?.data.device_type;
                return ["SWITCH", "CONTROLLER", "ROUTER", "FIREWALL", "SERVER", "NVR", "PRINTER", "UPS"].includes(tType);
            }
            return true;
        });

        const elements = filteredRawElements.map(element => {
            if (element.group === "edges") {
                return {
                    ...element,
                    data: {
                        ...element.data,
                        edge_label: formatEdgeLabel(element.data)
                    }
                };
            }
            const type = element.data.kind === "device" ? element.data.device_type
                : element.data.kind === "type" ? element.data.name : element.data.kind;
            const uplinkPort = uplinkPorts.get(element.data.id) || "";
            const channel = cameraChannels.get(element.data.id);
            let relationshipLabel = channel ? `NVR · Canal ${channel}` : "";
            if (view === "physical" && type === "ACCESS_POINT" && !linkedAps.has(element.data.id)) {
                relationshipLabel = element.data.switch_association
                    ? `MAC · Pto ${element.data.switch_association.port}` : "Sin enlace visible";
            }
            const enrichedData = {
                ...element.data,
                uplink_port: uplinkPort,
                relationship_label: relationshipLabel,
                icon: mapIcon(type),
                badge_icon: mapCardBadge(type),
                icon_color: mapDeviceInfo(type).color
            };
            enrichedData.card_label = buildCardLabel(enrichedData);
            return { ...element, data: enrichedData };
        });

        const infraNodeCount = elements.filter(
            el => el.group === "nodes" && el.data.kind === "device"
        ).length;
        const clientSummaryText = overview.totalClientCount
            ? ` · ${overview.totalClientCount} clientes resumidos`
            : "";
        document.getElementById("map-empty").classList.toggle("d-none", deviceCount > 0);
        document.getElementById("map-summary").textContent = view === "logical"
            ? `${infraNodeCount} equipos en diagrama${clientSummaryText}`
            : view === "inventory"
                ? `${infraNodeCount} equipos en diagrama · ${elements.filter(element => element.data.kind === "type").length} categorías${clientSummaryText}`
                : `${infraNodeCount} equipos en diagrama · ${elements.filter(element => element.group === "edges" && !["NVR_CHANNEL", "MAP_SUMMARY", "MAC_PORT"].includes(element.data.discovery_method)).length} enlaces físicos${clientSummaryText}`;
        document.getElementById("map-view-label").textContent = {
            physical: "Arquitectura física", logical: "Arquitectura lógica", inventory: "Inventario por capa"
        }[view];
        const macCount = elements.filter(el => el.data.discovery_method === "MAC_PORT").length;
        if (macCount) document.getElementById("map-summary").textContent += ` · ${macCount} puertos observados`;
        const nvrCount = elements.filter(el => el.data.discovery_method === "NVR_CHANNEL").length;
        if (nvrCount) document.getElementById("map-summary").textContent += ` · ${nvrCount} canales NVR`;
        const noLinks = document.getElementById("map-no-links");
        noLinks.classList.toggle("d-none", view !== "physical" || !deviceCount ||
            elements.some(element => element.group === "edges" && !["NVR_CHANNEL", "MAP_SUMMARY", "MAC_PORT"].includes(element.data.discovery_method)));
        document.getElementById("gateway-legend").classList.toggle("d-none", view !== "logical");
        renderUnresolved(data.unresolved_neighbors || []);
        renderDeviceLegend(data.counts);

        const positions = buildArchitecturalPositions(elements, active);
        graph = cytoscape({
            container: canvas,
            elements,
            style: [
                { selector: "node", style: {
                    "shape": "round-rectangle",
                    "width": 182,
                    "height": 68,
                    "background-color": "#ffffff",
                    "background-image": "data(badge_icon)",
                    "background-fit": "none",
                    "background-width": 36,
                    "background-height": 36,
                    "background-position-x": "10px",
                    "background-position-y": "50%",
                    "background-repeat": "no-repeat",
                    "border-width": 2.5,
                    "border-color": "data(icon_color)",
                    "label": "data(card_label)",
                    "color": "#0f172a",
                    "font-size": 10.5,
                    "font-weight": "600",
                    "text-wrap": "wrap",
                    "text-max-width": 124,
                    "text-valign": "center",
                    "text-halign": "center",
                    "text-margin-x": 20,
                    "text-margin-y": 0,
                    "text-background-opacity": 0,
                    "min-zoomed-font-size": 0,
                    "z-index": 10
                }},
                { selector: 'node[device_type = "FIREWALL"], node[device_type = "ROUTER"], node[device_type = "SWITCH"]', style: {
                    "width": 194,
                    "height": 74,
                    "border-width": 3,
                    "background-color": "#f8fafc",
                    "font-size": 11
                }},
                { selector: 'node[client_count > 0]', style: {
                    "border-width": 3,
                    "underlay-color": "#0f766e",
                    "underlay-opacity": 0.12,
                    "underlay-padding": 4
                }},
                { selector: 'node[kind = "network"], node[kind = "vlan"], node[kind = "type"], node[kind = "gateway"]',
                  style: {
                      "background-color": "#f1f5f9",
                      "color": "#0f172a",
                      "width": 186,
                      "height": 66,
                      "font-weight": "bold",
                      "border-width": 2.5
                  } },
                { selector: 'node[kind = "gateway"]', style: { "border-color": "#b45309", "border-style": "dashed" } },
                { selector: 'node[kind = "map_group"]', style: {
                    "shape": "round-rectangle", "width": 184, "height": 74,
                    "background-color": "#e0f2fe", "background-image": "none",
                    "border-color": "#0284c7", "border-width": 2,
                    "color": "#0c4a6e", "font-weight": "bold", "text-max-width": 165,
                    "min-zoomed-font-size": 0, "text-valign": "center", "text-margin-x": 0, "text-margin-y": 0
                } },
                { selector: 'node[kind = "map_group"][parent_type = "ap"]', style: {
                    "background-color": "#dcfce7", "border-color": "#047857", "color": "#065f46"
                } },
                { selector: 'node[kind = "device"][identity_confidence = "low"]',
                  style: { "underlay-color": "#f59e0b", "underlay-opacity": 0.22, "underlay-padding": 5 } },
                { selector: 'node[kind = "device"][identity_confidence = "none"]',
                  style: { "border-color": "#94a3b8", "background-color": "#f8fafc" } },
                { selector: 'node[status = "OFFLINE"]', style: { "background-color": "#f1f5f9", "opacity": 0.65 } },
                { selector: 'node[kind = "device"][connection_medium = "WIFI"]',
                  style: { "border-style": "dashed" } },
                { selector: 'node:selected', style: {
                    "border-width": 4,
                    "underlay-color": "#2563eb",
                    "underlay-opacity": 0.22,
                    "underlay-padding": 6
                }},
                { selector: "edge", style: {
                    "width": 2.2,
                    "line-color": "#94a3b8",
                    "curve-style": "taxi",
                    "taxi-direction": "downward",
                    "taxi-turn": "50%",
                    "target-arrow-shape": "none",
                    "target-arrow-color": "#94a3b8",
                    "arrow-scale": 0.75,
                    "z-index": 1
                }},
                { selector: 'edge[discovery_method = "GATEWAY_CONFIG"], edge[discovery_method = "NETWORK_GATEWAY"]',
                  style: { "target-arrow-shape": "triangle" } },
                { selector: 'edge[discovery_method = "LLDP"], edge[discovery_method = "CDP"]',
                  style: {
                      "line-color": "#15803d",
                      "width": 4,
                      "label": "data(edge_label)",
                      "font-size": 9.5,
                      "font-weight": "700",
                      "color": "#065f46",
                      "text-background-color": "#dcfce7",
                      "text-background-opacity": 0.95,
                      "text-background-padding": 3,
                      "text-background-shape": "roundrectangle",
                      "text-rotation": "none"
                  } },
                { selector: 'edge[discovery_method = "MAC_PORT"]',
                  style: { "line-color": "#2563eb", "line-style": "dotted", "width": 3,
                      "label": "data(edge_label)", "font-size": 11, "color": "#1d4ed8" } },
                { selector: 'edge[discovery_method = "NVR_CHANNEL"]',
                  style: { "line-color": "#be185d", "line-style": "dashed", "width": 3,
                      "curve-style": "straight", "target-arrow-shape": "triangle",
                      "target-arrow-color": "#be185d" } },
                { selector: 'edge[discovery_method = "MANUAL"]',
                  style: { "line-color": "#8b5cf6", "target-arrow-color": "#8b5cf6", "line-style": "dashed" } },
                { selector: 'edge[discovery_method = "GATEWAY_CONFIG"]',
                  style: { "line-color": "#d97706", "target-arrow-color": "#d97706", "line-style": "dashed", "width": 2, "opacity": 0.75 } },
                { selector: 'edge[discovery_method = "NETWORK_GATEWAY"]',
                  style: { "line-color": "#d97706", "target-arrow-color": "#d97706", "width": 2.5 } },
                { selector: 'edge[discovery_method = "NETWORK_MEMBERSHIP"], edge[discovery_method = "VLAN_MEMBERSHIP"], edge[discovery_method = "INVENTORY_GROUP"]',
                  style: { "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "width": 1.5, "opacity": 0.65 } },
                { selector: 'edge[discovery_method = "MAP_SUMMARY"]',
                  style: { "line-color": "#0284c7", "target-arrow-color": "#0284c7",
                      "line-style": "dotted", "target-arrow-shape": "none", "width": 2 } },
                { selector: 'edge[discovery_method = "MAP_SUMMARY"][parent_type = "ap"]',
                  style: { "line-color": "#047857" } },
                { selector: ".map-muted", style: { "opacity": 0.22 } }
            ],
            layout: {
                name: "preset",
                positions: node => positions[node.id()] || { x: 0, y: 0 },
                fit: true,
                padding: 46
            }
        });
        applyTypeFilter();
        const pending = (data.counts || {}).UNKNOWN || 0;
        const pendingLabel = document.getElementById("identity-pending");
        if (pendingLabel) pendingLabel.textContent = pending;
        graph.on("tap", "node", event => {
            const node = event.target.data();
            if (node.kind === "map_group") {
                expandedGroup = node.group_id;
                groupPage = 0;
                render(lastData);
                return;
            }
            graph.elements().removeClass("map-muted");
            if (view === "physical" && event.target.connectedEdges().length) {
                graph.elements().difference(event.target.closedNeighborhood()).addClass("map-muted");
            }
            inspect(node, false);
        });
        graph.on("tap", "edge", event => inspect(event.target.data(), true));
        graph.on("tap", event => {
            if (event.target === graph) {
                graph.elements().removeClass("map-muted");
                document.getElementById("sp-title").textContent = "Selecciona un equipo o enlace";
                document.getElementById("sp-details").replaceChildren();
                document.getElementById("sp-btn-detail").classList.add("d-none");
            }
        });
        if (active) {
            requestAnimationFrame(() => {
                if (!graph) return;
                const ids = new Set([...active.visibleMemberIds, active.parentId]);
                const focus = graph.nodes().filter(node => ids.has(node.id()));
                if (focus.length) graph.fit(focus, 55);
            });
        }
    }

    async function load() {
        const current = ++requestNumber;
        const query = new URLSearchParams({ view, status: status.value });
        if (subnet.value) query.set("cidr", subnet.value);
        if (vlan.value) query.set("vlan", vlan.value);
        if (method.value && view === "physical") query.set("method", method.value);
        if (search.value.trim()) query.set("q", search.value.trim());
        try {
            const response = await fetch(`/api/topology/data?${query}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || "No se pudo cargar el mapa");
            if (current !== requestNumber) return;
            setOptions(subnet, data.available_subnets || [], "Todas las redes", item => item, item => item);
            setOptions(vlan, data.available_vlans || [], "Todas las VLAN",
                       item => item.vlan_id, item => `${item.vlan_id} · ${item.name}`);
            lastData = data;
            expandedGroup = null;
            groupPage = 0;
            render(data);
        } catch (error) {
            document.getElementById("map-summary").textContent = error.message;
        }
    }

    viewButtons.forEach(button => button.addEventListener("click", () => {
        view = button.dataset.view;
        viewButtons.forEach(other => {
            other.classList.toggle("btn-primary", other === button);
            other.classList.toggle("btn-outline-primary", other !== button);
        });
        method.disabled = view !== "physical";
        load();
    }));
    [subnet, vlan, status, method].forEach(select => select.addEventListener("change", load));
    groupSelect.addEventListener("change", () => {
        expandedGroup = groupSelect.value || null;
        groupPage = 0;
        render(lastData);
    });
    search.addEventListener("input", () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(load, 250);
    });
    document.getElementById("btn-group-back").addEventListener("click", () => {
        expandedGroup = null;
        groupPage = 0;
        render(lastData);
    });
    document.getElementById("btn-group-prev").addEventListener("click", () => {
        groupPage--;
        render(lastData);
    });
    document.getElementById("btn-group-next").addEventListener("click", () => {
        groupPage++;
        render(lastData);
    });
    document.getElementById("btn-fit-cy").addEventListener("click", () => graph?.fit(undefined, 35));
    document.getElementById("btn-export-png").addEventListener("click", () => {
        if (!graph) return;
        const link = document.createElement("a");
        link.href = graph.png({ full: true, bg: "#ffffff", scale: 2 });
        link.download = `mapa-${view}.png`;
        link.click();
    });
    const maintenanceStatus = document.getElementById("maintenance-status");
    async function postJson(url, body) {
        const response = await fetch(url, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {})
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "La operación falló.");
        return result;
    }
    document.getElementById("btn-reclassify")?.addEventListener("click", async event => {
        event.currentTarget.disabled = true;
        maintenanceStatus.textContent = "Reclasificando...";
        try {
            const result = await postJson("/api/identity/reclassify");
            maintenanceStatus.textContent = `${result.updated} de ${result.examined} equipos sin identificar se reclasificaron con las reglas actuales.`;
            if (result.updated) await load();
        } catch (error) {
            maintenanceStatus.textContent = error.message;
        } finally {
            event.currentTarget.disabled = false;
        }
    });
    document.getElementById("btn-purge-stale")?.addEventListener("click", async event => {
        const days = Number(document.getElementById("stale-days").value);
        try {
            const preview = await postJson("/api/devices/stale", { days });
            if (!preview.count) {
                maintenanceStatus.textContent = `No hay clientes con MAC aleatoria sin verse hace más de ${days} días.`;
                return;
            }
            if (!window.confirm(`Se eliminarán ${preview.count} equipos desconectados con MAC aleatoria sin verse hace más de ${days} días. Esta acción no se puede deshacer. ¿Continuar?`)) return;
            const result = await postJson("/api/devices/stale", { days, confirm: true });
            maintenanceStatus.textContent = `${result.deleted} equipos eliminados.`;
            await load();
        } catch (error) {
            maintenanceStatus.textContent = error.message;
        }
    });
    const feedbackForm = document.getElementById("identity-feedback-upload");
    if (feedbackForm) feedbackForm.addEventListener("submit", async event => {
        event.preventDefault();
        const message = document.getElementById("identity-feedback-status");
        const button = feedbackForm.querySelector('button[type="submit"]');
        button.disabled = true;
        message.textContent = "Aplicando clasificaciones...";
        try {
            const response = await fetch("/api/identity/feedback", {
                method: "POST", body: new FormData(feedbackForm)
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || "No se pudo importar el CSV.");
            message.textContent = `${result.imported} clasificaciones guardadas · ${result.updated} equipos actualizados ahora. Se aplicarán también en los próximos escaneos.`;
            if (result.updated) await load();
        } catch (error) {
            message.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
    document.getElementById("ap-association-upload").addEventListener("submit", async event => {
        event.preventDefault();
        const form = event.currentTarget;
        const message = document.getElementById("ap-association-status");
        const button = form.querySelector('button[type="submit"]');
        button.disabled = true;
        message.textContent = "Importando asociaciones...";
        try {
            const response = await fetch("/api/ap-associations/import", {
                method: "POST", body: new FormData(form)
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || "No se pudo importar el CSV.");
            message.textContent = result.replaced
                ? `${result.imported} asociaciones importadas · ${result.unresolved} AP sin coincidencia · ${result.invalid} filas inválidas · ${result.ambiguous} MAC ambiguas.`
                : `No se importaron asociaciones; se conservó la captura anterior. ${result.unresolved} AP sin coincidencia · ${result.invalid} filas inválidas · ${result.ambiguous} MAC ambiguas.`;
            if (result.replaced) await load();
        } catch (error) {
            message.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
    load();
});
