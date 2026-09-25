const MAP_DEVICE_TYPES = {
    ROUTER: { label: "Router", color: "#b45309", shape: '<rect x="3" y="9" width="18" height="10" rx="2"/><path d="M7 9V5m10 4V5M5 15h.01M9 15h.01M13 15h.01M17 15h.01"/>' },
    FIREWALL: { label: "Firewall", color: "#b91c1c", shape: '<path d="M12 2 20 5v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5z"/><path d="M8 10h8M8 14h8M12 10v4"/>' },
    SWITCH: { label: "Switch", color: "#0e7490", shape: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M5 10h2v3H5zm4 0h2v3H9zm4 0h2v3h-2zm4 0h2v3h-2zM5 16h14"/>' },
    ACCESS_POINT: { label: "Punto de acceso", color: "#047857", shape: '<circle cx="12" cy="18" r="2"/><path d="M7.5 13.5a6.5 6.5 0 0 1 9 0M4.5 10.5a10.5 10.5 0 0 1 15 0"/>' },
    SERVER: { label: "Servidor", color: "#4338ca", shape: '<rect x="4" y="3" width="16" height="5" rx="1"/><rect x="4" y="10" width="16" height="5" rx="1"/><rect x="4" y="17" width="16" height="5" rx="1"/><path d="M7 5.5h.01M7 12.5h.01M7 19.5h.01M11 5.5h6M11 12.5h6M11 19.5h6"/>' },
    PC: { label: "Computador", color: "#1d4ed8", shape: '<rect x="3" y="4" width="18" height="13" rx="1"/><path d="M9 21h6m-3-4v4"/>' },
    LAPTOP: { label: "Portátil", color: "#1d4ed8", shape: '<rect x="5" y="4" width="14" height="12" rx="1"/><path d="m3 20 2-4h14l2 4z"/>' },
    PHONE: { label: "Teléfono", color: "#7c3aed", shape: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>' },
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
            addDetail("Medio", { WIFI: "Wi-Fi", WIRED: "Cable", UNKNOWN: "No identificado" }[data.connection_medium] || "No identificado");
            addDetail("Evidencia del medio", data.medium_evidence);
            if (data.switch_association) {
                addDetail("Switch asociado por MAC", data.switch_association.switch_id);
                addDetail("Puerto donde se aprendió la MAC", data.switch_association.port);
                addDetail("Alcance de la asociación", data.switch_association.evidence);
            }
            if (data.ap_association) {
                addDetail("AP asociado por MAC", data.ap_association.ap_name);
                addDetail("Radio del AP", data.ap_association.radio);
                addDetail("Alcance de la asociación", data.ap_association.evidence);
            }
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

    function render(data) {
        if (graph) graph.destroy();
        const deviceCount = data.elements.filter(element => element.data.kind === "device").length;
        const overview = view === "physical"
            ? MapOverview.buildPhysicalOverview(data.elements, expandedGroup, groupPage)
            : { elements: data.elements, groups: [], activeGroup: null };
        const active = overview.activeGroup;
        document.getElementById("topo-group-filter").classList.toggle("d-none", view !== "physical");
        groupSelect.replaceChildren(new Option("Resumen completo", ""));
        overview.groups.forEach(group => groupSelect.add(new Option(
            `${group.parentType === "ap" ? "AP" : group.parentType === "switch" ? "Switch" : "Subred"}: ${group.title} (${group.count})`, group.id)));
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
        const visibleNodeCount = overview.elements.filter(element => element.group === "nodes").length;
        const elements = overview.elements.map(element => {
            if (element.group !== "nodes") return element;
            const type = element.data.kind === "device" ? element.data.device_type
                : element.data.kind === "type" ? element.data.name : element.data.kind;
            return { ...element, data: {
                ...element.data,
                icon: mapIcon(type),
                icon_color: mapDeviceInfo(type).color
            }};
        });
        document.getElementById("map-empty").classList.toggle("d-none", deviceCount > 0);
        const edgeCount = methodName => data.elements.filter(element =>
            element.group === "edges" && element.data.discovery_method === methodName).length;
        document.getElementById("map-summary").textContent = view === "logical"
            ? `${deviceCount} equipos · ${edgeCount("GATEWAY_CONFIG")} relaciones con gateway`
            : view === "inventory"
                ? `${deviceCount} equipos · ${data.elements.filter(element => element.data.kind === "type").length} tipos`
                : `${deviceCount} equipos · ${data.elements.filter(element => element.group === "edges").length} enlaces · ${overview.groups.length} grupos`;
        document.getElementById("map-view-label").textContent = {
            physical: "Conexiones físicas", logical: "Subred → gateway → equipos", inventory: "Equipos por tipo"
        }[view];
        document.getElementById("gateway-legend").classList.toggle("d-none", view !== "logical");
        renderUnresolved(data.unresolved_neighbors || []);
        renderDeviceLegend(data.counts);
        graph = cytoscape({
            container: canvas,
            elements,
            style: [
                { selector: "node", style: {
                    "background-color": "data(icon_color)", "background-image": "data(icon)",
                    "background-fit": "contain", "background-width": "62%", "background-height": "62%",
                    "background-repeat": "no-repeat", "label": "data(label)", "color": "#172033",
                    "font-size": 11, "text-wrap": "wrap", "text-max-width": 115,
                    "min-zoomed-font-size": 9,
                    "text-valign": "bottom", "text-margin-y": 8, "width": 48, "height": 48,
                    "border-width": 2, "border-color": "#ffffff"
                }},
                { selector: 'node[kind = "network"], node[kind = "vlan"], node[kind = "type"], node[kind = "gateway"]',
                  style: { "color": "#122c4f", "width": 56, "height": 56, "font-weight": "bold" } },
                { selector: 'node[kind = "type"], node[kind = "gateway"]', style: { "shape": "round-rectangle" } },
                { selector: 'node[kind = "network"]', style: { "shape": "hexagon" } },
                { selector: 'node[kind = "gateway"]', style: { "border-color": "#b45309", "border-style": "dashed" } },
                { selector: 'node[kind = "map_group"]', style: {
                    "shape": "round-rectangle", "width": 150, "height": 82,
                    "background-color": "#e0f2fe", "background-image": "none",
                    "border-color": "#0284c7", "border-width": 2,
                    "color": "#0c4a6e", "font-weight": "bold", "text-max-width": 145,
                    "min-zoomed-font-size": 0, "text-valign": "center", "text-margin-y": 0
                } },
                { selector: 'node[kind = "map_group"][parent_type = "ap"]', style: {
                    "background-color": "#dcfce7", "border-color": "#047857", "color": "#065f46"
                } },
                { selector: 'node[status = "OFFLINE"]', style: { "background-color": "#a4acba", "opacity": 0.65 } },
                { selector: 'node[kind = "device"][connection_medium = "WIFI"]',
                  style: { "border-color": "#0284c7", "border-style": "dashed", "border-width": 4 } },
                { selector: 'node[kind = "device"][connection_medium = "WIRED"]',
                  style: { "border-color": "#15803d", "border-style": "solid", "border-width": 4 } },
                { selector: "edge", style: {
                    "width": 2, "line-color": "#7c91ac", "curve-style": "bezier",
                    "target-arrow-shape": "triangle", "target-arrow-color": "#7c91ac",
                    "arrow-scale": 0.7
                }},
                { selector: 'edge[discovery_method = "MANUAL"]',
                  style: { "line-color": "#8b5cf6", "target-arrow-color": "#8b5cf6", "line-style": "dashed" } },
                { selector: 'edge[discovery_method = "GATEWAY_CONFIG"]',
                  style: { "line-color": "#d97706", "target-arrow-color": "#d97706", "line-style": "dashed", "width": 2 } },
                { selector: 'edge[discovery_method = "NETWORK_GATEWAY"]',
                  style: { "line-color": "#d97706", "target-arrow-color": "#d97706", "width": 2 } },
                { selector: 'edge[discovery_method = "NETWORK_MEMBERSHIP"], edge[discovery_method = "VLAN_MEMBERSHIP"], edge[discovery_method = "INVENTORY_GROUP"]',
                  style: { "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "width": 1 } },
                { selector: 'edge[discovery_method = "MAP_SUMMARY"]',
                  style: { "line-color": "#0284c7", "target-arrow-color": "#0284c7",
                      "line-style": "dotted", "target-arrow-shape": "none", "width": 2 } },
                { selector: 'edge[discovery_method = "MAP_SUMMARY"][parent_type = "ap"]',
                  style: { "line-color": "#047857" } }
            ],
            layout: view === "physical"
                ? visibleNodeCount > 220
                    ? { name: "grid", padding: 80, spacingFactor: 1.4 }
                    : { name: "cose", padding: 80, animate: false, nodeRepulsion: 14000,
                        idealEdgeLength: 130, componentSpacing: 140, nodeOverlap: 30, numIter: 350 }
                : { name: "breadthfirst", directed: true, padding: 42, spacingFactor: 1.3 }
        });
        graph.on("tap", "node", event => {
            const node = event.target.data();
            if (node.kind === "map_group") {
                expandedGroup = node.group_id;
                groupPage = 0;
                render(lastData);
                return;
            }
            inspect(node, false);
        });
        graph.on("tap", "edge", event => inspect(event.target.data(), true));
        graph.on("tap", event => {
            if (event.target === graph) {
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
    load();
});
