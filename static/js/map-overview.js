/* Keep large physical maps readable without claiming an unobserved cable. */
(function (root) {
    const PAGE_SIZE = 60;
    const INFRASTRUCTURE_TYPES = new Set([
        'ROUTER', 'FIREWALL', 'SWITCH', 'ACCESS_POINT', 'CONTROLLER',
        'SERVER', 'CAMERA', 'NVR', 'PRINTER', 'UPS'
    ]);
    const LOGICAL_ONLY_METHODS = new Set([
        'GATEWAY_CONFIG', 'NETWORK_GATEWAY', 'NETWORK_MEMBERSHIP',
        'VLAN_MEMBERSHIP', 'INVENTORY_GROUP', 'MAP_SUMMARY', 'MAC_PORT'
    ]);

    function buildPhysicalOverview(elements, expandedId = null, requestedPage = 0, options = {}) {
        const showClientGroupNodes = options.showClientGroupNodes !== false;
        const nodes = elements.filter(element => element.group === 'nodes');
        const edges = elements.filter(element => element.group === 'edges');
        const byId = new Map(nodes.map(node => [node.data.id, node]));
        const neighbors = new Map();
        for (const edge of edges) {
            if (LOGICAL_ONLY_METHODS.has(edge.data.discovery_method)) continue;
            const { source, target } = edge.data;
            if (!byId.has(source) || !byId.has(target)) continue;
            if (!neighbors.has(source)) neighbors.set(source, new Set());
            if (!neighbors.has(target)) neighbors.set(target, new Set());
            neighbors.get(source).add(target);
            neighbors.get(target).add(source);
        }

        const buckets = new Map();
        const parentClientCounts = new Map();
        const subnetClientCounts = new Map();
        let totalClientCount = 0;
        const addParentClientCount = (parentId, isAssociated) => {
            if (!parentId) return;
            if (!parentClientCounts.has(parentId)) {
                parentClientCounts.set(parentId, { total: 0, associated: 0 });
            }
            const entry = parentClientCounts.get(parentId);
            entry.total++;
            if (isAssociated) entry.associated++;
        };

        for (const node of nodes) {
            if (node.data.kind !== 'device' ||
                INFRASTRUCTURE_TYPES.has(node.data.device_type)) continue;
            totalClientCount++;
            const subnetKey = node.data.network_cidr || 'Sin subred registrada';
            subnetClientCounts.set(subnetKey, (subnetClientCounts.get(subnetKey) || 0) + 1);
            const adjacent = neighbors.get(node.data.id);
            let key;
            let title;
            let parentId = null;
            let parentType = null;
            let association = null;
            if (adjacent && adjacent.size === 1) {
                const candidate = [...adjacent][0];
                const type = byId.get(candidate).data.device_type;
                if (type === 'SWITCH' || type === 'ACCESS_POINT') {
                    parentId = candidate;
                    parentType = type === 'SWITCH' ? 'switch' : 'ap';
                    key = `${parentType}:${candidate}`;
                    title = byId.get(candidate).data.name || byId.get(candidate).data.label;
                }
            }
            if (!key && (!adjacent || adjacent.size === 0)) {
                const ap = node.data.ap_association;
                const sw = node.data.switch_association;
                if (ap && byId.get(ap.ap_id)?.data.device_type === 'ACCESS_POINT') {
                    parentId = ap.ap_id;
                    parentType = 'ap';
                    association = ap;
                } else if (sw && byId.get(sw.switch_id)?.data.device_type === 'SWITCH') {
                    parentId = sw.switch_id;
                    parentType = 'switch';
                    association = sw;
                }
                if (parentId) {
                    key = `${parentType}:${parentId}`;
                    title = byId.get(parentId).data.name || byId.get(parentId).data.label;
                }
            }
            if (!key && (!adjacent || adjacent.size === 0)) {
                key = `unlinked:${subnetKey}`;
                title = subnetKey;
            }
            if (!key) continue;
            if (!buckets.has(key)) buckets.set(key, { id: key, title, parentId, parentType,
                members: [], associatedCount: 0 });
            buckets.get(key).members.push(node);
            if (association) {
                buckets.get(key).associatedCount++;
            }
            if (parentId) {
                addParentClientCount(parentId, Boolean(association));
            }
        }

        const minUnlinkedSize = showClientGroupNodes ? 4 : 1;
        const groups = [...buckets.values()].filter(group =>
            group.members.length >= (group.parentId ? 1 : minUnlinkedSize));
        groups.sort((a, b) => a.title.localeCompare(b.title, undefined, { numeric: true }));
        const groupedIds = new Set(groups.flatMap(group => group.members.map(node => node.data.id)));
        const visible = nodes.filter(node => {
            if (groupedIds.has(node.data.id)) return false;
            if (!showClientGroupNodes && node.data.kind === 'type' && !INFRASTRUCTURE_TYPES.has(node.data.name)) {
                return false;
            }
            return true;
        }).map(node => {
            const counts = parentClientCounts.get(node.data.id);
            const subnetClients = !showClientGroupNodes && (
                node.data.kind === 'network'
                    ? (subnetClientCounts.get(node.data.name) || 0)
                    : ['FIREWALL', 'ROUTER'].includes(node.data.device_type)
                        ? (subnetClientCounts.get(node.data.network_cidr) || 0)
                        : 0
            );
            if (!counts && !subnetClients) return node;
            const total = counts ? counts.total : subnetClients;
            const associated = counts ? counts.associated : 0;
            const suffix = `\n[${total} cliente${total === 1 ? '' : 's'}${!counts && subnetClients ? ' en subred' : ''}]`;
            const baseLabel = node.data.label || node.data.name || node.data.ip || node.data.id;
            return {
                ...node,
                data: {
                    ...node.data,
                    client_count: total,
                    associated_client_count: associated,
                    subnet_client_count: subnetClients || undefined,
                    label: baseLabel.includes('cliente') ? baseLabel : `${baseLabel}${suffix}`
                }
            };
        });
        const visibleIds = new Set(visible.map(node => node.data.id));
        let activeGroup = null;

        for (const group of groups) {
            group.members.sort((a, b) => (a.data.ip || a.data.label)
                .localeCompare(b.data.ip || b.data.label, undefined, { numeric: true }));
            group.count = group.members.length;
            group.pages = Math.ceil(group.count / PAGE_SIZE);
            if (group.id === expandedId) {
                const page = Math.max(0, Math.min(requestedPage, group.pages - 1));
                activeGroup = { id: group.id, title: group.title, count: group.count,
                    page, pages: group.pages, parentId: group.parentId,
                    parentType: group.parentType,
                    associatedCount: group.associatedCount, visibleMemberIds: [] };
                for (const node of group.members.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)) {
                    visible.push(node);
                    visibleIds.add(node.data.id);
                    activeGroup.visibleMemberIds.push(node.data.id);
                }
                continue;
            }
            if (!showClientGroupNodes) {
                continue;
            }
            const id = `map-group:${group.id}`;
            visible.push({ group: 'nodes', data: { id, kind: 'map_group',
                label: `${group.parentId ? 'Clientes en' : 'Sin enlace confirmado'}\n${group.title}\n${group.count} equipo${group.count === 1 ? '' : 's'}${group.associatedCount ? ` · ${group.associatedCount} asociados` : ''}`,
                name: group.title, count: group.count, group_id: group.id,
                parent_id: group.parentId, parent_type: group.parentType,
                associated_count: group.associatedCount } });
            if (group.parentId) {
                edges.push({ group: 'edges', data: { id: `map-summary:${group.id}`,
                    source: group.parentId, target: id, discovery_method: 'MAP_SUMMARY',
                    parent_type: group.parentType,
                    evidence: 'Grupo de visualización; no representa un cable.' } });
            }
            visibleIds.add(id);
        }
        return { elements: [...visible, ...edges.filter(edge =>
            visibleIds.has(edge.data.source) && visibleIds.has(edge.data.target))],
            groups: groups.map(({ id, title, count, pages, parentId, parentType, associatedCount }) =>
                ({ id, title, count, pages, parentId, parentType, associatedCount })),
            activeGroup, totalClientCount };
    }

    const api = { buildPhysicalOverview, INFRASTRUCTURE_TYPES };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.MapOverview = api;
})(typeof window === 'undefined' ? globalThis : window);
