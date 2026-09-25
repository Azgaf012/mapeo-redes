/* Keep large physical maps readable without claiming an unobserved cable. */
(function (root) {
    const PAGE_SIZE = 60;

    function buildPhysicalOverview(elements, expandedId = null, requestedPage = 0) {
        const nodes = elements.filter(element => element.group === 'nodes');
        const edges = elements.filter(element => element.group === 'edges');
        const byId = new Map(nodes.map(node => [node.data.id, node]));
        const neighbors = new Map();
        for (const edge of edges) {
            const { source, target } = edge.data;
            if (!byId.has(source) || !byId.has(target)) continue;
            if (!neighbors.has(source)) neighbors.set(source, new Set());
            if (!neighbors.has(target)) neighbors.set(target, new Set());
            neighbors.get(source).add(target);
            neighbors.get(target).add(source);
        }

        const buckets = new Map();
        for (const node of nodes) {
            if (node.data.kind !== 'device' ||
                ['SWITCH', 'ACCESS_POINT', 'ROUTER', 'FIREWALL'].includes(node.data.device_type)) continue;
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
                const subnet = node.data.network_cidr || 'Sin subred registrada';
                key = `unlinked:${subnet}`;
                title = subnet;
            }
            if (!key) continue;
            if (!buckets.has(key)) buckets.set(key, { id: key, title, parentId, parentType,
                members: [], associatedCount: 0 });
            buckets.get(key).members.push(node);
            if (association) {
                buckets.get(key).associatedCount++;
            }
        }

        const groups = [...buckets.values()].filter(group =>
            group.members.length >= (group.parentId ? 1 : 4));
        groups.sort((a, b) => a.title.localeCompare(b.title, undefined, { numeric: true }));
        const groupedIds = new Set(groups.flatMap(group => group.members.map(node => node.data.id)));
        const visible = nodes.filter(node => !groupedIds.has(node.data.id));
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
            const id = `map-group:${group.id}`;
            visible.push({ group: 'nodes', data: { id, kind: 'map_group',
                label: `${group.parentId ? 'Equipos de' : 'Sin enlace confirmado'}\n${group.title}\n${group.count} equipos${group.associatedCount ? ` · ${group.associatedCount} asociados` : ''}`,
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
                ({ id, title, count, pages, parentId, parentType, associatedCount })), activeGroup };
    }

    const api = { buildPhysicalOverview };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.MapOverview = api;
})(typeof window === 'undefined' ? globalThis : window);
