const assert = require('node:assert/strict');
const test = require('node:test');
const { buildPhysicalOverview } = require('../static/js/map-overview.js');

const node = (id, type = 'PC', network = '10.0.0.0/24') => ({
    group: 'nodes', data: { id, kind: 'device', device_type: type,
        label: id, network_cidr: network }
});
const edge = (id, source, target) => ({
    group: 'edges', data: { id, source, target, discovery_method: 'LLDP' }
});

test('switch endpoints form distinct expandable groups with real links preserved', () => {
    const elements = [node('s1', 'SWITCH'), node('s2', 'SWITCH'),
        ...Array.from({ length: 5 }, (_, i) => node(`a${i}`)),
        ...Array.from({ length: 5 }, (_, i) => node(`b${i}`)),
        ...Array.from({ length: 5 }, (_, i) => edge(`ea${i}`, 's1', `a${i}`)),
        ...Array.from({ length: 5 }, (_, i) => edge(`eb${i}`, 's2', `b${i}`))];
    const overview = buildPhysicalOverview(elements);
    assert.equal(overview.groups.length, 2);
    assert.equal(overview.elements.filter(e => e.group === 'nodes').length, 4);
    const first = overview.groups.find(g => g.id === 'switch:s1');
    assert.equal(first.count, 5);
    const s1Node = overview.elements.find(e => e.data.id === 's1');
    assert.equal(s1Node.data.client_count, 5);
    assert(s1Node.data.label.includes('[5 clientes]'));
    const cleanOverview = buildPhysicalOverview(elements, null, 0, { showClientGroupNodes: false });
    assert.equal(cleanOverview.elements.filter(e => e.group === 'nodes').length, 2);
    const expanded = buildPhysicalOverview(elements, 'switch:s1');
    assert(expanded.elements.some(e => e.data.id === 'a0'));
    assert(!expanded.elements.some(e => e.data.id === 'b0'));
    assert(expanded.elements.some(e => e.data.id === 'ea0'));
    assert(!expanded.elements.some(e => e.data.id === 'eb0'));
});

test('unconfirmed devices are grouped by subnet without invented physical edges', () => {
    const elements = [...Array.from({ length: 6 }, (_, i) => node(`x${i}`)),
        ...Array.from({ length: 6 }, (_, i) => node(`y${i}`, 'PC', '10.1.0.0/24'))];
    const overview = buildPhysicalOverview(elements);
    assert.equal(overview.groups.length, 2);
    assert.equal(overview.elements.filter(e => e.group === 'edges').length, 0);
});

test('MAC association places a device under its switch without a physical edge', () => {
    const pc = node('pc');
    pc.data.switch_association = { switch_id: 's', port: 'Gi0/1' };
    const overview = buildPhysicalOverview([node('s', 'SWITCH'), pc, node('other')]);
    const group = overview.groups.find(item => item.id === 'switch:s');
    assert.equal(group.count, 1);
    assert.equal(group.associatedCount, 1);
    assert(!overview.elements.some(item => item.group === 'edges'
        && item.data.discovery_method === 'LLDP'));
});

test('access points remain visible beside switch groups', () => {
    const elements = [node('s', 'SWITCH'), node('ap', 'ACCESS_POINT'),
        ...Array.from({ length: 8 }, (_, i) => node(`pc${i}`)),
        edge('ap-link', 's', 'ap'),
        ...Array.from({ length: 8 }, (_, i) => edge(`pc-link${i}`, 's', `pc${i}`))];
    const overview = buildPhysicalOverview(elements);
    assert(overview.elements.some(item => item.data.id === 'ap'));
    assert(overview.elements.some(item => item.data.id === 'ap-link'));
});

test('clients with a confirmed AP link form an expandable AP group', () => {
    const elements = [node('s', 'SWITCH'), node('ap', 'ACCESS_POINT'),
        ...Array.from({ length: 8 }, (_, i) => node(`wifi${i}`)),
        edge('uplink', 's', 'ap'),
        ...Array.from({ length: 8 }, (_, i) => edge(`wireless${i}`, 'ap', `wifi${i}`))];
    const overview = buildPhysicalOverview(elements);
    const group = overview.groups.find(item => item.id === 'ap:ap');
    assert.equal(group.count, 8);
    assert(overview.elements.some(item => item.data.id === 'ap'));
    assert(!overview.elements.some(item => item.data.id === 'wifi0'));
    const expanded = buildPhysicalOverview(elements, 'ap:ap');
    assert(expanded.elements.some(item => item.data.id === 'wifi0'));
    assert(expanded.elements.some(item => item.data.id === 'wireless0'));
});

test('manual Wi-Fi association also places a client under its AP', () => {
    const manual = edge('manual-wifi', 'ap', 'client');
    manual.data.discovery_method = 'MANUAL';
    manual.data.connection_type = 'WIFI';
    const overview = buildPhysicalOverview([node('ap', 'ACCESS_POINT'),
        node('client', 'PHONE'), manual]);
    assert.equal(overview.groups.find(item => item.id === 'ap:ap').count, 1);
    const expanded = buildPhysicalOverview([node('ap', 'ACCESS_POINT'),
        node('client', 'PHONE'), manual], 'ap:ap');
    assert(expanded.elements.some(item => item.data.id === 'manual-wifi'));
});

test('AP radio MAC association takes priority over a switch MAC association', () => {
    const client = node('client');
    client.data.ap_association = { ap_id: 'ap', radio: 'wlan0' };
    client.data.switch_association = { switch_id: 's', port: 'Gi0/1' };
    const overview = buildPhysicalOverview([node('s', 'SWITCH'),
        node('ap', 'ACCESS_POINT'), client]);
    assert.equal(overview.groups.find(item => item.id === 'ap:ap').count, 1);
    assert(!overview.groups.some(item => item.id === 'switch:s'));
    assert(!overview.elements.some(item => item.group === 'edges'
        && item.data.discovery_method === 'LLDP'));
});

test('large groups page devices and avoid rendering thousands at once', () => {
    const elements = [node('s', 'SWITCH'),
        ...Array.from({ length: 3000 }, (_, i) => node(`n${i}`)),
        ...Array.from({ length: 3000 }, (_, i) => edge(`e${i}`, 's', `n${i}`))];
    const overview = buildPhysicalOverview(elements, 'switch:s', 2);
    assert.equal(overview.activeGroup.count, 3000);
    assert.equal(overview.activeGroup.pages, 50);
    assert.equal(overview.elements.filter(e => e.group === 'nodes').length, 61);
    assert(expanded = overview.elements.some(e => e.data.id === 'n120'));
    assert(!overview.elements.some(e => e.data.id === 'n60'));
});

test('thousands of AP clients remain navigable in pages', () => {
    const clients = Array.from({ length: 3000 }, (_, i) => {
        const client = node(`wifi${i}`, 'PHONE');
        client.data.ap_association = { ap_id: 'ap', radio: 'wlan0' };
        return client;
    });
    const elements = [node('ap', 'ACCESS_POINT'), ...clients];
    const overview = buildPhysicalOverview(elements);
    assert.equal(overview.elements.filter(item => item.group === 'nodes').length, 2);
    const expanded = buildPhysicalOverview(elements, 'ap:ap', 3);
    assert.equal(expanded.activeGroup.pages, 50);
    assert.equal(expanded.elements.filter(item => item.group === 'nodes').length, 61);
    assert(expanded.elements.some(item => item.data.id === 'wifi180'));
});

test('fixed infrastructure devices remain visible while client endpoints are summarized on parent', () => {
    const elements = [
        node('s', 'SWITCH'),
        node('ap', 'ACCESS_POINT'),
        node('srv', 'SERVER'),
        node('cam', 'CAMERA'),
        node('prn', 'PRINTER'),
        node('pc1', 'PC'),
        node('phone1', 'PHONE'),
        edge('e-ap', 's', 'ap'),
        edge('e-srv', 's', 'srv'),
        edge('e-cam', 's', 'cam'),
        edge('e-prn', 's', 'prn'),
        edge('e-pc', 's', 'pc1'),
        edge('e-phone', 'ap', 'phone1'),
    ];
    const overview = buildPhysicalOverview(elements, null, 0, { showClientGroupNodes: false });
    const visibleIds = new Set(overview.elements.filter(e => e.group === 'nodes').map(e => e.data.id));
    assert(visibleIds.has('s'));
    assert(visibleIds.has('ap'));
    assert(visibleIds.has('srv'));
    assert(visibleIds.has('cam'));
    assert(visibleIds.has('prn'));
    assert(!visibleIds.has('pc1'));
    assert(!visibleIds.has('phone1'));
    const switchNode = overview.elements.find(e => e.data.id === 's');
    const apNode = overview.elements.find(e => e.data.id === 'ap');
    assert.equal(switchNode.data.client_count, 1);
    assert.equal(apNode.data.client_count, 1);
});

test('logical view hides unidentified client nodes and summarizes them on the gateway', () => {
    const fw = node('fw', 'FIREWALL', '192.168.48.0/22');
    const sw = node('sw', 'SWITCH', '192.168.48.0/22');
    const ap = node('ap', 'ACCESS_POINT', '192.168.48.0/22');
    const clients = Array.from({ length: 180 }, (_, i) => node(`u${i}`, 'UNKNOWN', '192.168.48.0/22'));
    const gwEdges = [sw, ap, ...clients].map((n, i) => ({
        group: 'edges',
        data: { id: `gw-${i}`, source: 'fw', target: n.data.id, discovery_method: 'GATEWAY_CONFIG' }
    }));
    const overview = buildPhysicalOverview([fw, sw, ap, ...clients, ...gwEdges], null, 0, { showClientGroupNodes: false });
    const visibleNodeIds = overview.elements.filter(e => e.group === 'nodes').map(e => e.data.id);
    assert.deepEqual(visibleNodeIds, ['fw', 'sw', 'ap']);
    assert.equal(overview.totalClientCount, 180);
    const fwNode = overview.elements.find(e => e.data.id === 'fw');
    assert.equal(fwNode.data.subnet_client_count, 180);
    assert.equal(overview.elements.filter(e => e.group === 'edges').length, 2);
});


test('mixed inventory with 392 devices keeps infrastructure visible and every client reachable', () => {
    // Counts from the inventory export. All identifiers and the subnet are synthetic.
    const counts = {
        ACCESS_POINT: 21, CAMERA: 20, FIREWALL: 1, LAPTOP: 1, NVR: 1,
        PC: 7, PHONE: 7, PRINTER: 1, SMART_TV: 3, SWITCH: 2, UNKNOWN: 328
    };
    const subnet = '192.0.2.0/23';
    const elements = Object.entries(counts).flatMap(([type, count]) =>
        Array.from({ length: count }, (_, index) =>
            node(type + '-' + index, type, type === 'CAMERA' && index < 6 ? '' : subnet)));
    const options = { showClientGroupNodes: false };
    const overview = buildPhysicalOverview(elements, null, 0, options);
    const infrastructureIds = elements.filter(item =>
        ['ACCESS_POINT', 'CAMERA', 'FIREWALL', 'NVR', 'PRINTER', 'SWITCH'].includes(item.data.device_type))
        .map(item => item.data.id);
    assert.equal(overview.totalClientCount, 346);
    assert.deepEqual(overview.elements.map(item => item.data.id), infrastructureIds);
    assert.equal(overview.groups.length, 1);
    const [group] = overview.groups;
    assert.equal(group.pages, 6);

    const seen = [];
    for (let page = 0; page < group.pages; page++) {
        const expanded = buildPhysicalOverview(elements, group.id, page, options);
        const visibleIds = expanded.elements.map(item => item.data.id);
        const pageClients = visibleIds.filter(id => !infrastructureIds.includes(id));
        assert.equal(pageClients.length, page === 5 ? 46 : 60);
        assert.deepEqual(pageClients, expanded.activeGroup.visibleMemberIds);
        assert(expanded.elements.every(item => item.group === 'nodes'));
        seen.push(...pageClients);
    }
    const clientIds = elements.map(item => item.data.id).filter(id => !infrastructureIds.includes(id));
    assert.deepEqual(seen.sort(), clientIds.sort());
    assert.deepEqual(buildPhysicalOverview(elements, null, 0, options), overview);
});
