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
    assert(overview.elements.some(e => e.data.id === 'n120'));
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
