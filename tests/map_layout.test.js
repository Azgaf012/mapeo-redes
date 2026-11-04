const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const context = { document: { addEventListener() {} } };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../static/js/topology.js'), 'utf8'), context);

test('switch branches and NVR channels form distinct sections with space between them', () => {
    const node = (id, type) => ({ group: 'nodes', data: { id, kind: 'device', device_type: type } });
    const edge = (source, target, method) => ({ group: 'edges', data: {
        source, target, discovery_method: method
    } });
    const elements = [node('s1', 'SWITCH'), node('s2', 'SWITCH'), node('nvr', 'NVR'),
        node('ap1', 'ACCESS_POINT'), node('ap2', 'ACCESS_POINT'), node('camera', 'CAMERA'),
        node('other', 'CAMERA'), edge('s1', 'ap1', 'LLDP'), edge('s2', 'ap2', 'LLDP'),
        edge('nvr', 'camera', 'NVR_CHANNEL'), edge('s1', 'camera', 'MAC_PORT')];
    const sections = [];
    const positions = context.buildArchitecturalPositions(elements, null, sections);
    assert.equal(sections.find(s => s.id === 'section:switch:s1').members.join(','), 's1,ap1');
    assert.equal(sections.find(s => s.id === 'section:nvr:nvr').members.join(','), 'nvr,camera');
    assert.equal(sections.find(s => s.id === 'section:CAMERA').members.join(','), 'other');
    assert(positions.s2.x - positions.s1.x > 300);
    assert(positions.nvr.y - positions.ap1.y > 200);
    assert(positions.other.y - positions.camera.y > 200);
    assert.equal(new Set(sections.flatMap(s => Array.from(s.members))).size, 7);
});
