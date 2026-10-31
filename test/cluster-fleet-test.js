'use strict';

// lib/cluster/fleet.js: the instance-wide numbers /v1/stats reports when several instances share
// one Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { summarizeFleet } = require('../lib/cluster/fleet');

test('summarizeFleet()', async t => {
    await t.test('sums every instance, taking this one fresh', () => {
        const members = [
            { id: 'b', ready: true, owned: 3, connections: { connected: 3 }, version: '2.88.0', started: 1000, heartbeat: 2000, address: '10.0.0.2:3001' },
            { id: 'a', ready: true, owned: 2, connections: { connected: 1, connecting: 1 }, version: '2.88.0' }
        ];
        const { connections, instances } = summarizeFleet(members, 'a', { connected: 2, disconnected: 0 });
        assert.deepEqual(connections, { connected: 5, disconnected: 0 });
        assert.deepEqual(
            instances.map(instance => instance.id),
            ['a', 'b']
        );
        assert.equal(instances[0].self, true);
        assert.deepEqual(instances[0].connections, { connected: 2, disconnected: 0 });
        assert.equal(instances[1].accounts, 3);
        assert.equal(instances[1].started, new Date(1000).toISOString());
        assert.equal(instances[1].address, undefined, 'addresses are not reported');
    });

    await t.test('an instance that is not registered still counts what it serves', () => {
        const { connections, instances } = summarizeFleet([], 'a', { connected: 4 });
        assert.deepEqual(connections, { connected: 4 });
        assert.deepEqual(instances, []);
    });

    await t.test('a record without counts adds nothing', () => {
        const { connections } = summarizeFleet([{ id: 'b' }], 'a', { connected: 1 });
        assert.deepEqual(connections, { connected: 1 });
    });
});

test('instanceRows()', () => {
    const { instanceRows } = require('../lib/cluster/fleet');
    const rows = instanceRows([
        { id: 'c', ready: true, connections: { connected: 4 }, lastHeartbeat: '2026-10-31T10:00:00.000Z' },
        { id: 'b', ready: false, self: true },
        { id: 'a', ready: true }
    ]);
    assert.deepEqual(
        rows.map(row => row.id),
        ['b', 'a', 'c'],
        'this instance first, then by id'
    );
    assert.equal(rows[0].statusLabel, 'Not taking accounts');
    assert.equal(rows[2].statusVariant, 'success');
    assert.equal(rows[2].connected, 4);
    assert.equal(rows[2].heartbeatTime, '2026-10-31T10:00:00.000Z');
    assert.deepEqual(instanceRows({}), [], 'anything but a list is no rows');
});

test('loadFleetView()', async () => {
    const { loadFleetView } = require('../lib/cluster/fleet');
    const logger = { warn() {} };
    const two = [
        { id: 'a', self: true, ready: true },
        { id: 'b', ready: true }
    ];
    assert.deepEqual((await loadFleetView(async () => two, logger)).selfInstance, 'a');
    assert.equal((await loadFleetView(async () => two, logger)).instances.length, 2);
    assert.equal((await loadFleetView(async () => [two[0]], logger)).instances, false, 'a lone instance shows no card');
    const failed = await loadFleetView(async () => {
        throw new Error('timeout');
    }, logger);
    assert.deepEqual(failed, { instances: false, selfInstance: null });
});
