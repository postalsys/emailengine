'use strict';

// The MS Graph notification routes are unauthenticated, and every entry that failed validation was
// logged on its own with the request's fields, so a 1 MB body of empty entries wrote about 200 MB
// of log. The failures of one request are now one record.

const test = require('node:test');
const assert = require('node:assert').strict;

const { graphNotificationEntries, logRejectedGraphEntries, MAX_LOGGED_GRAPH_ENTRIES } = require('../lib/graph-notifications');

function makeRequest() {
    const records = [];
    return { records, request: { query: { account: 'acc1' }, logger: { warn: entry => records.push(entry) } } };
}

test('rejected entries of one request are logged as one record with a sample', () => {
    const { records, request } = makeRequest();
    const rejected = Array.from({ length: 2000 }, (_, i) => ({ receivedSubscriptionId: `s${i}`, subscriptionIdMatch: false, clientStateMatch: false }));
    logRejectedGraphEntries(request, rejected, { msg: 'Webhook validation failed - potential security issue', securityEvent: 'webhook_validation_failure' });
    assert.equal(records.length, 1);
    assert.equal(records[0].rejected, 2000);
    assert.equal(records[0].sample.length, MAX_LOGGED_GRAPH_ENTRIES);
    assert.equal(records[0].securityEvent, 'webhook_validation_failure');
    assert.equal(records[0].account, 'acc1');
});

test('nothing is logged when every entry validated', () => {
    const { records, request } = makeRequest();
    logRejectedGraphEntries(request, [], { msg: 'x' });
    assert.equal(records.length, 0);
});

test('graphNotificationEntries() keeps only object entries of an arbitrary body', () => {
    assert.deepEqual(graphNotificationEntries({ value: [{ a: 1 }, null, 'x', 5, { b: 2 }] }), [{ a: 1 }, { b: 2 }]);
    assert.deepEqual(graphNotificationEntries(null), []);
    assert.deepEqual(graphNotificationEntries({ value: 'nope' }), []);
});

test('partitionGraphEntries() keeps the entries of the stored subscription only', () => {
    const { partitionGraphEntries } = require('../lib/graph-notifications');
    const subscription = { id: 'sub1', clientState: 'state1' };
    const { valid, rejected } = partitionGraphEntries(
        [
            { subscriptionId: 'sub1', clientState: 'state1', changeType: 'created' },
            { subscriptionId: 'sub1', clientState: 'wrong', changeType: 'created' },
            { subscriptionId: 'other', clientState: 'state1', changeType: 'updated' }
        ],
        subscription,
        entry => ({ changeType: entry.changeType })
    );
    assert.equal(valid.length, 1);
    assert.deepEqual(rejected, [
        { subscriptionIdMatch: true, clientStateMatch: false, receivedSubscriptionId: 'sub1', changeType: 'created' },
        { subscriptionIdMatch: false, clientStateMatch: true, receivedSubscriptionId: 'other', changeType: 'updated' }
    ]);
});
