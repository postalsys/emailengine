'use strict';

// A server can keep a long-lived IMAP session alive while its view of the selected mailbox stops
// moving: no EXISTS arrives, and FETCH or SEARCH on that session answer from the frozen view, so
// the account stays "connected" and receives nothing until it reconnects. Observed on a Zoho
// hosted mailbox for more than nine days, while LIST and STATUS of other folders kept answering
// OK every resync pass. stale-view.js decides when a second connection looks at the main mailbox
// and when what it sees is reason enough to drop the primary connection.
//
// Pure: no Redis, no connections - the module under test is dependency-free.

const test = require('node:test');
const assert = require('node:assert').strict;

const { planStaleViewProbe, evaluateStaleViewProbe, STALE_CONFIRMATIONS } = require('../lib/email-client/imap/stale-view');

const MINUTE = 60 * 1000;
const INTERVAL = 60 * MINUTE;
const UIDVALIDITY = 1717171717n;

const stored = (uidNext, uidValidity = UIDVALIDITY) => ({ uidNext, uidValidity });
const server = (uidNext, uidValidity = UIDVALIDITY) => ({ path: 'INBOX', uidNext, uidValidity });

// Runs planStaleViewProbe() from a fresh connection until the first pass that probes
const quietUntilProbe = (storedUidNext, start) => {
    let first = planStaleViewProbe(null, storedUidNext, start, INTERVAL);
    let second = planStaleViewProbe(first.state, storedUidNext, start + INTERVAL, INTERVAL);
    assert.equal(second.probe, true);
    return second.state;
};

test('planStaleViewProbe', async t => {
    await t.test('does nothing while the check is disabled', () => {
        for (const interval of [0, false, null, undefined]) {
            assert.deepEqual(planStaleViewProbe(null, 100, 0, interval), { probe: false, state: null });
        }
    });

    await t.test('does nothing without a stored UIDNEXT to compare against', () => {
        for (const uidNext of [false, 0, undefined]) {
            assert.deepEqual(planStaleViewProbe(null, uidNext, 0, INTERVAL), { probe: false, state: null });
        }
    });

    await t.test('the first pass on a connection only records a baseline', () => {
        const result = planStaleViewProbe(null, 100, 1000, INTERVAL);
        assert.equal(result.probe, false);
        assert.deepEqual(result.state, { checkedAt: 1000, uidNext: 100, confirmations: 0 });
    });

    await t.test('probes once the main mailbox has stored nothing new for the interval', () => {
        const baseline = planStaleViewProbe(null, 100, 0, INTERVAL).state;
        assert.equal(planStaleViewProbe(baseline, 100, INTERVAL - 1, INTERVAL).probe, false);
        assert.equal(planStaleViewProbe(baseline, 100, INTERVAL, INTERVAL).probe, true);
    });

    await t.test('a probe that never answers waits a whole interval before the next one', () => {
        const baseline = planStaleViewProbe(null, 100, 0, INTERVAL).state;
        const probed = planStaleViewProbe(baseline, 100, INTERVAL, INTERVAL);
        assert.equal(probed.probe, true);
        // the probe failed, so evaluateStaleViewProbe() never ran; the next resync pass follows
        assert.equal(planStaleViewProbe(probed.state, 100, INTERVAL + MINUTE, INTERVAL).probe, false);
        assert.equal(planStaleViewProbe(probed.state, 100, 2 * INTERVAL, INTERVAL).probe, true);
    });

    await t.test('an arrival stored by the primary connection starts the quiet period over', () => {
        const baseline = planStaleViewProbe(null, 100, 0, INTERVAL).state;
        const result = planStaleViewProbe(baseline, 101, INTERVAL, INTERVAL);
        assert.equal(result.probe, false);
        assert.deepEqual(result.state, { checkedAt: INTERVAL, uidNext: 101, confirmations: 0 });
    });
});

test('evaluateStaleViewProbe', async t => {
    await t.test('a server that is not ahead clears the confirmations', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        const result = evaluateStaleViewProbe(state, stored(100), 100, server(100), INTERVAL);
        assert.deepEqual(result, { stale: false, ahead: false, state: { checkedAt: INTERVAL, uidNext: 100, confirmations: 0 } });
    });

    await t.test('one probe finding the server ahead is not enough', () => {
        const state = quietUntilProbe(100, 0);
        const result = evaluateStaleViewProbe(state, stored(100), 100, server(167), INTERVAL);
        assert.equal(result.ahead, true);
        assert.equal(result.stale, false);
        assert.equal(result.state.confirmations, 1);
    });

    await t.test(`${STALE_CONFIRMATIONS} probes in a row finding the server ahead mark the view stale`, () => {
        let state = quietUntilProbe(100, 0);
        let now = INTERVAL;
        let result;
        for (let i = 0; i < STALE_CONFIRMATIONS; i++) {
            result = evaluateStaleViewProbe(state, stored(100), 100, server(167), now);
            now += INTERVAL;
            state = planStaleViewProbe(result.state, 100, now, INTERVAL).state;
        }
        assert.equal(result.stale, true);
        // the next connection's streak does not inherit this one
        assert.equal(result.state.confirmations, 0);
    });

    await t.test('an arrival stored while the probe was running proves the connection alive', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        const result = evaluateStaleViewProbe(state, stored(101), 101, server(167), INTERVAL);
        assert.deepEqual(result, { stale: false, ahead: false, state: { checkedAt: INTERVAL, uidNext: 101, confirmations: 0 } });
    });

    await t.test('a frozen session is behind the server even when it agrees with the store', () => {
        // The stale session reports the UIDNEXT it had when its view stopped moving
        const state = { checkedAt: 0, uidNext: 236, confirmations: 1 };
        assert.equal(evaluateStaleViewProbe(state, stored(236), 236, server(303), INTERVAL).stale, true);
    });

    await t.test('a session that knows the server UIDNEXT is not behind a lagging store', () => {
        // A message delivered and expunged before the primary fetched it leaves the stored
        // UIDNEXT behind for good on a CONDSTORE server; the SELECT of the session after a
        // reconnect reports the server's value, so the check must not reconnect again
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        const result = evaluateStaleViewProbe(state, stored(100), 101, server(101), INTERVAL);
        assert.equal(result.ahead, false);
        assert.equal(result.state.confirmations, 0);
    });

    await t.test('a session that reports no UIDNEXT falls back to the stored one', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 0 };
        assert.equal(evaluateStaleViewProbe(state, stored(100), false, server(101), INTERVAL).ahead, true);
    });

    await t.test('UIDs of another folder incarnation are not compared', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        assert.equal(evaluateStaleViewProbe(state, stored(100), 100, server(167, 99n), INTERVAL).ahead, false);
        assert.equal(evaluateStaleViewProbe(state, stored(100, false), 100, server(167), INTERVAL).ahead, false);
    });

    await t.test('a STATUS answer without UIDNEXT is not a finding', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        for (const answer of [null, { path: 'INBOX', uidValidity: UIDVALIDITY }]) {
            const result = evaluateStaleViewProbe(state, stored(100), 100, answer, INTERVAL);
            assert.equal(result.ahead, false);
            assert.equal(result.state.confirmations, 0);
        }
    });

    await t.test('without a stored UIDNEXT the check has no state', () => {
        const state = { checkedAt: 0, uidNext: 100, confirmations: 1 };
        assert.deepEqual(evaluateStaleViewProbe(state, stored(false), false, server(167), INTERVAL), { stale: false, ahead: false, state: null });
    });
});
