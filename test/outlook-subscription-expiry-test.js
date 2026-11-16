'use strict';

// What ensureSubscriptionLocked() does with a stored MS Graph subscription, by how long it has
// left: one inside the clock-skew buffer is treated as gone and created anew, one inside the
// renewal window is renewed, and anything else (including an expiry that does not parse) is left
// alone.

const test = require('node:test');
const { after } = require('node:test');
const assert = require('node:assert').strict;
const exitWhenStandalone = require('./helpers/exit-standalone');

require('./helpers/mock-db').installDbMock();

after(() => {
    // outlook-client pulls in lib/settings -> lib/tools, whose Redis handles keep the event loop
    // alive after the assertions are done
    exitWhenStandalone();
});

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { classifyExistingSubscription } = require('../lib/email-client/outlook/subscription-expiry');
const { OUTLOOK_CLOCK_SKEW_BUFFER, OUTLOOK_EXPIRATION_RENEW_TIME } = require('../lib/consts');

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

function makeClient(stored, { renewResult = { success: true } } = {}) {
    const outlook = new OutlookClient('expiry-account', { redis: {} });
    const calls = { renew: [], requests: [], saved: [], cleared: 0 };

    outlook.logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };
    outlook.getAccountKey = () => 'iad:expiry-account';
    outlook.oauth2UserPath = 'me';
    outlook.getStoredSubscription = async () => JSON.parse(JSON.stringify(stored));
    outlook.saveStoredSubscription = async sub => {
        calls.saved.push(JSON.parse(JSON.stringify(sub)));
    };
    outlook.clearSubscriptionFailure = async () => {
        calls.cleared++;
    };
    outlook.renewSubscription = async opts => {
        calls.renew.push(opts);
        return renewResult;
    };
    outlook.scheduleSubscriptionRetry = () => {};
    outlook.request = async (url, method, payload) => {
        calls.requests.push({ url, method, payload });
        return { id: 'sub-new', expirationDateTime: new Date(Date.now() + 3 * 24 * HOUR).toISOString(), clientState: payload.clientState };
    };

    return { outlook, calls };
}

const stored = expiresIn => ({
    id: 'sub-old',
    expirationDateTime: typeof expiresIn === 'number' ? new Date(Date.now() + expiresIn).toISOString() : expiresIn,
    state: { state: 'created', time: Date.now() }
});

const run = outlook =>
    outlook.ensureSubscriptionLocked({ clearExisting: false, serviceUrl: 'https://ee.example.com', notificationBaseUrl: 'https://ee.example.com' });

test('ensureSubscriptionLocked() by the time a stored subscription has left', async t => {
    await t.test('inside the clock-skew buffer it is replaced with a new subscription', async () => {
        const { outlook, calls } = makeClient(stored(30 * 1000));

        await run(outlook);

        assert.equal(calls.renew.length, 0, 'a subscription that is about to expire is not renewed');
        assert.equal(calls.requests.length, 1);
        assert.equal(calls.requests[0].url, '/subscriptions');
        assert.equal(calls.requests[0].method, 'post');
        assert.equal(calls.saved[0].state.state, 'creating', 'the creating state is saved before the POST');
        assert.equal(calls.saved.at(-1).id, 'sub-new');
    });

    await t.test('already expired, it is replaced too', async () => {
        const { outlook, calls } = makeClient(stored(-HOUR));

        await run(outlook);

        assert.equal(calls.renew.length, 0);
        assert.equal(calls.requests.length, 1);
    });

    await t.test('past the buffer but inside the renewal window it is renewed under the held lock', async () => {
        const { outlook, calls } = makeClient(stored(5 * MINUTE));

        const result = await run(outlook);

        assert.deepEqual(calls.renew, [{ force: false, skipLock: true }]);
        assert.equal(calls.requests.length, 0);
        assert.equal(result, true);
    });

    await t.test('a renewal that finds it expired creates a new one', async () => {
        const { outlook, calls } = makeClient(stored(23 * HOUR), { renewResult: { success: false, reason: 'expired' } });

        await run(outlook);

        assert.equal(calls.renew.length, 1);
        assert.equal(calls.requests.length, 1);
    });

    await t.test('a renewal that fails otherwise reports the failure and creates nothing', async () => {
        const { outlook, calls } = makeClient(stored(HOUR), { renewResult: { success: false, reason: 'error' } });

        const result = await run(outlook);

        assert.equal(result, false);
        assert.equal(calls.requests.length, 0);
    });

    await t.test('beyond the renewal window it is left alone and any failure cleared', async () => {
        const { outlook, calls } = makeClient(stored(25 * HOUR));

        await run(outlook);

        assert.equal(calls.renew.length, 0);
        assert.equal(calls.requests.length, 0);
        assert.equal(calls.cleared, 1);
        assert.equal(outlook.subscriptionState, 'valid');
    });

    await t.test('an expiry that does not parse counts as valid', async () => {
        const { outlook, calls } = makeClient(stored('not a date'));

        await run(outlook);

        assert.equal(calls.renew.length, 0);
        assert.equal(calls.requests.length, 0);
        assert.equal(outlook.subscriptionState, 'valid');
    });
});

test('classifyExistingSubscription()', async t => {
    const now = Date.parse('2026-11-16T12:00:00Z');
    const at = offset => new Date(now + offset);

    await t.test('expired once inside the clock-skew buffer', () => {
        assert.equal(classifyExistingSubscription(at(-HOUR), now), 'expired');
        assert.equal(classifyExistingSubscription(at(0), now), 'expired');
        assert.equal(classifyExistingSubscription(at(OUTLOOK_CLOCK_SKEW_BUFFER - 1), now), 'expired');
    });

    await t.test('renewed from the buffer up to the renewal window', () => {
        assert.equal(classifyExistingSubscription(at(OUTLOOK_CLOCK_SKEW_BUFFER), now), 'renew');
        assert.equal(classifyExistingSubscription(at(OUTLOOK_EXPIRATION_RENEW_TIME - 1), now), 'renew');
    });

    await t.test('valid from the renewal window on, and when there is no expiry to read', () => {
        assert.equal(classifyExistingSubscription(at(OUTLOOK_EXPIRATION_RENEW_TIME), now), 'valid');
        assert.equal(classifyExistingSubscription(at(3 * 24 * HOUR), now), 'valid');
        assert.equal(classifyExistingSubscription(null, now), 'valid');
    });
});
