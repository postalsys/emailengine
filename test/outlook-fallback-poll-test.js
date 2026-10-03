'use strict';

// Graph loses change notifications without reporting it: the `missed` lifecycle event only covers
// deliveries our endpoint failed. A HotHawk account received five messages in an afternoon with no
// notification and no lifecycle event, and they surfaced only when someone pressed Run sync, inside
// the four-hour recovery window - the oldest one never did. These tests pin the periodic recovery
// pass that now runs on every connected Graph account, and the Run sync `since` that reaches past
// the window.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient, parseFallbackPollInterval } = require('../lib/email-client/outlook-client');
const { Account } = require('../lib/account');
const { OUTLOOK_MISSED_LOOKBACK } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');
const { createMockLogger } = require('./helpers/mock-logger');

registerRedisTeardown(redis);

function makeOutlook(accountObject, account = `poll-${process.pid}`) {
    const outlook = new OutlookClient(account, { redis });
    outlook.logger = noopLogger;
    outlook.oauth2UserPath = 'me';
    outlook.accountObject = accountObject;
    outlook._updateLastNotificationTime = async () => {};
    outlook.getMessageFetchOptions = async () => ({});
    return outlook;
}

test('parseFallbackPollInterval()', () => {
    const DEFAULT = 10 * 60 * 1000;
    assert.equal(parseFallbackPollInterval(undefined), DEFAULT, 'unset gets the default');
    assert.equal(parseFallbackPollInterval(''), DEFAULT);
    assert.equal(parseFallbackPollInterval('  '), DEFAULT);
    assert.equal(parseFallbackPollInterval('0'), 0, '0 switches the pass off');
    assert.equal(parseFallbackPollInterval('5m'), 5 * 60 * 1000, 'a duration with a unit');
    assert.equal(parseFallbackPollInterval('900000'), 900000, 'plain milliseconds');
    assert.equal(parseFallbackPollInterval('1s'), 10 * 1000, 'never shorter than ten seconds');
    assert.equal(parseFallbackPollInterval('every so often'), DEFAULT, 'an unreadable value gets the default');
    assert.equal(parseFallbackPollInterval('-5'), DEFAULT, 'so does a negative one');
});

test('OutlookClient periodic recovery timer', async t => {
    await t.test('the first pass runs at a random point of the interval, then on every interval', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        t.mock.method(Math, 'random', () => 0.5);

        const outlook = makeOutlook(null);
        outlook.fallbackPollInterval = 60000;
        let ticks = 0;
        outlook.requestPeriodicRecovery = () => ticks++;

        outlook.setupFallbackPollTimer({ first: true });
        t.mock.timers.tick(29999);
        assert.equal(ticks, 0);
        t.mock.timers.tick(1);
        assert.equal(ticks, 1, 'half of the interval with Math.random() at 0.5');

        t.mock.timers.tick(59999);
        assert.equal(ticks, 1);
        t.mock.timers.tick(1);
        assert.equal(ticks, 2, 'then a full interval');

        outlook.closed = true;
        outlook.clearTimers();
        t.mock.timers.tick(10 * 60000);
        assert.equal(ticks, 2, 'stopped with the other timers');
    });

    await t.test('is not armed when switched off or closed', async t => {
        t.mock.timers.enable({ apis: ['setTimeout'] });

        const off = makeOutlook(null);
        off.fallbackPollInterval = 0;
        off.setupFallbackPollTimer({ first: true });
        assert.equal(off.fallbackPollTimer, null);

        const closed = makeOutlook(null);
        closed.closed = true;
        closed.setupFallbackPollTimer({ first: true });
        assert.equal(closed.fallbackPollTimer, null);
    });

    await t.test('a tick asks the drain for a pass, without touching the deferred store', async () => {
        const outlook = makeOutlook({
            queueMissedRecovery: async () => assert.fail('the periodic request is not stored')
        });
        outlook.state = 'connected';
        let drains = 0;
        outlook.triggerSync = () => drains++;

        outlook.requestPeriodicRecovery();
        assert.equal(outlook.periodicRecoveryDue, true);
        assert.equal(drains, 1);
    });

    await t.test('a tick does nothing unless the account is connected', async () => {
        const outlook = makeOutlook(null);
        outlook.triggerSync = () => assert.fail('no drain');

        // a refused credential, a tenant that disabled the service, a parked account
        for (const state of ['authenticationError', 'connectError', 'unset', 'connecting', 'disconnected']) {
            outlook.state = state;
            outlook.requestPeriodicRecovery();
        }

        outlook.state = 'connected';
        outlook.closed = true;
        outlook.requestPeriodicRecovery();
        assert.equal(outlook.periodicRecoveryDue, false);
    });
});

test('OutlookClient periodic recovery pass', async t => {
    await t.test('the drain runs a requested pass once, from where the previous pass finished', async () => {
        const outlook = makeOutlook({ listDueChangeEvents: async () => ({ due: [], next: null }), pullQueueEvent: async () => null });
        const lastPass = Date.now() - 10 * 60 * 1000;
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, String(lastPass)] });
        const passes = [];
        outlook.syncMissedMessages = async ({ since, reason, options }) => passes.push({ since, reason, lazy: typeof options === 'function' });

        await outlook.processHistory();
        assert.deepEqual(passes, [], 'nothing was requested');

        outlook.periodicRecoveryDue = true;
        await outlook.processHistory();
        await outlook.processHistory();
        assert.deepEqual(passes, [{ since: lastPass - 2 * 60 * 1000, reason: 'periodic', lazy: true }]);
    });

    await t.test('is skipped when a recovery earlier in the same drain covered its window', async () => {
        const outlook = makeOutlook(null);
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        outlook.syncMissedMessages = async () => assert.fail('already covered');
        outlook.periodicRecoveryDue = true;

        await outlook.runPeriodicRecovery({ recoveredSince: Date.now() - 24 * 60 * 60 * 1000 });
        assert.equal(outlook.periodicRecoveryDue, false);
    });

    await t.test('a failed pass is logged and left to the next one', async () => {
        const outlook = makeOutlook(null);
        outlook.logger = createMockLogger();
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        outlook.syncMissedMessages = async () => {
            throw new Error('Graph is down');
        };
        outlook.periodicRecoveryDue = true;

        const context = {};
        await outlook.runPeriodicRecovery(context);

        assert.equal(context.recoveredSince, undefined, 'a failed pass covers nothing for the rest of the drain');
        assert.ok(outlook.logger.entries.some(entry => entry.level === 'warn' && entry.err?.message === 'Graph is down'));
    });

    await t.test('a pass that found nothing reads no fetch options and stays out of the info log', async () => {
        const outlook = makeOutlook(null, `poll-log-${process.pid}`);
        outlook.logger = createMockLogger();
        outlook.request = async () => ({ value: [] });

        try {
            await outlook.syncMissedMessages({ since: Date.now() - 60000, options: () => assert.fail('options are not needed'), reason: 'periodic' });
            const recoveryLines = outlook.logger.entries.filter(entry => /recovery|Recovering/.test(entry.msg || ''));
            assert.equal(recoveryLines.length, 2);
            assert.ok(
                recoveryLines.every(entry => entry.level === 'debug'),
                'nothing above debug'
            );

            outlook.logger.entries.length = 0;
            await outlook.syncMissedMessages({ since: Date.now() - 60000, options: {}, reason: 'manual' });
            assert.ok(
                outlook.logger.entries.some(
                    entry => entry.level === 'info' && entry.msg === 'Missed notification recovery completed' && entry.reason === 'manual'
                )
            );
        } finally {
            await redis.del(outlook.getAccountKey());
        }
    });

    await t.test('a pass that recovered a message resolves the options once and says so in the info log', async () => {
        const outlook = makeOutlook(null, `poll-found-${process.pid}`);
        outlook.logger = createMockLogger();
        const ids = [`found-a-${process.pid}`, `found-b-${process.pid}`];
        outlook.request = async () => ({ value: ids.map(id => ({ id, parentFolderId: 'f1' })) });
        outlook.getCachedMailboxListing = async () => [{ id: 'f1', pathName: 'INBOX' }];
        outlook.prepareNewMessage = async id => ({ id, path: 'INBOX' });
        const announced = [];
        outlook.processNew = async messageData => {
            announced.push(messageData.id);
            messageData.path = undefined;
        };
        let resolved = 0;

        try {
            await outlook.syncMissedMessages({
                since: Date.now() - 60000,
                options: async () => {
                    resolved++;
                    return {};
                },
                reason: 'periodic'
            });
            assert.deepEqual(announced, ids);
            assert.equal(resolved, 1);
            assert.ok(
                outlook.logger.entries.some(entry => entry.level === 'info' && entry.msg === 'Missed notification recovery completed' && entry.recovered === 2)
            );
        } finally {
            await redis.del(outlook.getAnnouncedKey(), outlook.getAccountKey());
        }
    });
});

test('Account.queueMissedRecovery() records how far back a manual request looks', async () => {
    const account = new Account({ redis, account: `queue-manual-${process.pid}`, logger: noopLogger, call: async () => {} });
    const since = Date.now() - 24 * 60 * 60 * 1000;
    const before = Date.now();

    try {
        await account.queueMissedRecovery({ reason: 'manual', since });
        await account.queueMissedRecovery();
        const events = (await account.listDueChangeEvents()).due.map(entry => entry.event);

        const manual = events.find(event => event.reason === 'manual');
        assert.equal(manual.since, since);
        assert.ok(manual.receivedAt >= before);
        assert.equal(events.find(event => event.reason === 'missed').since, undefined, 'the lifecycle event names no start');
    } finally {
        await redis.del(account.getDeferredQueueKey());
    }
});

test('OutlookClient stored recovery requests', async t => {
    await t.test('a request stored before reasons were recorded is a lifecycle one', async () => {
        const outlook = makeOutlook(null);
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        const receivedAt = Date.now();
        const passes = [];
        outlook.syncMissedMessages = async ({ since, reason }) => passes.push({ since, reason });

        await outlook.processChangeEvent({ type: 'missedRecovery', receivedAt }, {});

        assert.deepEqual(passes, [{ since: receivedAt - OUTLOOK_MISSED_LOOKBACK, reason: 'missed' }]);
    });

    await t.test('an explicit start reaches past every floor', async () => {
        const outlook = makeOutlook(null);
        const receivedAt = Date.now();
        const lastPass = receivedAt - 60 * 1000;
        // a recent pass and a recent announced-set start would both clamp the usual window
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [String(lastPass), String(lastPass), String(lastPass)] });
        const since = receivedAt - 3 * 24 * 60 * 60 * 1000;
        const passes = [];
        outlook.syncMissedMessages = async ({ since, reason }) => passes.push({ since, reason });

        await outlook.processChangeEvent({ type: 'missedRecovery', receivedAt, reason: 'manual', since }, {});

        assert.deepEqual(passes, [{ since, reason: 'manual' }]);
    });

    await t.test('a failed stored pass is thrown, so the deferred store retries it', async () => {
        const outlook = makeOutlook(null);
        outlook.redis = Object.assign(Object.create(redis), { hmget: async () => [null, null, null] });
        outlook.syncMissedMessages = async () => {
            throw new Error('Graph is down');
        };

        await assert.rejects(outlook.processChangeEvent({ type: 'missedRecovery', receivedAt: Date.now(), reason: 'manual' }, {}), /Graph is down/);
    });
});

test('Account.requestSync() hands the requested start to the worker', async () => {
    const calls = [];
    const account = new Account({ redis, account: `request-sync-${process.pid}`, logger: noopLogger, call: async message => calls.push(message) });
    account.loadAccountData = async () => ({});

    await account.requestSync({ sync: true, since: new Date('2026-10-02T13:00:00.000Z') });
    await account.requestSync({ sync: true });
    await account.requestSync({ sync: false, since: new Date('2026-10-02T13:00:00.000Z') });

    assert.equal(calls.length, 2, 'nothing is asked without sync');
    assert.equal(calls[0].since, Date.parse('2026-10-02T13:00:00.000Z'), 'as epoch ms, the form the recovery request stores');
    assert.equal(calls[1].since, undefined);
});
