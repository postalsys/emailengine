'use strict';

// The subscription behind a license key (lib/license-subscription.js) and the three places that act
// on it: the decisions themselves, registering a key (lib/settings.js setLicense keeps the stored
// state for the same key, so posting it again or restarting with a license file cannot lift a
// suspension), the API worker's precheck (refuses API requests while suspended), and the license
// keys EmailEngine trusts (checkLicense and runPrechecks must agree, and a monthly key is reported).

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const msgpack = require('../lib/msgpack');

process.env.EENGINE_REDIS_PREFIX = 'test_license_subscription';

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const tools = require('../lib/tools');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const {
    decide,
    startupPlan,
    expiredSuspension,
    checkInterval,
    subscriptionView,
    isSuspended,
    keepsSubscriptionState,
    isSubscriptionLicense,
    LEGACY_GRACE,
    OVERDUE_CHECK_INTERVAL,
    CHECK_INTERVAL,
    MAX_LICENSE_CHECK_DELAY
} = require('../lib/license-subscription');

registerRedisTeardown(redis);

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2027-01-15T12:00:00Z');
const iso = time => new Date(time).toISOString();

test('a successful answer clears the state and schedules the next check by validatedUntil, capped', () => {
    const result = decide({ ok: true, data: { success: true, validatedUntil: iso(NOW + 2 * HOUR) }, now: NOW, subexp: NOW + DAY });
    assert.deepEqual(result, { clear: true, resume: true, subexp: null, suspend: null, removeLicense: false, nextCheck: NOW + 2 * HOUR });
    assert.equal(decide({ ok: true, data: { validatedUntil: iso(NOW + 365 * DAY) }, now: NOW }).nextCheck, NOW + MAX_LICENSE_CHECK_DELAY);
    assert.equal(decide({ ok: true, data: {}, now: NOW }).nextCheck, null);
});

test("a refusal without invalidate changes nothing: the license server's own trouble never stops EmailEngine", () => {
    assert.deepEqual(decide({ ok: false, data: { code: 'InvalidInput', invalidate: false }, now: NOW, subexp: null }), {
        clear: false,
        resume: false,
        subexp: null,
        suspend: null,
        removeLicense: false,
        nextCheck: null
    });
    assert.equal(decide({ ok: false, data: null, now: NOW }).clear, false);
});

test("the server's deadline is kept as it is, earlier or later, and checked again within the hour", () => {
    const until = NOW + 5 * DAY;
    const result = decide({
        ok: false,
        data: { invalidate: true, keepLicense: true, code: 'PaymentOverdue', graceUntil: iso(until) },
        now: NOW,
        subexp: NOW + 20 * DAY
    });
    assert.equal(result.subexp, until, 'an earlier deadline replaces the stored one');
    assert.equal(result.suspend, null, 'still working until then');
    assert.equal(result.resume, true, "and a stored suspension is lifted: the server's deadline counts, and it can move later");
    assert.equal(result.nextCheck, NOW + OVERDUE_CHECK_INTERVAL);
});

test('past the deadline with keepLicense: suspended, key kept', () => {
    const result = decide({
        ok: false,
        data: {
            invalidate: true,
            keepLicense: true,
            code: 'PaymentOverdue',
            error: 'Subscription payment overdue',
            graceUntil: iso(NOW - DAY),
            overdueSince: iso(NOW - 8 * DAY)
        },
        now: NOW,
        subexp: null
    });
    assert.equal(result.removeLicense, false);
    assert.equal(result.suspend.code, 'PaymentOverdue');
    assert.equal(result.suspend.since, iso(NOW - DAY));
    assert.equal(result.suspend.overdueSince, iso(NOW - 8 * DAY));
    assert.equal(result.subexp, NOW - DAY);
});

test('a server that names no deadline gets the legacy 28 days from the first refusal, and the key is removed after them', () => {
    const first = decide({ ok: false, data: { invalidate: true }, now: NOW, subexp: null });
    assert.equal(first.subexp, NOW + LEGACY_GRACE);
    assert.equal(first.removeLicense, false);

    const during = decide({ ok: false, data: { invalidate: true }, now: NOW, subexp: NOW + DAY });
    assert.equal(during.subexp, NOW + DAY, 'the window is not restarted');
    assert.equal(
        decide({ ok: false, data: { invalidate: true }, now: NOW, subexp: String(NOW + DAY) }).subexp,
        NOW + DAY,
        'nor when Redis hands it back as a string'
    );

    const after = decide({ ok: false, data: { invalidate: true }, now: NOW, subexp: NOW - 1 });
    assert.equal(after.removeLicense, true);
    assert.equal(after.suspend, null);
    assert.equal(after.resume, false);
});

test('subscription licenses are the ones without an expiry, a lifetime flag or a trial flag', () => {
    assert.equal(isSubscriptionLicense({ key: 'a' }), true);
    assert.equal(isSubscriptionLicense({ key: 'a', billing: 'monthly' }), true);
    assert.equal(isSubscriptionLicense({ key: 'a', lt: true }), false);
    assert.equal(isSubscriptionLicense({ key: 'a', trial: true, expires: iso(NOW + DAY) }), false);
    assert.equal(isSubscriptionLicense(false), false);
});

test('checks run daily, hourly while the subscription is not in good standing', () => {
    assert.equal(checkInterval({}), CHECK_INTERVAL);
    assert.equal(checkInterval({ subexp: String(NOW + DAY) }), OVERDUE_CHECK_INTERVAL);
    assert.equal(checkInterval({ subsusp: '{"code":"x"}' }), OVERDUE_CHECK_INTERVAL);
});

test('a start: suspended from the stored state, and an online check for monthly keys and overdue ones, at most hourly', () => {
    const yearly = { key: 'a' };
    const monthly = { key: 'b', billing: 'monthly' };

    assert.deepEqual(startupPlan({ details: yearly, now: NOW }), { suspension: null, checkNow: false }, 'a yearly key keeps the usual first delay');
    assert.equal(startupPlan({ details: monthly, now: NOW }).checkNow, true);
    assert.equal(startupPlan({ details: monthly, subcheck: NOW - 10 * 60 * 1000, now: NOW }).checkNow, false, 'checked ten minutes ago');

    const stored = startupPlan({ details: yearly, subsusp: JSON.stringify({ code: 'PaymentOverdue', since: iso(NOW - DAY) }), now: NOW });
    assert.equal(stored.suspension.code, 'PaymentOverdue');
    assert.equal(stored.checkNow, true);

    const ranOut = startupPlan({ details: yearly, subexp: NOW - HOUR, now: NOW });
    assert.ok(ranOut.suspension, 'a deadline that passed while stopped starts suspended');

    assert.equal(startupPlan({ details: yearly, subexp: NOW + DAY, now: NOW }).suspension, null, 'still inside the window');
    assert.equal(startupPlan({ details: { key: 'c', lt: true }, subsusp: '{"code":"x"}', now: NOW }).suspension, null, 'never for a lifetime license');
    assert.equal(startupPlan({ details: false, subsusp: '{"code":"x"}', now: NOW }).suspension, null);
});

test('a passed deadline implies a suspension when none is recorded', () => {
    assert.equal(expiredSuspension(NOW + DAY, null, NOW), null, 'not yet');
    assert.equal(expiredSuspension(null, null, NOW), null);
    assert.equal(expiredSuspension(NOW - HOUR, '{"code":"PaymentOverdue"}', NOW), null, 'one is recorded already');
    const implied = expiredSuspension(String(NOW - HOUR), null, NOW);
    assert.equal(implied.code, 'SubscriptionInactive');
    assert.equal(implied.since, iso(NOW - HOUR));
});

test('only the same key keeps the stored state when registered', () => {
    assert.equal(keepsSubscriptionState('abc', 'abc'), true);
    assert.equal(keepsSubscriptionState('abc', 'def'), false);
    assert.equal(keepsSubscriptionState(null, 'abc'), false);
});

test('the state as the license page and the API report it', () => {
    assert.equal(subscriptionView({ now: NOW }), null);
    assert.deepEqual(subscriptionView({ subexp: NOW + DAY, now: NOW }), {
        status: 'overdue',
        code: null,
        error: null,
        since: null,
        until: iso(NOW + DAY),
        days: 1
    });
    const suspended = subscriptionView({
        suspension: { code: 'MissingSubscription', error: 'Subscription expired', since: iso(NOW - DAY), endedAt: iso(NOW - DAY) },
        now: NOW
    });
    assert.equal(suspended.status, 'suspended');
    assert.equal(suspended.since, iso(NOW - DAY));
    assert.equal(suspended.days, 0, 'none left once paused');
    assert.equal(isSuspended({ subscription: suspended }), true);
    assert.equal(isSuspended({ subscription: { status: 'overdue' } }), false);
    assert.equal(isSuspended(null), false);
});

// --- registering a key, against Redis ---

const settingsKey = () => `${REDIS_PREFIX}settings`;
const subscriptionLicense = key => ({ application: '@postalsys/emailengine-app', key, licensedTo: 'Test' });
const cleanup = () => redis.hdel(settingsKey(), 'license', 'tract', 'subexp', 'subsusp', 'sentryEnabled', 'sentryAutoEnabled');

test('registering the same key again keeps a deadline and a suspension; a different key starts clean', async t => {
    t.beforeEach(cleanup);
    t.afterEach(cleanup);

    await t.test('the same key', async () => {
        await settings.setLicense(subscriptionLicense('same-key'), 'LICENSE-A');
        await redis.hset(settingsKey(), 'subexp', String(NOW), 'subsusp', '{"code":"PaymentOverdue"}');
        await settings.setLicense(subscriptionLicense('same-key'), 'LICENSE-A');
        const [subexp, subsusp] = await redis.hmget(settingsKey(), 'subexp', 'subsusp');
        assert.equal(subexp, String(NOW));
        assert.equal(subsusp, '{"code":"PaymentOverdue"}');
    });

    await t.test('a different key', async () => {
        await settings.setLicense(subscriptionLicense('old-key'), 'LICENSE-A');
        await redis.hset(settingsKey(), 'subexp', String(NOW), 'subsusp', '{"code":"PaymentOverdue"}');
        await settings.setLicense(subscriptionLicense('new-key'), 'LICENSE-B');
        const [subexp, subsusp] = await redis.hmget(settingsKey(), 'subexp', 'subsusp');
        assert.equal(subexp, null);
        assert.equal(subsusp, null);
    });

    await t.test('removing the license keeps both, so adding the same key back finds them', async () => {
        await settings.setLicense(subscriptionLicense('gone-key'), 'LICENSE-A');
        await redis.hset(settingsKey(), 'subexp', String(NOW), 'subsusp', '{"code":"PaymentOverdue"}');
        await settings.removeLicense();
        assert.deepEqual(await redis.hmget(settingsKey(), 'subexp', 'subsusp'), [String(NOW), '{"code":"PaymentOverdue"}']);
        await settings.setLicense(subscriptionLicense('gone-key'), 'LICENSE-A');
        assert.deepEqual(await redis.hmget(settingsKey(), 'subexp', 'subsusp'), [String(NOW), '{"code":"PaymentOverdue"}'], 'the same key back');
        await settings.setLicense(subscriptionLicense('other-key'), 'LICENSE-B');
        assert.deepEqual(await redis.hmget(settingsKey(), 'subexp', 'subsusp'), [null, null], 'a different key starts clean');
    });
});

test('the API precheck refuses requests while a suspension is recorded for a registered license', async () => {
    await redis.hset(settingsKey(), 'subsusp', '{"code":"PaymentOverdue"}', 'license', 'LICENSE-A');
    try {
        await assert.rejects(tools.runPrechecks(redis), err => err.code === 'ESubscriptionSuspended' && err.statusCode === 403);
        await redis.hdel(settingsKey(), 'license');
        await assert.rejects(tools.runPrechecks(redis), err => err.code === 'EContentValidation', 'with no license, the usual answer');
    } finally {
        await redis.hdel(settingsKey(), 'subsusp', 'license');
    }
    await assert.rejects(tools.runPrechecks(redis), err => err.code === 'EContentValidation', 'without one, an absent license fails as before');
});

// --- the keys ---

// The public keys as checkLicense() and runPrechecks() carry them, read from the source: the hex copy
// in runPrechecks() is deliberately not reachable from code
function trustedKeyLists() {
    const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'tools.js'), 'utf8');
    const listStart = source.indexOf('const LICENSE_VERIFY_KEYS = [');
    const listEnd = source.indexOf('\n];', listStart);
    const pemList = [...source.slice(listStart, listEnd).matchAll(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g)].map(match => match[0]);
    const prechecks = source.slice(source.indexOf('async runPrechecks(redis) {'));
    const hexList = [...prechecks.slice(0, prechecks.indexOf('].map(key => createPublicKey(key))')).matchAll(/'([0-9a-f]{200,})'/g)].map(match =>
        Buffer.from(match[1], 'hex').toString()
    );
    const der = pem => crypto.createPublicKey(pem).export({ type: 'spki', format: 'der' }).toString('base64');
    return { pem: pemList.map(der), hex: hexList.map(der) };
}

test('checkLicense and the API precheck trust the same three keys', () => {
    const { pem, hex } = trustedKeyLists();
    assert.equal(pem.length, 3, 'main, trial and monthly');
    assert.deepEqual(hex, pem, 'a key added to one list and not the other breaks every API route for its licenses');
});

// A license file signed with a key generated here, the way postalsys.com builds one
function signLicense(privateKey, payload) {
    const l = msgpack.encode(payload);
    const sign = crypto.createSign('SHA256');
    sign.write(l);
    sign.end();
    const signed = msgpack.encode({ l, s: sign.sign(privateKey) });
    return zlib.brotliCompressSync(signed).toString('base64url');
}

test('decodeLicense reports a license signed by a monthly-plan key, and refuses one signed by any other key', async () => {
    const standard = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const monthly = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const stranger = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const keys = [{ key: standard.publicKey }, { key: monthly.publicKey, billing: 'monthly' }];
    const payload = { a: '@postalsys/emailengine-app', k: crypto.randomBytes(12), n: 'Test Org', h: 'mail.example.com', c: Date.now() };

    const monthlyLicense = await tools.decodeLicense(signLicense(monthly.privateKey, payload), keys);
    assert.equal(monthlyLicense.billing, 'monthly');
    assert.equal(monthlyLicense.licensedTo, 'Test Org');

    const standardLicense = await tools.decodeLicense(signLicense(standard.privateKey, payload), keys);
    assert.equal(standardLicense.billing, undefined);

    await assert.rejects(tools.decodeLicense(signLicense(stranger.privateKey, payload), keys), err => err.code === 'ELicenseValidation');
    await assert.rejects(
        tools.checkLicense(signLicense(monthly.privateKey, payload)),
        err => err.code === 'ELicenseValidation',
        'production trusts only its own keys'
    );
});
