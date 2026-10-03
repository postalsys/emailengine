'use strict';

// GET /v1/account/{account} derives `type` and `sendOnly`, and it used to do so from `imap.disabled`
// directly. The authentication-failure safety net sets that same flag when it parks an account, so a
// parked IMAP account answered "type": "sending", "sendOnly": true - a client that checks the type
// before reading mail was told the account can only send, while GET /v1/accounts and the admin UI
// both kept reporting it as an IMAP account.
//
// Driven through the captured route handler against real records in the test database, and compared
// with what listAccounts() says about the same account, because agreeing with the listing is the
// property that broke.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const accountRoutes = require('../lib/api-routes/account-routes');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_FIELD } = require('../lib/consts');

registerRedisTeardown(redis);

const logger = { warn() {}, error() {}, debug() {}, info() {}, trace() {} };
const suffix = crypto.randomBytes(4).toString('hex');

// create() and listAccounts() ask the main thread for the run index over RPC, which decides whether a
// stored "connected" state belongs to this run. Nothing in this file depends on the answer.
const call = async message => (message.cmd === 'runIndex' ? 1 : null);

async function captureGetRoute(routeCall) {
    const routes = [];
    await accountRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }, routeCall ? { call: routeCall } : undefined));
    const route = routes.find(r => r.method === 'GET' && r.path === '/v1/account/{account}');
    assert.ok(route, 'GET /v1/account/{account} is registered');
    return route;
}

async function seedImapAccount(account, { disabled = false, parked = false } = {}) {
    const accountObject = new Account({ redis, account, secret: await getSecret(), logger, call });
    await accountObject.create({
        account,
        name: 'Seed',
        imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' }, disabled },
        smtp: { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'u', pass: 'p' } }
    });
    if (parked) {
        // What the safety net writes: the flag plus its own marker, which is what tells its park from
        // the operator's send-only switch
        await redis.hmset(`${REDIS_PREFIX}iad:${account}`, { [AUTH_FAILURE_DISABLED_FIELD]: String(Date.now()) });
    }
    return accountObject;
}

test('the account getter reports the same type as the accounts listing', async t => {
    const route = await captureGetRoute();

    const get = account => route.handler({ params: { account }, query: {}, headers: {}, logger });
    const listed = async account => {
        const listing = await new Account({ redis, secret: await getSecret(), logger, call }).listAccounts(false, account, 0, 10);
        const entry = listing.accounts.find(row => row.account === account);
        assert.ok(entry, `${account} is in the listing`);
        return entry;
    };

    const accounts = [];
    t.after(async () => {
        for (const account of accounts) {
            await new Account({ redis, account, secret: await getSecret(), logger, call }).delete().catch(() => false);
        }
    });

    await t.test('a parked account is still an IMAP account', async () => {
        const account = `type-parked-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account, { disabled: true, parked: true });

        const result = await get(account);
        assert.equal(result.type, 'imap');
        assert.ok(!result.sendOnly, 'a parked account is not send-only');
        assert.ok(result.authFailureDisabledAt, 'and it is still reported as parked');
        assert.equal((await listed(account)).type, 'imap', 'the listing already said so');
    });

    await t.test('an account the operator switched off is send-only', async () => {
        const account = `type-sendonly-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account, { disabled: true });

        const result = await get(account);
        assert.equal(result.type, 'sending');
        assert.equal(result.sendOnly, true);
        assert.equal(result.authFailureDisabledAt, null);
        assert.equal((await listed(account)).type, 'sending');
    });

    await t.test('a syncing account is an IMAP account', async () => {
        const account = `type-imap-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account);

        const result = await get(account);
        assert.equal(result.type, 'imap');
        assert.ok(!result.sendOnly);
        assert.equal((await listed(account)).type, 'imap');
    });
});

// `?quota=true` is the one field of this record read off the live connection, and a lookup that
// cannot answer used to fail the whole response with a 503 rather than leaving the field out.
// getQuota() loads the account with requireValid, and only connected, connecting and syncing pass
// that, so every ordinary IMAP account that happened to be disconnected, backing off after a connect
// error, parked or paused answered 503 for its entire record - as did one carrying no IMAP, SMTP or
// OAuth2 configuration at all. The skips in front of the call are a short-circuit; the thing that
// makes the field optional is that a failure is caught.
test('the account getter never lets the quota lookup fail the account', async t => {
    let quotaCalls = 0;
    let quotaFails = false;
    // Counted rather than refused, so the positive case can assert the request is still made
    const route = await captureGetRoute(async message => {
        if (message.cmd === 'getQuota') {
            quotaCalls++;
            if (quotaFails) {
                throw Object.assign(new Error('Quota request failed'), { statusCode: 400 });
            }
            return { usage: 1, limit: 2 };
        }
        return message.cmd === 'runIndex' ? 1 : {};
    });

    const get = account => route.handler({ params: { account }, query: { quota: true }, headers: {}, logger });

    const accounts = [];
    t.after(async () => {
        for (const account of accounts) {
            await new Account({ redis, account, secret: await getSecret(), logger, call }).delete().catch(() => false);
        }
    });

    // getQuota() refuses an account that has never connected, and the run index has to match or the
    // stored state reads as "init" again
    const markConnected = account => redis.hmset(`${REDIS_PREFIX}iad:${account}`, { state: 'connected', runIndex: '1' });

    await t.test('a connected IMAP account reports one', async () => {
        const account = `quota-imap-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account);
        await markConnected(account);

        const result = await get(account);
        assert.equal(quotaCalls, 1);
        assert.deepEqual(result.quota, { usage: 1, limit: 2 });
    });

    await t.test('an IMAP account that is not connected still returns its record', async () => {
        // The broad case: nothing is wrong with this account's configuration, it simply is not
        // connected right now, which is a state every account passes through
        const account = `quota-disconnected-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account);
        await redis.hmset(`${REDIS_PREFIX}iad:${account}`, { state: 'disconnected', runIndex: '1' });

        const result = await get(account);
        assert.equal(result.type, 'imap');
        assert.ok(!('quota' in result), 'the field is left out rather than failing the response');
    });

    await t.test('a failed quota request leaves the field out rather than the record', async () => {
        const account = `quota-failing-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account);
        await markConnected(account);

        quotaFails = true;
        t.after(() => {
            quotaFails = false;
        });

        const before = quotaCalls;
        const result = await get(account);
        assert.equal(quotaCalls, before + 1, 'the request was made');
        assert.equal(result.type, 'imap');
        assert.ok(!('quota' in result));
    });

    await t.test('an account with no IMAP, SMTP or OAuth2 configuration is not even asked', async () => {
        const account = `quota-unconfigured-${suffix}`;
        accounts.push(account);
        await new Account({ redis, account, secret: await getSecret(), logger, call }).create({ account, name: 'Unconfigured' });

        const before = quotaCalls;
        const result = await get(account);
        assert.equal(result.type, 'sending', 'nothing to connect with');
        assert.ok(!result.sendOnly, 'and a broken configuration is not a send-only one');
        assert.equal(quotaCalls, before, 'no worker round trip for a request that could never answer');
        assert.ok(!('quota' in result));
    });

    await t.test('an account the operator switched off is not even asked', async () => {
        const account = `quota-sendonly-${suffix}`;
        accounts.push(account);
        await seedImapAccount(account, { disabled: true });

        const before = quotaCalls;
        await get(account);
        assert.equal(quotaCalls, before);
    });
});
