'use strict';

// POST /admin/accounts/{account}/bulk, the one-account step the accounts list's bulk actions are
// made of (lib/ui-routes/account-bulk.js). Driven through the captured route handler against real
// account records, because what matters is what ends up stored: a pause has to be the operator's
// switch and not look like a park, a resume has to lift either kind, and an action that does not
// apply has to leave the account alone and say why.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { registerPostAccountsBulk, bulkSkipReason, revocationNote } = require('../lib/ui-routes/account-bulk');
const registerRedisTeardown = require('./helpers/redis-teardown');
const exitWhenStandalone = require('./helpers/exit-standalone');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_FIELD } = require('../lib/consts');

registerRedisTeardown(redis);
exitWhenStandalone();

const logger = { warn() {}, error() {}, debug() {}, info() {}, trace() {}, child: () => logger };
const suffix = crypto.randomBytes(4).toString('hex');

const commands = [];
const call = async message => {
    commands.push(message);
    return message.cmd === 'runIndex' ? 1 : null;
};

function captureRoute() {
    const routes = [];
    registerPostAccountsBulk({ route: cfg => routes.push(cfg) }, { call });
    assert.equal(routes.length, 1);
    return routes[0];
}

async function seed(account, data) {
    const accountObject = new Account({ redis, account, secret: await getSecret(), logger, call });
    await accountObject.create(Object.assign({ account, name: account }, data));
    return accountObject;
}

const imapSettings = (extra = {}) => ({
    imap: Object.assign({ host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } }, extra),
    smtp: { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'u', pass: 'p' } }
});

async function storedImap(account) {
    return JSON.parse(await redis.hget(`${REDIS_PREFIX}iad:${account}`, 'imap'));
}

test('bulk account actions', async t => {
    const route = captureRoute();
    const run = (account, action, payload = {}) =>
        route.handler({ params: { account }, payload: Object.assign({ action, revoke: false }, payload), logger, app: { ip: '127.0.0.1' } });

    const accounts = [];
    t.after(async () => {
        for (const account of accounts) {
            await new Account({ redis, account, secret: await getSecret(), logger, call }).delete().catch(() => false);
        }
    });

    await t.test('pause is the operator switch, resume lifts it, and repeats are skipped', async () => {
        const account = `bulk-imap-${suffix}`;
        accounts.push(account);
        await seed(account, imapSettings());

        assert.deepEqual(await run(account, 'pause'), { result: 'done' });
        assert.equal((await storedImap(account)).disabled, true);
        assert.equal(await redis.hget(`${REDIS_PREFIX}iad:${account}`, AUTH_FAILURE_DISABLED_FIELD), null, 'a pause is not a park');
        // the IMAP settings survive the partial write
        assert.equal((await storedImap(account)).host, 'imap.example.com');

        assert.deepEqual(await run(account, 'pause'), { result: 'skipped', reason: 'Already paused' });
        assert.deepEqual(await run(account, 'reconnect'), { result: 'skipped', reason: 'Syncing is paused' });

        assert.deepEqual(await run(account, 'resume'), { result: 'done' });
        assert.equal((await storedImap(account)).disabled, false);
        assert.deepEqual(await run(account, 'resume'), { result: 'skipped', reason: 'Not paused' });

        commands.length = 0;
        assert.deepEqual(await run(account, 'reconnect'), { result: 'done' });
        assert.ok(commands.some(message => message.cmd === 'reconnect' && message.account === account));
    });

    await t.test('resume lifts a park by the safety net too', async () => {
        const account = `bulk-parked-${suffix}`;
        accounts.push(account);
        await seed(account, imapSettings({ disabled: true }));
        await redis.hset(`${REDIS_PREFIX}iad:${account}`, AUTH_FAILURE_DISABLED_FIELD, new Date().toISOString());

        assert.deepEqual(await run(account, 'resume'), { result: 'done' });
        assert.equal((await storedImap(account)).disabled, false);
        assert.equal(await redis.hget(`${REDIS_PREFIX}iad:${account}`, AUTH_FAILURE_DISABLED_FIELD), null);
    });

    await t.test('an SMTP-only account has nothing to pause, resume or reconnect', async () => {
        const account = `bulk-smtp-${suffix}`;
        accounts.push(account);
        await seed(account, { smtp: imapSettings().smtp });

        for (const action of ['pause', 'resume', 'reconnect']) {
            assert.deepEqual(await run(account, action), { result: 'skipped', reason: 'Sends only, nothing to sync' }, action);
        }
    });

    await t.test('delete removes the account, and a second delete finds it gone', async () => {
        const account = `bulk-delete-${suffix}`;
        await seed(account, imapSettings());

        assert.deepEqual(await run(account, 'delete'), { result: 'done' });
        assert.equal(await redis.exists(`${REDIS_PREFIX}iad:${account}`), 0);
        assert.deepEqual(await run(account, 'delete'), { result: 'missing' });
        assert.deepEqual(await run(account, 'pause'), { result: 'missing' });
    });

    await t.test('the payload only takes the four actions', async () => {
        const schema = route.options.validate.payload;
        assert.ok(schema.validate({ action: 'delete', revoke: true }).value);
        assert.ok(schema.validate({ action: 'flush' }).error);
        assert.ok(schema.validate({}).error);
    });
});

test('bulkSkipReason decides from the stored account alone', () => {
    const oauth = { oauth2: { provider: 'app' } };
    assert.equal(bulkSkipReason('delete', {}), null);
    assert.equal(bulkSkipReason('pause', oauth), null);
    assert.equal(bulkSkipReason('resume', oauth), 'Not paused');
    // a paused OAuth2 account carries a bare { disabled: true } blob
    assert.equal(bulkSkipReason('resume', Object.assign({ imap: { disabled: true } }, oauth)), null);
    assert.equal(bulkSkipReason('reconnect', Object.assign({ imap: { disabled: true } }, oauth)), 'Syncing is paused');
});

test('revocationNote speaks only when a grant was asked to go and stayed', () => {
    assert.equal(revocationNote(undefined), null);
    assert.equal(revocationNote({ attempted: true, revoked: true }), null);
    assert.equal(revocationNote({ attempted: false, revoked: false, reason: 'NotOAuth2' }), null);
    assert.equal(
        revocationNote({ attempted: false, revoked: false, reason: 'ServiceAccount' }),
        'Deleted, but access was not revoked: service accounts hold no grant to revoke'
    );
    assert.match(revocationNote({ attempted: true, revoked: false, reason: 'Rejected' }), /Rejected$/);
});
