'use strict';

// "Resume syncing" for an account the auth-failure safety net switched off: the one
// implementation, Account.resumeAfterAuthFailure(), and the two routes that call it - the admin UI
// action and PUT /v1/account/{account}/resume.
//
// Runs against the test database with account ids of its own, because what is under test is the
// pair of fields the park writes (`imap.disabled` and the provenance marker beside it) and a stub
// would have to re-implement exactly the reads being tested.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_FIELD } = require('../lib/consts');
const accountRoutes = require('../lib/api-routes/account-routes');
const { routeGrant, surfaceAdmits, ACTION, GROUP } = require('../lib/api-routes/permission-map');
const { routeAdmitsBoundToken } = require('../lib/api-routes/account-binding');
const { mcpGrantsFor } = require('../lib/token-permission-view');
const tokenPermissions = require('../lib/token-permissions');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

const logger = { warn() {}, error() {}, debug() {}, info() {}, trace() {} };
const DISABLED_AT = '2026-08-01T09:00:00.000Z';
const IMAP = { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'user@example.com' } };

const created = [];

async function storeAccount({ disabled, marker }) {
    const account = `resume-test-${crypto.randomBytes(6).toString('hex')}`;
    created.push(account);

    const fields = {
        account,
        name: 'Resume test',
        email: 'user@example.com',
        imap: JSON.stringify(Object.assign({}, IMAP, disabled ? { disabled: true } : {}))
    };
    if (marker) {
        fields[AUTH_FAILURE_DISABLED_FIELD] = DISABLED_AT;
    }
    await redis.hmset(`${REDIS_PREFIX}iad:${account}`, fields);
    return account;
}

async function storedState(account) {
    const [imap, marker] = await redis.hmget(`${REDIS_PREFIX}iad:${account}`, 'imap', AUTH_FAILURE_DISABLED_FIELD);
    return { disabled: !!JSON.parse(imap).disabled, marker };
}

function recordingCall(fail) {
    const calls = [];
    const call = async message => {
        calls.push(message);
        if (fail) {
            throw new Error('No worker');
        }
        return true;
    };
    return { calls, call };
}

test.after(async () => {
    for (const account of created) {
        await redis.del(`${REDIS_PREFIX}iad:${account}`);
    }
});

// After the cleanup above, which root hooks run in registration order
registerRedisTeardown(redis);

test('Account.resumeAfterAuthFailure', async t => {
    await t.test('lifts a park, clears the marker and asks the worker to reconnect', async () => {
        const account = await storeAccount({ disabled: true, marker: true });
        const { calls, call } = recordingCall();

        assert.equal(await new Account({ redis, account, call, logger }).resumeAfterAuthFailure(), true);

        assert.deepEqual(await storedState(account), { disabled: false, marker: null });
        assert.equal(calls.length, 1);
        assert.equal(calls[0].cmd, 'reconnect');
        assert.equal(calls[0].account, account);
    });

    await t.test('still resumes when the reconnect cannot be dispatched', async () => {
        // The flag is what parks the account, so once it is lifted the next periodic reconnect
        // picks the account up; a lost dispatch is not a failed resume
        const account = await storeAccount({ disabled: true, marker: true });
        const { calls, call } = recordingCall(true);

        assert.equal(await new Account({ redis, account, call, logger }).resumeAfterAuthFailure(), true);
        assert.deepEqual(await storedState(account), { disabled: false, marker: null });
        assert.equal(calls.length, 1);
    });

    await t.test("leaves an operator's send-only switch alone", async () => {
        const account = await storeAccount({ disabled: true, marker: false });
        const { calls, call } = recordingCall();

        assert.equal(await new Account({ redis, account, call, logger }).resumeAfterAuthFailure(), false);
        assert.deepEqual(await storedState(account), { disabled: true, marker: null });
        assert.equal(calls.length, 0);
    });

    await t.test('does nothing for an account that is running', async () => {
        const account = await storeAccount({ disabled: false, marker: false });
        const { calls, call } = recordingCall();

        assert.equal(await new Account({ redis, account, call, logger }).resumeAfterAuthFailure(), false);
        assert.deepEqual(await storedState(account), { disabled: false, marker: null });
        assert.equal(calls.length, 0);
    });
});

test('PUT /v1/account/{account}/resume', async t => {
    const routes = [];
    const { calls, call } = recordingCall();
    await accountRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }, { call }));
    const route = routes.find(entry => entry.method === 'PUT' && entry.path === '/v1/account/{account}/resume');
    assert.ok(route, 'the route is registered');

    const request = account => ({ params: { account }, headers: {}, logger });

    await t.test('resumes a parked account', async () => {
        const account = await storeAccount({ disabled: true, marker: true });
        calls.length = 0;

        assert.deepEqual(await route.handler(request(account)), { resumed: true });
        assert.deepEqual(await storedState(account), { disabled: false, marker: null });
        assert.deepEqual(
            calls.map(message => [message.cmd, message.account]),
            [['reconnect', account]]
        );
    });

    await t.test('answers 409 NotSwitchedOff for an account with nothing to resume', async () => {
        for (const state of [
            { disabled: false, marker: false },
            { disabled: true, marker: false }
        ]) {
            const account = await storeAccount(state);
            calls.length = 0;

            await assert.rejects(route.handler(request(account)), err => err.output.statusCode === 409 && err.output.payload.code === 'NotSwitchedOff');
            assert.equal(calls.length, 0);
            assert.equal((await storedState(account)).disabled, state.disabled, 'the switch is left as it was');
        }
    });

    await t.test('answers 404 for an unknown account', async () => {
        await assert.rejects(route.handler(request(`resume-test-missing-${crypto.randomBytes(6).toString('hex')}`)), err => err.output.statusCode === 404);
    });

    await t.test('is an account write: operating the connection like the reconnect, never mail', () => {
        const grant = routeGrant(route);
        assert.deepEqual(grant, { action: ACTION.WRITE, group: GROUP.ACCOUNT });
        assert.deepEqual(grant, routeGrant(routes.find(entry => entry.method === 'PUT' && entry.path === '/v1/account/{account}/reconnect')));

        assert.ok(surfaceAdmits('mcp-manage', grant));
        assert.ok(!surfaceAdmits('mcp', grant));

        const allowedAt = choice => tokenPermissions.check({ tokenData: mcpGrantsFor(choice), operation: grant }).allowed;
        assert.equal(allowedAt({ manage: 'observe' }), false);
        assert.equal(allowedAt({ manage: 'operate' }), true);
        assert.equal(allowedAt({ manage: 'none', mail: 'full' }), false);
    });

    await t.test('takes the account in its path, so an account-bound token reaches only its own', () => {
        assert.ok(routeAdmitsBoundToken('put', '/v1/account/{account}/resume'));
        assert.ok(route.options.validate.params.validate({ account: 'a' }).value);
    });
});
