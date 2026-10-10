'use strict';

// workers/imap.js assign/unassign bookkeeping, driven over the real worker-thread RPC protocol the
// main thread uses (WORK-3, WORK-15). The worker cannot be required from a test (it boots on load
// and needs a parentPort), so it runs in a Worker thread against the test Redis db.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { startWorker } = require('./helpers/worker-rpc');

registerRedisTeardown(redis);

test('IMAP worker assignment bookkeeping', async t => {
    const { worker, ready, call } = startWorker('imap.js');
    t.after(() => worker.terminate());
    await ready;

    await t.test('an assign for an account that does not exist leaves no entry behind (WORK-15)', async () => {
        const resp = await call({ cmd: 'assign', account: `missing-${process.pid}-1` });
        assert.ok(resp.error, 'the assign fails');
        assert.equal(resp.statusCode, 404, 'the main thread can tell the account is gone');

        const counts = await call({ cmd: 'countConnections' });
        assert.equal(counts.response.connections.unassigned, undefined, 'no connection-less entry is left counted as an account');
    });

    await t.test('an unassign that lands while the assign is being set up cancels it (WORK-3)', async () => {
        // The main thread sends unassign after an assign it timed out on, then gives the account
        // to another worker. The original assign must not go on to connect it here as well.
        const account = `assign-race-${process.pid}`;
        await new Account({ redis, secret: await getSecret(), call: async () => 0 }).create({
            account,
            name: 'Assign race',
            email: 'race@example.com',
            imap: { host: '127.0.0.1', port: 1, auth: { user: 'u', pass: 'p' }, disabled: true },
            smtp: false
        });
        t.after(() => redis.del(`${REDIS_PREFIX}iad:${account}`).then(() => redis.srem(`${REDIS_PREFIX}ia:accounts`, account)));

        const assigned = call({ cmd: 'assign', account });
        const unassigned = call({ cmd: 'unassign', account });
        const [assignResp, unassignResp] = await Promise.all([assigned, unassigned]);
        assert.equal(assignResp.error, undefined);
        assert.equal(unassignResp.response, true);

        const counts = await call({ cmd: 'countConnections' });
        const held = Object.values(counts.response.connections).reduce((sum, n) => sum + n, 0);
        assert.equal(held, 0, 'the worker holds no connection for the unassigned account');

        // A later assign still works and replaces rather than duplicates
        await call({ cmd: 'assign', account });
        await call({ cmd: 'assign', account });
        const after = await call({ cmd: 'countConnections' });
        assert.equal(
            Object.values(after.response.connections).reduce((sum, n) => sum + n, 0),
            1
        );
        await call({ cmd: 'unassign', account });
    });

    await t.test('unassign is a known command and tolerates an account the worker does not hold (WORK-3)', async () => {
        const resp = await call({ cmd: 'unassign', account: `missing-${process.pid}-2` });
        assert.equal(resp.error, undefined);
        assert.equal(resp.response, true);
    });
});
