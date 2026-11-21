'use strict';

// Account.notifyWorker() tells the owning worker about a change that is already saved. A failed
// dispatch is logged, never thrown, and a failed `update` or `reconnect` is sent once more in the
// background; `new` and `delete` are not (see the method's comment for why).

const test = require('node:test');
const assert = require('node:assert').strict;

const { Account } = require('../lib/account');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const RETRY_DELAY = 20;

function makeLogger() {
    const entries = [];
    const record = level => entry => entries.push(Object.assign({ level }, entry));
    return { entries, info: record('info'), warn: record('warn'), error: record('error'), debug: () => {} };
}

// `failures` is how many calls fail before the dispatch starts succeeding
function makeAccount(failures) {
    const calls = [];
    const logger = makeLogger();
    const call = async message => {
        calls.push(message);
        if (calls.length <= failures) {
            throw Object.assign(new Error('Request timed out'), { code: 'Timeout' });
        }
        return true;
    };
    const account = new Account({ account: 'acc1', call, logger, dispatchRetryDelay: RETRY_DELAY });
    return { account, calls, logger };
}

// A ref'd timer, so the event loop stays up while the unref'd retry timer is pending
const settle = () => new Promise(resolve => setTimeout(resolve, RETRY_DELAY * 5));

test('a successful dispatch is sent once', async () => {
    const { account, calls } = makeAccount(0);
    assert.equal(await account.notifyWorker('update'), true);
    await settle();
    assert.deepEqual(
        calls.map(c => c.cmd),
        ['update']
    );
});

for (const cmd of ['update', 'reconnect']) {
    test(`a failed ${cmd} is sent once more in the background`, async () => {
        const { account, calls, logger } = makeAccount(1);
        assert.equal(await account.notifyWorker(cmd), false, 'the first failure is reported to the caller');
        assert.equal(calls.length, 1, 'the retry does not hold up the caller');
        await settle();
        assert.deepEqual(
            calls.map(c => c.cmd),
            [cmd, cmd]
        );
        assert.equal(calls[1].account, 'acc1');
        assert.ok(logger.entries.some(e => e.msg === 'Notified the worker on retry'));
    });
}

test('a retry that fails too is logged and not repeated', async () => {
    const { account, calls, logger } = makeAccount(Infinity);
    assert.equal(await account.notifyWorker('update'), false);
    await settle();
    assert.equal(calls.length, 2, 'one retry only');
    assert.ok(logger.entries.some(e => e.level === 'error' && e.msg === 'Failed to notify the worker on retry'));
});

for (const cmd of ['new', 'delete']) {
    test(`a failed ${cmd} is not retried`, async () => {
        const { account, calls } = makeAccount(1);
        assert.equal(await account.notifyWorker(cmd), false);
        await settle();
        assert.equal(calls.length, 1);
    });
}

test('an account with no parent channel dispatches nothing', async () => {
    const logger = makeLogger();
    const account = new Account({ account: 'acc1', logger });
    assert.equal(await account.notifyWorker('update'), false);
    assert.ok(logger.entries.some(e => e.level === 'warn'));
});
