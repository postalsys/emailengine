'use strict';

// lib/revocation-events.js: a published change reaches every handler in the process, a malformed
// message still triggers a re-check, and removing the last handler closes the subscriber.

const test = require('node:test');
const assert = require('node:assert').strict;

const { publishRevocation, onRevocation, REVOCATION_CHANNEL } = require('../lib/revocation-events');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const waitUntil = require('./helpers/wait-until');

// One handler held for the whole file keeps the subscriber connection open, so each test waits on
// the same connection instead of racing a closing one against a new one
const keepOpen = onRevocation(() => false);

registerRedisTeardown(redis, async () => keepOpen());

// Resolves with the first event `match` accepts. Other unit test files share the database and
// publish changes of their own (rotating the proxy password, deleting tokens), so a test waits for
// the event it published, not for whichever arrives first.
function nextEvent(match, timeout = 4000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            off();
            reject(new Error('no revocation event'));
        }, timeout);
        const off = onRevocation(detail => {
            if (!match(detail)) {
                return;
            }
            clearTimeout(timer);
            off();
            resolve(detail);
        });
    });
}

const numsub = async () => Number((await redis.pubsub('NUMSUB', REVOCATION_CHANNEL))[1]);

// the subscriber connects lazily; wait until Redis counts it
async function subscribed() {
    assert.ok(await waitUntil(async () => (await numsub()) > 0, 4000), 'subscriber never joined the channel');
}

test('a published change reaches a handler', async () => {
    const event = nextEvent(detail => detail.account === 'revocation-test-acct-1');
    await subscribed();
    await publishRevocation({ type: 'token', account: 'revocation-test-acct-1' });
    assert.deepEqual(await event, { type: 'token', account: 'revocation-test-acct-1' });
});

test('a malformed message still means re-check', async () => {
    const event = nextEvent(detail => !('type' in detail));
    await subscribed();
    await redis.publish(REVOCATION_CHANNEL, 'not json');
    assert.deepEqual(await event, {});
});

test('removing the last handler closes the subscriber', async () => {
    await subscribed();
    // other processes may be subscribed too, so this counts the change, not the total
    const before = await numsub();
    keepOpen();
    assert.ok(await waitUntil(async () => (await numsub()) === before - 1, 4000));
});

test('a throwing handler does not stop the others', async () => {
    const offBad = onRevocation(() => {
        throw new Error('handler fault');
    });
    const event = nextEvent(detail => detail.account === 'revocation-test-acct-2');
    await subscribed();
    await publishRevocation({ type: 'account', account: 'revocation-test-acct-2' });
    assert.deepEqual(await event, { type: 'account', account: 'revocation-test-acct-2' });
    offBad();
});

// Account.update() is also how renewed OAuth2 tokens are saved, so announcing every update would
// re-check every proxied session on each renewal. Only an update that switches IMAP off announces.
test('an account update announces only when it switches IMAP off', async () => {
    const crypto = require('crypto');
    const { Account } = require('../lib/account');
    const { accountKeyFor, noopLogger } = require('./helpers/auth-failure');
    const account = `revocation-update-${crypto.randomBytes(4).toString('hex')}`;
    const imap = { host: 'imap.test', port: 993, secure: true, auth: { user: 'u', pass: 'p' } };
    await redis.hset(accountKeyFor(account), { account, imap: JSON.stringify(imap) });
    const accountObject = new Account({ redis, account, logger: noopLogger, call: async () => ({}) });

    const seen = [];
    const off = onRevocation(detail => {
        if (detail.account === account) {
            seen.push(detail);
        }
    });
    try {
        await subscribed();
        await accountObject.update({ account, name: 'renamed' });
        await accountObject.update({ account, imap: Object.assign({}, imap, { disabled: true }) });
        assert.ok(await waitUntil(() => seen.length > 0, 4000), 'switching IMAP off is announced');
        // switching off an account that already is off, and the rename before, announce nothing
        await accountObject.update({ account, imap: Object.assign({}, imap, { disabled: true }) });
        await new Promise(r => setTimeout(r, 200));
        assert.deepEqual(seen, [{ type: 'account', account }]);
    } finally {
        off();
        await redis.del(accountKeyFor(account));
    }
});
