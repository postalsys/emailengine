'use strict';

// Mailbox.sync() runs overlapping calls one after another, and calls made while a pass is still
// waiting its turn share that pass. A burst of API moves into one folder used to queue one STATUS
// round trip per message.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');

// A Mailbox whose syncOnce() records its calls and finishes only when told to
function createMailbox() {
    const passes = [];
    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        syncChain: null,
        pendingSync: null,
        syncOnce(forceEmpty) {
            return new Promise((resolve, reject) => {
                passes.push({ forceEmpty, resolve, reject });
            });
        }
    });
    return { ctx, passes };
}

const tick = () => new Promise(resolve => setImmediate(resolve));

test('Mailbox.sync() coalescing', async t => {
    await t.test('a single call runs a single pass', async () => {
        const { ctx, passes } = createMailbox();
        const result = ctx.sync();
        await tick();
        assert.strictEqual(passes.length, 1);
        passes[0].resolve(true);
        assert.strictEqual(await result, true);
    });

    await t.test('calls made while a pass waits its turn share it', async () => {
        const { ctx, passes } = createMailbox();

        const first = ctx.sync();
        await tick();
        assert.strictEqual(passes.length, 1);

        // the first pass is running, so these wait, and share one pass between them
        const waiting = [ctx.sync(), ctx.sync(), ctx.sync()];
        await tick();
        assert.strictEqual(passes.length, 1, 'nothing starts while the first pass runs');

        passes[0].resolve(true);
        assert.strictEqual(await first, true);
        await tick();
        assert.strictEqual(passes.length, 2, 'one pass for all the waiting calls');

        passes[1].resolve('second');
        assert.deepStrictEqual(await Promise.all(waiting), ['second', 'second', 'second']);
    });

    await t.test('a call made once the waiting pass started gets a pass of its own', async () => {
        const { ctx, passes } = createMailbox();

        const first = ctx.sync();
        await tick();
        passes[0].resolve(1);
        await first;

        const second = ctx.sync();
        await tick();
        assert.strictEqual(passes.length, 2);

        // the second pass has started: a change made now may not be seen by it
        const third = ctx.sync();
        await tick();
        assert.strictEqual(passes.length, 2);
        passes[1].resolve(2);
        assert.strictEqual(await second, 2);
        await tick();
        assert.strictEqual(passes.length, 3);
        passes[2].resolve(3);
        assert.strictEqual(await third, 3);
    });

    await t.test('a shared pass is forced if any caller asked for it', async () => {
        const { ctx, passes } = createMailbox();
        const first = ctx.sync();
        await tick();

        const waiting = [ctx.sync(false), ctx.sync(true), ctx.sync()];
        passes[0].resolve();
        await first;
        await tick();
        assert.strictEqual(passes[1].forceEmpty, true);
        passes[1].resolve();
        await Promise.all(waiting);
    });

    await t.test('a failed pass rejects its callers and does not stop the next one', async () => {
        const { ctx, passes } = createMailbox();
        const first = ctx.sync();
        await tick();
        const waiting = [ctx.sync(), ctx.sync()];

        passes[0].reject(new Error('STATUS failed'));
        await assert.rejects(first, /STATUS failed/);
        await tick();

        passes[1].reject(new Error('connection lost'));
        for (const call of waiting) {
            await assert.rejects(call, /connection lost/);
        }

        const after = ctx.sync();
        await tick();
        assert.strictEqual(passes.length, 3);
        passes[2].resolve('recovered');
        assert.strictEqual(await after, 'recovered');
    });
});
