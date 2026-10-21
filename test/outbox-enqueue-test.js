'use strict';

// outbox.enqueue(): a queued message is its content in the account's outbox hash plus the submit
// job that points to it, and the two are written together. A failed add used to leave the content
// with no job referring to it.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const outbox = require('../lib/outbox');

require('./helpers/redis-teardown')();

function fakes(add) {
    const hash = new Map();
    const redis = {
        hsetBuffer: async (key, field, value) => hash.set(`${key}|${field}`, value),
        hdel: async (key, field) => (hash.delete(`${key}|${field}`) ? 1 : 0)
    };
    return { hash, redis, queue: { add } };
}

const logger = { error() {} };

test('outbox.enqueue()', async t => {
    await t.test('stores the content, then adds the job pointing to it', async () => {
        const { hash, redis, queue } = fakes(async (name, data, opts) => ({ id: opts.jobId, name }));
        const job = await outbox.enqueue({
            redis,
            queue,
            account: 'acc',
            queueId: 'q1',
            content: Buffer.from('x'),
            name: 'queued',
            data: {},
            opts: { jobId: 'q1' },
            logger
        });
        assert.deepStrictEqual(job, { id: 'q1', name: 'queued' });
        assert.ok(hash.has(`${outbox.outboxKey('acc')}|q1`));
    });

    await t.test('takes the content back out when the job can not be added', async () => {
        const { hash, redis, queue } = fakes(async () => {
            assert.strictEqual(hash.size, 1, 'the content is written first');
            throw new Error('OOM command not allowed');
        });
        await assert.rejects(
            outbox.enqueue({ redis, queue, account: 'acc', queueId: 'q2', content: Buffer.from('x'), name: 'queued', data: {}, opts: {}, logger }),
            /OOM/
        );
        assert.strictEqual(hash.size, 0);
    });
});
