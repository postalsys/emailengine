'use strict';

// lib/queue-job-actions.js: getAccountJob() is what keeps a credential bound to one account away
// from another account's jobs on the account-scoped outbox and failed webhook routes.

const test = require('node:test');
const assert = require('node:assert').strict;

const { getAccountJob } = require('../lib/queue-job-actions');

test('getAccountJob', async t => {
    const jobs = new Map([
        ['1', { id: '1', data: { account: 'alice' } }],
        ['2', { id: '2', data: {} }]
    ]);
    const queue = { getJob: async id => jobs.get(id) || null };

    await t.test('any job without an account to check', async () => {
        assert.strictEqual((await getAccountJob(queue, '1')).id, '1');
        assert.strictEqual((await getAccountJob(queue, '2')).id, '2');
    });

    await t.test("another account's job reads as missing", async () => {
        assert.strictEqual((await getAccountJob(queue, '1', 'alice')).id, '1');
        assert.strictEqual(await getAccountJob(queue, '1', 'bob'), null);
        assert.strictEqual(await getAccountJob(queue, '2', 'alice'), null, 'a job naming no account belongs to none');
    });

    await t.test('no ID, no lookup', async () => {
        let looked = false;
        assert.strictEqual(
            await getAccountJob(
                {
                    getJob: async () => {
                        looked = true;
                    }
                },
                '',
                'alice'
            ),
            null
        );
        assert.strictEqual(looked, false);
        assert.strictEqual(await getAccountJob(queue, 'missing'), null);
    });
});
