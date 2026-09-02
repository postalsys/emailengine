'use strict';

// Unit tests for lib/submit-progress.js, the decision the submit worker makes before sending: a
// job that BullMQ re-runs after a stall carries the progress its previous run stored, and once
// that progress says the MTA accepted the message the worker must not send it again. Pure, so no
// Redis is needed.

const test = require('node:test');
const assert = require('node:assert').strict;

const { isAlreadySent, SENT_PROGRESS_STATES } = require('../lib/submit-progress');

test('isAlreadySent', async t => {
    await t.test('recognizes the states written after the message was accepted', () => {
        assert.strictEqual(isAlreadySent({ status: 'smtp-completed', response: '250 OK' }), true);
        assert.strictEqual(isAlreadySent({ status: 'submitted', response: '250 OK' }), true);
        assert.deepStrictEqual([...SENT_PROGRESS_STATES].sort(), ['smtp-completed', 'submitted']);
    });

    await t.test('lets a legitimate retry through', () => {
        // Every state a run leaves behind before the 250, and the one the failure path writes
        for (let status of ['queued', 'processing', 'smtp-starting', 'error']) {
            assert.strictEqual(isAlreadySent({ status }), false, `expected ${status} to be sent again`);
        }
    });

    await t.test('treats a job that never stored progress as not sent', () => {
        // BullMQ hydrates progress as 0 when nothing was ever written
        assert.strictEqual(isAlreadySent(0), false);
        assert.strictEqual(isAlreadySent(undefined), false);
        assert.strictEqual(isAlreadySent(null), false);
        assert.strictEqual(isAlreadySent({}), false);
        assert.strictEqual(isAlreadySent('smtp-completed'), false);
    });
});
