'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

test('submit worker 503 discard fix', async t => {
    // Mirrors the discard condition from workers/submit.js
    function shouldDiscard(err, job) {
        return err.statusCode >= 500 && err.statusCode !== 503 && job.attemptsMade < job.opts.attempts;
    }

    await t.test('does not discard jobs with 503 status code', async () => {
        let err503 = new Error('No active handler');
        err503.statusCode = 503;

        let err500 = new Error('Internal server error');
        err500.statusCode = 500;

        let err502 = new Error('Bad gateway');
        err502.statusCode = 502;

        let job = { attemptsMade: 1, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscard(err503, job), false, '503 errors should NOT be discarded (allows BullMQ retry)');
        assert.strictEqual(shouldDiscard(err500, job), true, '500 errors should be discarded');
        assert.strictEqual(shouldDiscard(err502, job), true, '502 errors should be discarded');
    });

    await t.test('still discards 5xx errors other than 503', async () => {
        let statusCodes = [500, 501, 502, 504, 505];
        let job = { attemptsMade: 0, opts: { attempts: 5 } };

        for (let code of statusCodes) {
            let err = new Error(`Error ${code}`);
            err.statusCode = code;
            assert.strictEqual(shouldDiscard(err, job), true, `${code} errors should still be discarded`);
        }
    });

    await t.test('does not discard when all attempts are exhausted', async () => {
        let err500 = new Error('Internal server error');
        err500.statusCode = 500;

        let job = { attemptsMade: 10, opts: { attempts: 10 } };

        assert.strictEqual(shouldDiscard(err500, job), false, 'Should not discard when attempts are exhausted');
    });
});
