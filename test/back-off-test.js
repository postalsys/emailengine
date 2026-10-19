'use strict';

// lib/utils/back-off.js drives the IMAP connection setup retries and the OIDC discovery retry. The
// wait is stubbed with withInstantTimers(), so the schedule is asserted exactly without waiting for it.

const test = require('node:test');
const assert = require('node:assert').strict;

const { backOff, getDelay } = require('../lib/utils/back-off');
const { withInstantTimers } = require('./helpers/instant-timers');

// Fails the first `failures` calls, then resolves with `value`
function flaky(failures, value) {
    let calls = 0;
    const fn = async () => {
        calls++;
        if (calls <= failures) {
            throw new Error(`failure ${calls}`);
        }
        return value;
    };
    fn.calls = () => calls;
    return fn;
}

test('backOff', async t => {
    await t.test('resolves with the first successful result without waiting', async () => {
        const { result, delays } = await withInstantTimers(() => backOff(async () => 'ok'));
        assert.strictEqual(result, 'ok');
        assert.deepStrictEqual(delays, []);
    });

    await t.test('runs the first attempt at once, then doubles from startingDelay up to maxDelay', async () => {
        const request = flaky(6, 'done');
        const { result, delays } = await withInstantTimers(() => backOff(request, { startingDelay: 2000, maxDelay: 30000, numOfAttempts: Infinity }));
        assert.strictEqual(result, 'done');
        assert.strictEqual(request.calls(), 7);
        assert.deepStrictEqual(delays, [2000, 4000, 8000, 16000, 30000, 30000]);
    });

    await t.test('delayFirstAttempt waits startingDelay before the first attempt too', async () => {
        const { delays } = await withInstantTimers(() => backOff(flaky(3, 'done'), { delayFirstAttempt: true, startingDelay: 500, maxDelay: 3000 }));
        assert.deepStrictEqual(delays, [500, 1000, 2000, 3000]);
    });

    await t.test('applies timeMultiple and the 100 ms default starting delay', async () => {
        const { delays } = await withInstantTimers(() => backOff(flaky(3, 'done'), { timeMultiple: 3 }));
        assert.deepStrictEqual(delays, [100, 300, 900]);
    });

    await t.test('asks retry() after each failure with the error and the failure count', async () => {
        const seen = [];
        await withInstantTimers(() =>
            backOff(flaky(2, 'done'), {
                retry: (err, failures) => {
                    seen.push([err.message, failures]);
                    return true;
                }
            })
        );
        assert.deepStrictEqual(seen, [
            ['failure 1', 1],
            ['failure 2', 2]
        ]);
    });

    await t.test('rethrows the error when retry() declines, awaiting an async answer', async () => {
        const request = flaky(5, 'done');
        const { error } = await withInstantTimers(() => backOff(request, { retry: async (lastError, failures) => failures < 2 }));
        assert.strictEqual(error.message, 'failure 2');
        assert.strictEqual(request.calls(), 2);
    });

    await t.test('stops after numOfAttempts and rethrows the last error', async () => {
        const request = flaky(Infinity);
        const { error, delays } = await withInstantTimers(() => backOff(request, { numOfAttempts: 3 }));
        assert.strictEqual(error.message, 'failure 3');
        assert.strictEqual(request.calls(), 3);
        assert.deepStrictEqual(delays, [100, 200]);
    });

    await t.test('defaults to 10 attempts and treats fewer than 1 as 1', async () => {
        const tenAttempts = flaky(Infinity);
        assert.ok((await withInstantTimers(() => backOff(tenAttempts))).error);
        assert.strictEqual(tenAttempts.calls(), 10);

        const oneAttempt = flaky(Infinity);
        assert.ok((await withInstantTimers(() => backOff(oneAttempt, { numOfAttempts: 0 }))).error);
        assert.strictEqual(oneAttempt.calls(), 1);
    });

    await t.test('keeps the default for an option passed as undefined', async () => {
        const { delays } = await withInstantTimers(() => backOff(flaky(2, 'done'), { startingDelay: undefined, maxDelay: undefined }));
        assert.deepStrictEqual(delays, [100, 200]);
    });

    await t.test('waits on a real timer', async () => {
        const started = Date.now();
        await backOff(flaky(1, 'done'), { startingDelay: 30 });
        assert.ok(Date.now() - started >= 25);
    });
});

test('getDelay', async t => {
    await t.test('never exceeds the largest delay setTimeout honours', () => {
        // an uncapped schedule must not overflow into setTimeout's 1 ms fallback
        assert.strictEqual(getDelay({ startingDelay: 1000, timeMultiple: 2, maxDelay: Infinity }, 100), 2 ** 31 - 1);
    });

    await t.test('is 0 for the first attempt unless delayFirstAttempt is set', () => {
        assert.strictEqual(getDelay({ startingDelay: 1000, timeMultiple: 2, maxDelay: Infinity }, 0), 0);
        assert.strictEqual(getDelay({ startingDelay: 1000, timeMultiple: 2, maxDelay: Infinity, delayFirstAttempt: true }, 0), 1000);
    });
});
