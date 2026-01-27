'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Simulate the waitForAssignment function from server.js
// This mirrors the implementation so we can test the logic in isolation
function createWaitForAssignment(state) {
    return function waitForAssignment(account, timeout = 12000, interval = 500) {
        return new Promise(resolve => {
            if (state.assigned.has(account)) {
                return resolve(true);
            }
            if (state.isClosing) {
                return resolve(false);
            }

            let elapsed = 0;
            let timer = setInterval(() => {
                elapsed += interval;
                if (state.assigned.has(account)) {
                    clearInterval(timer);
                    return resolve(true);
                }
                if (state.isClosing || elapsed >= timeout) {
                    clearInterval(timer);
                    return resolve(false);
                }
            }, interval);
        });
    };
}

test('waitForAssignment tests', async t => {
    await t.test('resolves immediately when account is already assigned', async () => {
        let state = {
            assigned: new Map([['account-1', { id: 'worker-1' }]]),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        let result = await waitForAssignment('account-1', 1000, 50);
        assert.strictEqual(result, true, 'Should resolve true immediately for assigned account');
    });

    await t.test('waits and resolves when account becomes assigned during polling', async () => {
        let state = {
            assigned: new Map(),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        // Simulate assignment after 150ms
        setTimeout(() => {
            state.assigned.set('account-2', { id: 'worker-1' });
        }, 150);

        let result = await waitForAssignment('account-2', 2000, 50);
        assert.strictEqual(result, true, 'Should resolve true after account becomes assigned');
    });

    await t.test('times out and returns false when account never becomes assigned', async () => {
        let state = {
            assigned: new Map(),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        let result = await waitForAssignment('account-3', 200, 50);
        assert.strictEqual(result, false, 'Should resolve false after timeout');
    });

    await t.test('exits early when isClosing is true at start', async () => {
        let state = {
            assigned: new Map(),
            isClosing: true
        };
        let waitForAssignment = createWaitForAssignment(state);

        let result = await waitForAssignment('account-4', 2000, 50);
        assert.strictEqual(result, false, 'Should resolve false immediately when isClosing is true');
    });

    await t.test('exits early when isClosing becomes true during polling', async () => {
        let state = {
            assigned: new Map(),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        // Set isClosing after 150ms
        setTimeout(() => {
            state.isClosing = true;
        }, 150);

        let start = Date.now();
        let result = await waitForAssignment('account-5', 5000, 50);
        let elapsed = Date.now() - start;

        assert.strictEqual(result, false, 'Should resolve false when isClosing becomes true');
        assert.ok(elapsed < 1000, 'Should exit well before the full timeout');
    });
});

test('submitMessage/queueMessage routing with wait logic', async t => {
    await t.test('submit operations wait instead of immediately throwing when account is temporarily unassigned', async () => {
        let state = {
            assigned: new Map(),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        // Simulate the routing logic from server.js
        async function routeSubmitMessage(account) {
            if (!state.assigned.has(account)) {
                let wasAssigned = await waitForAssignment(account, 500, 50);
                if (!wasAssigned) {
                    let err = new Error('No active handler for requested account. Try again later.');
                    err.statusCode = 503;
                    err.code = 'WorkerNotAvailable';
                    throw err;
                }
            }
            return { success: true, worker: state.assigned.get(account) };
        }

        // Simulate worker becoming available after 100ms
        setTimeout(() => {
            state.assigned.set('account-6', { id: 'worker-2' });
        }, 100);

        let result = await routeSubmitMessage('account-6');
        assert.strictEqual(result.success, true, 'Should succeed after worker becomes available');
        assert.deepStrictEqual(result.worker, { id: 'worker-2' });
    });

    await t.test('submit operations throw after wait timeout if account remains unassigned', async () => {
        let state = {
            assigned: new Map(),
            isClosing: false
        };
        let waitForAssignment = createWaitForAssignment(state);

        async function routeSubmitMessage(account) {
            if (!state.assigned.has(account)) {
                let wasAssigned = await waitForAssignment(account, 200, 50);
                if (!wasAssigned) {
                    let err = new Error('No active handler for requested account. Try again later.');
                    err.statusCode = 503;
                    err.code = 'WorkerNotAvailable';
                    throw err;
                }
            }
            return { success: true };
        }

        await assert.rejects(
            () => routeSubmitMessage('account-7'),
            err => {
                assert.strictEqual(err.statusCode, 503);
                assert.strictEqual(err.code, 'WorkerNotAvailable');
                return true;
            }
        );
    });
});

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
