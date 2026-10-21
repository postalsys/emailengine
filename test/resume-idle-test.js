'use strict';

// BaseClient.resumeIdle(), shared by the message upload and the Sent copy: only the primary
// connection, with a mailbox selected and not already idling, is put back into IDLE.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { BaseClient } = require('../lib/email-client/base-client');
const { createMockLogger } = require('./helpers/mock-logger');

function createClient(primaryState) {
    const logger = createMockLogger();
    const primary = Object.assign(
        {
            idleCalls: 0,
            idleOptions: null,
            idle(options) {
                this.idleCalls++;
                this.idleOptions = options;
                return primaryState.idleError ? Promise.reject(primaryState.idleError) : Promise.resolve(true);
            }
        },
        primaryState
    );
    const client = Object.assign(Object.create(BaseClient.prototype), {
        imapClient: primary,
        logger
    });
    return { client, primary, warnings: logger.entries };
}

test('BaseClient.resumeIdle()', async t => {
    await t.test('resumes IDLE on the primary connection', () => {
        const { client, primary } = createClient({ mailbox: { path: 'INBOX' }, idling: false });
        client.resumeIdle(primary);
        assert.strictEqual(primary.idleCalls, 1);
        // a sync or API call may hold the mailbox lock, IDLE must not start between its commands
        assert.deepStrictEqual(primary.idleOptions, { whenFree: true });
    });

    await t.test('leaves a secondary connection alone', () => {
        const { client, primary } = createClient({ mailbox: { path: 'INBOX' }, idling: false });
        client.resumeIdle({ mailbox: { path: 'INBOX' } });
        assert.strictEqual(primary.idleCalls, 0);
    });

    await t.test('does nothing without a selected mailbox or while already idling', () => {
        let { client, primary } = createClient({ mailbox: false, idling: false });
        client.resumeIdle(primary);
        assert.strictEqual(primary.idleCalls, 0);

        ({ client, primary } = createClient({ mailbox: { path: 'INBOX' }, idling: true }));
        client.resumeIdle(primary);
        assert.strictEqual(primary.idleCalls, 0);
    });

    await t.test('does nothing without a primary connection', () => {
        const client = Object.assign(Object.create(BaseClient.prototype), { imapClient: null });
        assert.doesNotThrow(() => client.resumeIdle({}));
    });

    await t.test('logs an IDLE failure instead of rejecting', async () => {
        const { client, primary, warnings } = createClient({ mailbox: { path: 'INBOX' }, idling: false, idleError: new Error('Connection closed') });
        client.resumeIdle(primary);
        await new Promise(resolve => setImmediate(resolve));
        assert.strictEqual(warnings[0].msg, 'IDLE error');
        assert.strictEqual(warnings[0].level, 'warn');
    });

    await t.test('a connection that closed while IDLE waited for it is logged at debug', async () => {
        const closed = Object.assign(new Error('Connection not available'), { code: 'NoConnection' });
        const { client, primary, warnings } = createClient({ mailbox: { path: 'INBOX' }, idling: false, idleError: closed });
        client.resumeIdle(primary);
        await new Promise(resolve => setImmediate(resolve));
        assert.deepStrictEqual(
            warnings.map(entry => [entry.level, entry.msg]),
            [['debug', 'IDLE error']]
        );
    });
});

test('BaseClient.resumeIdle() waits once per connection', async () => {
    let release;
    let calls = 0;
    const primary = {
        mailbox: { path: 'INBOX' },
        idling: false,
        idle() {
            calls++;
            return new Promise(resolve => {
                release = resolve;
            });
        }
    };
    const client = Object.assign(Object.create(BaseClient.prototype), { imapClient: primary, logger: createMockLogger() });

    // two uploads while the connection is busy: one waiter, not two
    client.resumeIdle(primary);
    client.resumeIdle(primary);
    assert.strictEqual(calls, 1);

    // once that IDLE is over, the next upload resumes it again
    release(true);
    await new Promise(resolve => setImmediate(resolve));
    client.resumeIdle(primary);
    assert.strictEqual(calls, 2);
});
