'use strict';

// Regression tests for the reconnect scheduling behavior of Subconnection.reconnect():
// the backoff counter and the close/re-entry races around the pre-connect sleep.
//
// Counter: it must be reset only after the monitored mailbox has been opened,
// not right after connect/login succeeds. Before the fix a subconnection whose
// folder could be logged into but not opened (the phantom-folder scenario) reset
// the counter on every cycle, so a server that drops the connection after the
// failed SELECT kept the close-triggered retry loop at the base delay forever -
// the same reset-on-every-cycle storm that was fixed on the primary connection.
//
// Races: _connecting must be set before the backoff sleep (otherwise the error
// and close handlers of one dying connection each start an overlapping cycle),
// and a close() landing during the sleep must not be erased on wake (otherwise
// a subconnection the parent already discarded revives as an unreachable zombie
// holding a live server connection).

const test = require('node:test');
const assert = require('node:assert').strict;

const { Subconnection } = require('../lib/email-client/imap/subconnection');

// reconnect() sleeps delay + Math.random() * 1000 of jitter before connecting;
// zero the jitter so the subtests do not add real wall-clock waits (each test
// file runs in its own process, so the stub can not leak elsewhere)
test.mock.method(Math, 'random', () => 0);

const noopLogger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
        return noopLogger;
    }
};

// listResponse drives the missing-mailbox verification LIST that runs after a
// tagged NO: a non-empty array means the folder is still listed (phantom), an
// empty array means it is gone, and a function can throw to simulate a failed
// verification. Defaults to "folder exists".
function makeSubconnection({ mailboxOpenError, path = 'Shared Folders/team', listResponse = [{ path: 'Shared Folders/team' }] } = {}) {
    const listingRefreshCalls = [];

    const subconnection = new Subconnection({
        parent: {
            // Consumed by the missing-mailbox disable path
            refreshAndProcessListing: async () => {
                listingRefreshCalls.push(1);
                return new Set();
            }
        },
        account: 'test-account',
        mailbox: { path },
        logger: noopLogger
    });

    // Shrink the scheduling delay so the pre-connect wait stays in milliseconds
    subconnection.reconnectBackoff.baseDelay = 1;

    // Replace the connection setup: successful "login", configurable mailboxOpen
    subconnection.start = async () => {
        subconnection.imapClient = {
            usable: true,
            mailboxOpen: async () => {
                if (mailboxOpenError) {
                    throw mailboxOpenError;
                }
                return {};
            },
            run: async () => (typeof listResponse === 'function' ? listResponse() : listResponse),
            close: () => {}
        };
    };

    return { subconnection, listingRefreshCalls };
}

test('Subconnection.reconnect() backoff counter', async t => {
    await t.test('keeps the counter when a still-listed mailbox can not be opened', async () => {
        // The folder IS in the LIST response (phantom/INUSE case), so the
        // subconnection must keep retrying with a growing backoff, not disable
        const mailboxOpenError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT'
        });
        const { subconnection } = makeSubconnection({ mailboxOpenError });
        subconnection.reconnectBackoff.attempts = 5;

        await subconnection.reconnect();

        // reconnect() increments the counter when scheduling; a failed mailbox
        // open must not reset it, otherwise every retry runs at the base delay
        assert.equal(subconnection.reconnectBackoff.attempts, 6, 'counter must keep growing while the setup keeps failing');
        assert.notEqual(subconnection.state, 'connected');
        assert.ok(!subconnection.disabled, 'a still-listed mailbox must not disable the subconnection');
    });

    await t.test('resets the counter after the monitored mailbox is open', async () => {
        const { subconnection } = makeSubconnection();
        subconnection.reconnectBackoff.attempts = 5;

        await subconnection.reconnect();

        assert.equal(subconnection.reconnectBackoff.attempts, 0, 'counter must reset after a fully successful setup');
        assert.equal(subconnection.state, 'connected');
    });
});

test('Subconnection.reconnect() missing monitored mailbox', async t => {
    await t.test('disables the subconnection when the mailbox is gone', async () => {
        const mailboxOpenError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT'
        });
        // Verification LIST returns nothing: the folder was deleted server-side
        const { subconnection, listingRefreshCalls } = makeSubconnection({ mailboxOpenError, listResponse: [] });

        await subconnection.reconnect();

        assert.equal(subconnection.state, 'disabled');
        assert.equal(subconnection.disabledReason, 'Mailbox folder not found');
        assert.equal(subconnection.disabled, true, 'must look like a placeholder to the reconciler');
        assert.equal(subconnection.isClosed, true, 'the connection must be shut down');
        assert.equal(subconnection.imapClient, null);
        assert.equal(listingRefreshCalls.length, 1, 'the parent listing refresh must be requested');
        assert.equal(await subconnection.reconnect(), false, 'retries must stop for the missing folder');
    });

    await t.test('a wildcard-matched sibling is not proof that the mailbox exists', async () => {
        const mailboxOpenError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT'
        });
        // The raw path is used as the LIST match pattern, so the '%' in the
        // deleted folder's name makes the server return a matching sibling.
        // Only an exact path match may count as "still exists" - otherwise
        // the disable path is skipped and the subconnection retries forever
        const { subconnection, listingRefreshCalls } = makeSubconnection({
            mailboxOpenError,
            path: 'Reports 2024%',
            listResponse: [{ path: 'Reports 2024-archive' }]
        });

        await subconnection.reconnect();

        assert.equal(subconnection.disabled, true, 'a wildcard sibling match must not keep the subconnection alive');
        assert.equal(subconnection.state, 'disabled');
        assert.equal(subconnection.disabledReason, 'Mailbox folder not found');
        assert.equal(listingRefreshCalls.length, 1, 'the folder deletion must be processed');
    });

    await t.test('keeps retrying when the verification LIST itself fails', async () => {
        const mailboxOpenError = Object.assign(new Error('Command failed'), {
            responseStatus: 'NO',
            serverResponseCode: 'NONEXISTENT'
        });
        const { subconnection } = makeSubconnection({
            mailboxOpenError,
            listResponse: () => {
                throw Object.assign(new Error('Connection not available'), { code: 'NoConnection' });
            }
        });
        subconnection.reconnectBackoff.attempts = 5;

        await subconnection.reconnect();

        assert.ok(!subconnection.disabled, 'an unverified miss must not disable the subconnection');
        assert.equal(subconnection.reconnectBackoff.attempts, 6, 'the backoff counter must keep growing');
        assert.notEqual(subconnection.state, 'disabled');
    });
});

test('Subconnection.reconnect() close and re-entry races', async t => {
    await t.test('a close() during the backoff sleep is not erased on wake', async () => {
        const { subconnection } = makeSubconnection();
        let startCalls = 0;
        subconnection.start = async () => {
            startCalls++;
        };

        // reconnect() enters its (1ms base + zeroed jitter) backoff sleep;
        // close() is synchronous, so it lands inside that sleep window
        const pending = subconnection.reconnect();
        subconnection.close();

        assert.equal(await pending, false, 'the sleeping cycle must bail out');
        assert.equal(startCalls, 0, 'a closed subconnection must not open a new connection');
        assert.equal(subconnection.isClosed, true, 'close() must not be erased by the sleeping cycle');
        assert.equal(subconnection._connecting, false);
    });

    await t.test('a concurrent reconnect() during an in-flight cycle is rejected', async () => {
        const { subconnection } = makeSubconnection();
        let startCalls = 0;
        subconnection.start = async () => {
            startCalls++;
            subconnection.imapClient = {
                usable: true,
                mailboxOpen: async () => ({})
            };
        };

        // The first call sets _connecting synchronously, so a second call -
        // e.g. from the 'close' handler of a dying connection while the first
        // cycle sleeps - must short-circuit on the guard
        const first = subconnection.reconnect();
        assert.equal(await subconnection.reconnect(), false, 'concurrent reconnect must be rejected');

        await first;

        assert.equal(startCalls, 1, 'exactly one connection cycle must run');
        assert.equal(subconnection.state, 'connected');
    });
});
