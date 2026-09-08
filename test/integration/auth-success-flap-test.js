'use strict';

// Regression test for the authenticationSuccess flood.
//
// An account that logs in successfully but cannot finish its folder sync reconnects in a loop, and
// every cycle used to announce itself as a fresh login. Two things caused it and both are fixed:
// the stored error state was read in start() but only cleared once a sync completed, so the same
// stale error was re-read on every attempt; and the "first successful connection" test reads the
// connected-session counter, which is only raised when the account reaches `connected` - i.e. never,
// for an account that cannot sync. A customer running five instances reported the resulting webhook
// volume against Outlook, Hotmail and Yahoo accounts.
//
// Hermetic: an in-process mock IMAP server on localhost, no external services or credentials. It
// accepts the login and the folder listing, then drops the connection as soon as the sync tries to
// open a folder - which is the shape of the report, a connection that comes up and goes away again.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');
const { ACCESS_TOKEN, waitForCondition, startMockImapServer } = require('./helpers');
const webhooksServer = require('./webhooks-server');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

// Enough cycles that a per-attempt notification would be unmistakable. The close-triggered backoff
// starts at 2s and grows, so this is a handful of seconds of reconnecting.
const REQUIRED_LOGINS = 3;
const LOOP_TIMEOUT = 60000;

// Webhooks are queued, so the last cycle's delivery can still be in flight when the login count
// reaches its target
const WEBHOOK_SETTLE_TIME = 5000;

const authSuccessEventsFor = account => (webhooksServer.webhooks.get(account) || []).filter(wh => wh.event === 'authenticationSuccess');

test('A login that cannot sync announces itself once, not once per reconnect', async t => {
    const account = `auth-flap-${crypto.randomBytes(4).toString('hex')}`;

    let logins = 0;

    const mock = await startMockImapServer({
        onCommand({ tag, cmd, send, drop, session }) {
            switch (cmd) {
                case 'LOGIN':
                    logins++;
                    return false; // the default handler records the user and answers OK

                case 'LIST':
                case 'LSUB':
                    // A listing the client can work with, so the connection setup completes and the
                    // account gets as far as syncing
                    send(`* ${cmd} (\\HasNoChildren) "/" "INBOX"`);
                    send(`${tag} OK ${cmd} completed.`);
                    session.listed = true;
                    return true;

                case 'SELECT':
                case 'EXAMINE':
                case 'STATUS':
                case 'IDLE':
                    if (session.listed) {
                        // Drop the connection the moment the sync reaches for a folder. Nothing is
                        // sent back - the socket simply goes away, the way a server that hangs up
                        // does
                        drop();
                        return true;
                    }
                    return false;
            }
            return false;
        }
    });

    t.before(async () => {
        await webhooksServer.init();
    });

    t.after(async () => {
        try {
            await server.delete(`/v1/account/${account}`);
        } catch (err) {
            // the account might not exist if the test failed early
        }
        await mock.close();
        await webhooksServer.quit();
    });

    await server
        .post(`/v1/account`)
        .send({
            account,
            name: `Auth success flap test (${account})`,
            imap: {
                host: '127.0.0.1',
                port: mock.port,
                secure: false,
                auth: { user: 'testuser', pass: 'pass' },
                resyncDelay: 3600
            }
        })
        .expect(200);

    // The loop has to actually happen, otherwise the assertion below would pass for the wrong
    // reason. Every login here is a completed authentication - the point of the test is that only
    // the first one is worth telling anybody about.
    await waitForCondition(() => logins >= REQUIRED_LOGINS, {
        timeout: LOOP_TIMEOUT,
        message: `The account only logged in ${logins} time(s), so the reconnect loop under test never ran`
    });

    await new Promise(resolve => setTimeout(resolve, WEBHOOK_SETTLE_TIME));

    const authSuccessEvents = authSuccessEventsFor(account);
    assert.equal(authSuccessEvents.length, 1, `expected exactly one authenticationSuccess after ${logins} logins, got ${authSuccessEvents.length}`);
});
