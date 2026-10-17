'use strict';

// The account-level IDLE restart interval (imap.maxIdleTime).
//
// Some servers, or a proxy or firewall in front of them, drop a connection left in IDLE for a few
// minutes without sending BYE, and the account reconnects every few minutes. An account can set
// imap.maxIdleTime to end and restart IDLE more often than that, so the connection never looks
// idle. This asserts the whole chain - API, stored account, ImapFlow config - by watching a mock
// IMAP server receive DONE and a fresh IDLE on the same session. Fully hermetic - a failure here is
// never an external flake.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');
const { ACCESS_TOKEN, waitForCondition, startMockImapServer, mockImapConnection } = require('./helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

// The schema floor, so the test runs as quickly as an account could be configured to restart
const MAX_IDLE_TIME = 10 * 1000;
const RESTART_TIMEOUT = 60 * 1000;

test('Account-level maxIdleTime restarts IDLE', async t => {
    const suffix = crypto.randomBytes(4).toString('hex');
    const restartAccount = `idle-restart-${suffix}`;
    const defaultAccount = `idle-default-${suffix}`;

    // login user -> the mock's session objects of the connections that started IDLE
    const sessions = new Map();

    const mock = await startMockImapServer({
        inbox: true,
        onCommand({ cmd, session }) {
            if (cmd === 'IDLE' && !session.idles) {
                sessions.set(session.user, (sessions.get(session.user) || []).concat(session));
            }
            // the mock's own INBOX handlers answer
            return false;
        }
    });

    t.after(async () => {
        for (const account of [restartAccount, defaultAccount]) {
            try {
                await server.delete(`/v1/account/${account}`);
            } catch (err) {
                // account might not exist if the test failed early
            }
        }
        await mock.close();
    });

    const createAccount = async (account, imapExtras) => {
        await server
            .post(`/v1/account`)
            .send({
                account,
                name: `maxIdleTime test (${account})`,
                imap: Object.assign(
                    mockImapConnection(mock.port, {
                        // the login user keys the recorded sessions, so both accounts share one mock
                        auth: { user: account, pass: 'pass' }
                    }),
                    imapExtras
                )
            })
            .expect(200);
    };

    const restarted = account => (sessions.get(account) || []).find(session => session.idles >= 2 && session.dones >= 1);

    await createAccount(defaultAccount, {});
    await createAccount(restartAccount, { maxIdleTime: MAX_IDLE_TIME });

    // The stored value round-trips through the account API
    const accountData = await server.get(`/v1/account/${restartAccount}`).expect(200);
    assert.equal(accountData.body.imap.maxIdleTime, MAX_IDLE_TIME);

    const startedAt = Date.now();
    await waitForCondition(async () => restarted(restartAccount), {
        timeout: RESTART_TIMEOUT,
        message: `Account ${restartAccount} never restarted IDLE on one connection (IDLE counts: ${JSON.stringify((sessions.get(restartAccount) || []).map(session => [session.idles, session.dones]))})`
    });
    assert.ok(Date.now() - startedAt >= MAX_IDLE_TIME / 2, 'IDLE was not restarted sooner than configured');

    // Over the same stretch the account without the setting stays in its first IDLE
    const defaultSessions = sessions.get(defaultAccount) || [];
    assert.ok(defaultSessions.length, 'the default account reached IDLE too');
    for (const session of defaultSessions) {
        assert.ok(!session.dones, 'the default account did not break IDLE');
    }

    // An update can clear the setting again
    await server
        .put(`/v1/account/${restartAccount}`)
        .send({ imap: { partial: true, maxIdleTime: null } })
        .expect(200);
    const cleared = await server.get(`/v1/account/${restartAccount}`).expect(200);
    assert.ok(!cleared.body.imap.maxIdleTime, 'maxIdleTime was cleared');
});
