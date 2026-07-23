'use strict';

// Regression test for the account-level IMAP4rev2 opt-out (imap.disableIMAP4rev2).
//
// Some servers advertise IMAP4rev2 but have a broken implementation of it, so an
// account can set imap.disableIMAP4rev2 to keep the connection on IMAP4rev1
// without losing the other auto-enabled extensions. The stored option flows
// verbatim into the ImapFlow connection config, and this test asserts the whole
// chain by inspecting the ENABLE command a mock IMAP server receives. Fully
// hermetic - a failure here is never an external flake.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');
const { ACCESS_TOKEN, waitForCondition, startMockImapServer } = require('./helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

const ENABLE_TIMEOUT = 30000;

// CONDSTORE is advertised alongside IMAP4rev2 so that the opt-out connection
// still sends an ENABLE command - the assertion can then check what the command
// contained instead of inferring from its absence
const CAPABILITIES = 'IMAP4rev1 IMAP4rev2 ENABLE CONDSTORE ID';

test('Account-level disableIMAP4rev2 controls the ENABLE command', async t => {
    const suffix = crypto.randomBytes(4).toString('hex');
    const defaultAccount = `rev2-default-${suffix}`;
    const optOutAccount = `rev2-disabled-${suffix}`;

    // login user -> array of ENABLE argument strings, e.g. 'CONDSTORE IMAP4REV2'
    const enableCommands = new Map();

    // Records the ENABLE arguments per login user; the folder listing is rejected
    // afterwards so the connection setup ends there (the account settles into
    // connectError, which is irrelevant for this test)
    const mock = await startMockImapServer({
        capabilities: CAPABILITIES,
        onCommand({ tag, cmd, args, send, session }) {
            switch (cmd) {
                case 'ENABLE':
                    if (session.user) {
                        if (!enableCommands.has(session.user)) {
                            enableCommands.set(session.user, []);
                        }
                        enableCommands.get(session.user).push(args || '');
                    }
                    send(`* ENABLED ${args || ''}`);
                    send(`${tag} OK Enabled.`);
                    return true;
                case 'LIST':
                case 'LSUB':
                    send(`${tag} BAD Unsupported in this mock`);
                    return true;
            }
            return false;
        }
    });

    t.after(async () => {
        for (const account of [defaultAccount, optOutAccount]) {
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
                name: `IMAP4rev2 test (${account})`,
                imap: Object.assign(
                    {
                        host: '127.0.0.1',
                        port: mock.port,
                        secure: false,
                        // the login user doubles as the key for the recorded
                        // ENABLE commands, so both accounts can share one mock
                        auth: { user: account, pass: 'pass' },
                        resyncDelay: 3600
                    },
                    imapExtras
                )
            })
            .expect(200);
    };

    const waitForEnable = async account =>
        waitForCondition(
            async () => {
                const commands = enableCommands.get(account);
                return commands && commands.length ? commands : false;
            },
            { timeout: ENABLE_TIMEOUT, message: `Account ${account} never sent an ENABLE command` }
        );

    // Default account: IMAP4rev2 must be part of the ENABLE list
    await createAccount(defaultAccount, {});
    const defaultEnable = await waitForEnable(defaultAccount);
    assert.ok(/\bIMAP4REV2\b/i.test(defaultEnable[0]), `default account must enable IMAP4rev2 (sent: ${JSON.stringify(defaultEnable[0])})`);

    // Opt-out account: ENABLE is still sent (for CONDSTORE), but without IMAP4rev2
    await createAccount(optOutAccount, { disableIMAP4rev2: true });
    const optOutEnable = await waitForEnable(optOutAccount);
    assert.ok(/\bCONDSTORE\b/i.test(optOutEnable[0]), `opt-out account must still enable other extensions (sent: ${JSON.stringify(optOutEnable[0])})`);
    for (const args of optOutEnable) {
        assert.ok(!/\bIMAP4REV2\b/i.test(args), `opt-out account must not enable IMAP4rev2 (sent: ${JSON.stringify(args)})`);
    }

    // The option must also round-trip through the account API
    const accountData = await server.get(`/v1/account/${optOutAccount}`).expect(200);
    assert.equal(accountData.body.imap.disableIMAP4rev2, true, 'disableIMAP4rev2 must be returned in the account response');
});
