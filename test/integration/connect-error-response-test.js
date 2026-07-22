'use strict';

// Regression test for the "IMAP response: [object Object]" account error state.
//
// When a connection attempt failed on a rejected IMAP command (reported in the
// field with an Exchange IMAP4rev2 server answering LIST/LSUB with BAD),
// EmailEngine stored ImapFlow's parsed response object in the lastErrorState
// `response` field instead of the response text. The admin UI and the REST API
// (whose Joi schema declares lastError.response as a string) then surfaced the
// error as "[object Object]", hiding the actual server reply from the operator.
// Fixed on both layers: ImapFlow rewrites command errors to a string response
// (enhanceCommandError in the list command since 1.4.9) and EmailEngine only
// stores string responses, falling back to responseText / the error message.
//
// Like the phantom-folder suite this test is fully hermetic: it runs against an
// in-process mock IMAP server on localhost and needs no external services or
// credentials. A failure here is never an external flake.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('net');
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');
const { ACCESS_TOKEN, waitForCondition } = require('./helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

// The BAD text the customer's Exchange server used - the exact wording does not
// matter, but reusing it keeps the test aligned with the original report
const BAD_TEXT = 'Command Argument Error. 12';

const ERROR_TIMEOUT = 30000;

// Scripted mock IMAP server, just enough protocol for ImapFlow: authentication
// succeeds, but every LIST/LSUB is rejected with BAD, so the connection setup
// fails after login and the account lands in the connectError state.
function startMockImap() {
    const sockets = new Set();

    const mockServer = net.createServer(socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        let buf = '';

        const send = line => {
            if (!socket.destroyed) {
                socket.write(line + '\r\n');
            }
        };

        send('* OK [CAPABILITY IMAP4rev1 IDLE ID UIDPLUS] Mock IMAP ready.');

        const handle = line => {
            const m = line.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
            if (!m) {
                return;
            }
            const [, tag, cmdRaw] = m;
            const cmd = cmdRaw.toUpperCase();

            switch (cmd) {
                case 'CAPABILITY':
                    send('* CAPABILITY IMAP4rev1 IDLE ID UIDPLUS');
                    send(`${tag} OK Capability completed.`);
                    break;
                case 'ID':
                    send('* ID ("name" "MockIMAP")');
                    send(`${tag} OK ID completed.`);
                    break;
                case 'LOGIN':
                    send(`${tag} OK [CAPABILITY IMAP4rev1 IDLE ID UIDPLUS] Logged in`);
                    break;
                case 'LIST':
                case 'LSUB':
                    send(`${tag} BAD ${BAD_TEXT}`);
                    break;
                case 'LOGOUT':
                    send('* BYE Logging out');
                    send(`${tag} OK Logout completed.`);
                    socket.end();
                    break;
                default:
                    send(`${tag} OK ${cmd} completed.`);
            }
        };

        socket.on('data', chunk => {
            buf += chunk.toString('binary');
            let idx;
            while ((idx = buf.indexOf('\r\n')) >= 0) {
                const line = buf.slice(0, idx);
                buf = buf.slice(idx + 2);
                handle(line);
            }
        });

        socket.on('error', () => {});
    });

    return new Promise(resolve => {
        mockServer.listen(0, '127.0.0.1', () => {
            resolve({
                port: mockServer.address().port,
                close: () =>
                    new Promise(done => {
                        // Destroy lingering client connections first - server.close()
                        // fires its callback only after every socket has ended, and the
                        // account keeps retrying against this mock until it is deleted
                        for (const socket of sockets) {
                            socket.destroy();
                        }
                        mockServer.close(() => done());
                    })
            });
        });
    });
}

test('Connection error response is stored as text', async t => {
    const account = `connect-error-${crypto.randomBytes(4).toString('hex')}`;
    const mock = await startMockImap();

    t.after(async () => {
        try {
            await server.delete(`/v1/account/${account}`);
        } catch (err) {
            // account might not exist if the test failed early
        }
        await mock.close();
    });

    await server
        .post(`/v1/account`)
        .send({
            account,
            name: `Connect error test (${account})`,
            imap: {
                host: '127.0.0.1',
                port: mock.port,
                secure: false,
                auth: { user: 'testuser', pass: 'pass' },
                resyncDelay: 3600
            }
        })
        .expect(200);

    // Login succeeds but the folder listing fails, so the account must settle
    // into connectError (not authenticationError)
    const accountData = await waitForCondition(
        async () => {
            const response = await server.get(`/v1/account/${account}`).expect(200);
            return response.body.state === 'connectError' ? response.body : false;
        },
        { timeout: ERROR_TIMEOUT, message: `Account ${account} did not report connectError` }
    );

    // The whole point: the stored response is the server's reply text, not a
    // parsed response object that renders as "[object Object]"
    assert.ok(accountData.lastError, 'lastError must be present');
    assert.equal(typeof accountData.lastError.response, 'string', `lastError.response must be a string (got ${typeof accountData.lastError.response})`);
    assert.ok(
        accountData.lastError.response.includes(BAD_TEXT),
        `lastError.response must carry the server reply (got ${JSON.stringify(accountData.lastError.response)})`
    );
});
