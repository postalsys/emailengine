'use strict';

// Shared helpers for the live-server integration tier (test/integration/*-test.js). Kept in one
// place so the tracking / unsubscribe-events specs do not each re-declare them. api-test.js and
// sendonly-test.js predate this module and keep their own inline copies on purpose (they run as
// standalone files and are left untouched). The Ethereal/polling implementations live in the
// cross-tier module test/helpers/ethereal.js (shared with test/e2e); this wrapper only bakes in
// the integration-tier polling defaults. The Dovecot tier (test/dovecot) also imports
// ACCESS_TOKEN and waitForCondition from here - it runs against the same test-server setup.

const crypto = require('node:crypto');
const net = require('node:net');
const testConfig = require('./test-config');
const { createUsableTestAccount, waitForCondition: waitForConditionBase, etherealAccountPayload } = require('../helpers/ethereal');

// The prepared serviceSecret from config/test.toml. Tracking / unsubscribe URLs are signed with an
// HMAC-SHA256 of the JSON payload keyed by this secret, so tests can forge valid signed blobs
// without a lib/db handle (same approach as tracking-signature-test.js).
const SERVICE_SECRET = 'a cat';

// The prepared "*"-scope access token from config/test.toml - authenticates REST API calls that
// verify/clean up accounts the integration tests create.
const ACCESS_TOKEN = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

// Poll `checkFn` until it returns a truthy value (then return it) or the timeout elapses.
async function waitForCondition(checkFn, options = {}) {
    const { interval = testConfig.POLL_INTERVAL, timeout = testConfig.DEFAULT_TIMEOUT, message } = options;
    return waitForConditionBase(checkFn, { interval, timeout, message });
}

// Poll the account state through the REST API until it reaches 'connected'. Throws early when the
// account settles in an error state. `server` is the supertest agent of the calling spec.
async function waitForAccountConnected(server, account, timeout) {
    await waitForCondition(
        async () => {
            const response = await server.get(`/v1/account/${account}`);
            if (response.status !== 200) {
                return false;
            }
            switch (response.body.state) {
                case 'authenticationError':
                case 'connectError':
                    throw new Error('Invalid account state ' + response.body.state);
                case 'connected':
                    return true;
            }
            return false;
        },
        { timeout, message: `Account ${account} connection timeout` }
    );
}

// Wait for a messageSent webhook with the given queue id to land on the shared webhook receiver.
async function waitForMessageSent(account, queueId, timeout, message) {
    const webhooksServer = require('./webhooks-server');
    return await waitForCondition(
        async () => {
            const webhooks = webhooksServer.webhooks.get(account) || [];
            return webhooks.find(wh => wh.event === 'messageSent' && wh.data.queueId === queueId);
        },
        { timeout, message }
    );
}

// Poll a mailbox listing through the REST API until the predicate over the message array settles.
async function waitForListing(server, account, path, predicate, timeout, message) {
    return await waitForCondition(
        async () => {
            const res = await server.get(`/v1/account/${account}/messages?path=${encodeURIComponent(path)}&pageSize=20`);
            if (res.status !== 200) {
                return false;
            }
            return predicate(res.body.messages || []);
        },
        { timeout, message }
    );
}

// Sign a payload object the way EmailEngine signs tracking / unsubscribe blobs: base64url(JSON) as
// `data` and base64url(HMAC-SHA256(JSON)) as `sig`. Mirrors lib/tools.js getSignedFormDataSync.
function signBlob(obj) {
    const data = Buffer.from(JSON.stringify(obj));
    const sig = crypto.createHmac('sha256', SERVICE_SECRET).update(data).digest('base64url');
    return { data: data.toString('base64url'), sig };
}

// Find the crumb (CSRF token) value in a response's set-cookie headers, so a scripted POST can pass
// the crumb plugin the same way a browser would.
function extractCrumb(setCookie) {
    for (const cookie of setCookie || []) {
        const match = /(?:^|;\s*)crumb=([^;]+)/.exec(cookie);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
}

// Scripted mock IMAP server for hermetic connection tests - just enough protocol for ImapFlow
// to get through the connection setup. Default handlers cover CAPABILITY/ID/LOGIN/LOGOUT and
// answer everything else with a tagged OK; `onCommand({ tag, cmd, args, send, session })` runs
// first and takes over a command by returning true (per-connection state can be stashed on
// `session`; the default LOGIN handler stores the login user in `session.user`). Resolves to
// `{ port, close }`; `close()` destroys lingering client sockets first, because server.close()
// fires its callback only after every socket has ended, and accounts keep retrying against the
// mock until they are deleted. phantom-folder-test.js keeps its own richer inline mock on
// purpose (a stateful SELECT/STATUS machine with per-folder failure scripting that would bloat
// this helper); fold it in only if a third test needs that depth.
function startMockImapServer({ capabilities = 'IMAP4rev1 IDLE ID UIDPLUS', onCommand } = {}) {
    const sockets = new Set();

    const mockServer = net.createServer(socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        let buf = '';
        const session = {};

        const send = line => {
            if (!socket.destroyed) {
                socket.write(line + '\r\n');
            }
        };

        send(`* OK [CAPABILITY ${capabilities}] Mock IMAP ready.`);

        const handle = line => {
            const m = line.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
            if (!m) {
                return;
            }
            const [, tag, cmdRaw, args] = m;
            const cmd = cmdRaw.toUpperCase();

            if (onCommand && onCommand({ tag, cmd, args, send, session }) === true) {
                return;
            }

            switch (cmd) {
                case 'CAPABILITY':
                    send(`* CAPABILITY ${capabilities}`);
                    send(`${tag} OK Capability completed.`);
                    break;
                case 'ID':
                    send('* ID ("name" "MockIMAP")');
                    send(`${tag} OK ID completed.`);
                    break;
                case 'LOGIN': {
                    // ImapFlow sends the credentials as quoted strings
                    const userMatch = (args || '').match(/^"([^"]*)"/);
                    session.user = userMatch ? userMatch[1] : null;
                    send(`${tag} OK [CAPABILITY ${capabilities}] Logged in`);
                    break;
                }
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
                        for (const socket of sockets) {
                            socket.destroy();
                        }
                        mockServer.close(() => done());
                    })
            });
        });
    });
}

module.exports = {
    createUsableTestAccount,
    waitForCondition,
    waitForAccountConnected,
    waitForMessageSent,
    waitForListing,
    etherealAccountPayload,
    signBlob,
    extractCrumb,
    startMockImapServer,
    SERVICE_SECRET,
    ACCESS_TOKEN
};
