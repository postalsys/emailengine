'use strict';

// Regression test for phantom folders that are listed but can not be selected.
//
// Some servers (seen with Dovecot and mailbox list indexes) list a shared
// namespace root like "Shared Folders" without \Noselect, answer STATUS for it,
// but reject SELECT with "NO [NONEXISTENT]". Before the fixes this aborted the
// whole account connection setup, retried it about once a second forever (the
// reconnect backoff counter was reset on every cycle), and leaked one ImapFlow
// instance per cycle in the connection tracking set until the process ran out
// of memory.
//
// Unlike the other integration suites this test is fully hermetic: it runs
// against in-process mock IMAP servers on localhost and needs no external
// services or credentials. A failure here is never an external flake.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('net');
const crypto = require('crypto');
const supertest = require('supertest');
const Redis = require('ioredis');
const config = require('@zone-eu/wild-config');
const { ACCESS_TOKEN, waitForCondition } = require('./helpers');

const redis = new Redis(config.dbs.redis);
const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

const SHARED = 'Shared Folders';
const CONNECT_TIMEOUT = 30000;

// Scripted mock IMAP server, just enough protocol for ImapFlow. Lists a
// "Shared Folders" namespace root that can not be selected:
// - sharedStatus 'ok': STATUS answers with counters (Dovecot list-index style),
//   SELECT is rejected with NO [NONEXISTENT] - the bug scenario
// - sharedStatus 'no': STATUS is rejected as well - control scenario
// - listNonExistent: the root is listed with a \NonExistent flag (RFC 5258)
// - killOnPhantomSelect: the NO reply is followed by the server dropping the
//   connection, like a Dovecot session dying on the failed SELECT of a broken
//   shared namespace root (seen in the wild; the drop used to cause an
//   unthrottled reconnect loop)
function startMockImap({ sharedStatus = 'ok', listNonExistent = false, killOnPhantomSelect = false } = {}) {
    const counters = { connects: 0, logins: 0, sharedSelects: 0, sharedStatuses: 0 };
    const sockets = new Set();

    const listRows = [
        ['\\HasNoChildren', 'INBOX'],
        [listNonExistent ? '\\HasChildren \\NonExistent' : '\\HasChildren', SHARED],
        ['\\HasNoChildren', `${SHARED}/team`]
    ];

    const mockServer = net.createServer(socket => {
        counters.connects++;
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        let buf = '';
        let idleTag = null;

        const send = line => {
            if (!socket.destroyed) {
                socket.write(line + '\r\n');
            }
        };

        send('* OK [CAPABILITY IMAP4rev1 IDLE ID UIDPLUS] Mock IMAP ready.');

        const selectOk = tag => {
            send('* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)');
            send('* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.');
            send('* 0 EXISTS');
            send('* 0 RECENT');
            send('* OK [UIDVALIDITY 1751000000] UIDs valid');
            send('* OK [UIDNEXT 1] Predicted next UID');
            send(`${tag} OK [READ-WRITE] Select completed.`);
        };

        const handle = line => {
            const m = line.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
            if (!m) {
                if (idleTag && /^DONE$/i.test(line.trim())) {
                    send(`${idleTag} OK Idle completed.`);
                    idleTag = null;
                }
                return;
            }
            const [, tag, cmdRaw, restRaw] = m;
            const cmd = cmdRaw.toUpperCase();
            const rest = restRaw || '';

            // resolve quoted or atom mailbox argument
            const mailboxArg = () => {
                let mq = rest.match(/^"((?:[^"\\]|\\.)*)"/);
                if (mq) {
                    return mq[1].replace(/\\(.)/g, '$1');
                }
                let ma = rest.match(/^(\S+)/);
                return ma ? ma[1] : '';
            };

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
                    counters.logins++;
                    send(`${tag} OK [CAPABILITY IMAP4rev1 IDLE ID UIDPLUS] Logged in`);
                    break;
                case 'LIST':
                case 'LSUB': {
                    const pat = rest.replace(/^"[^"]*"\s+/, '').replace(/^"|"$/g, '');
                    for (const [flags, path] of listRows) {
                        if (pat === '*' || pat === '%' || pat === path) {
                            send(`* ${cmd} (${flags}) "/" "${path}"`);
                        }
                    }
                    send(`${tag} OK ${cmd} completed.`);
                    break;
                }
                case 'STATUS': {
                    const path = mailboxArg();
                    if (path === SHARED) {
                        counters.sharedStatuses++;
                        if (sharedStatus === 'no') {
                            send(`${tag} NO Mailbox doesn't exist: ${SHARED}`);
                            break;
                        }
                    }
                    send(`* STATUS "${path}" (MESSAGES 0 UIDNEXT 1 UIDVALIDITY 1751000000)`);
                    send(`${tag} OK Status completed.`);
                    break;
                }
                case 'SELECT':
                case 'EXAMINE': {
                    const path = mailboxArg();
                    if (path === SHARED) {
                        counters.sharedSelects++;
                        send(`${tag} NO [NONEXISTENT] Mailbox doesn't exist: ${SHARED}`);
                        if (killOnPhantomSelect) {
                            // let the NO reach the client first, then drop the
                            // connection like a dying server session would
                            setTimeout(() => socket.destroy(), 25);
                        }
                    } else {
                        selectOk(tag);
                    }
                    break;
                }
                case 'IDLE':
                    idleTag = tag;
                    send('+ idling');
                    break;
                case 'LOGOUT':
                    send('* BYE Logging out');
                    send(`${tag} OK Logout completed.`);
                    socket.end();
                    break;
                case 'NOOP':
                case 'CLOSE':
                case 'SUBSCRIBE':
                case 'UNSUBSCRIBE':
                case 'ENABLE':
                case 'CHECK':
                    send(`${tag} OK ${cmd} completed.`);
                    break;
                default:
                    send(`${tag} BAD Unknown command`);
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
                counters,
                close: () =>
                    new Promise(done => {
                        // Destroy lingering client connections first - server.close()
                        // fires its callback only after every socket has ended, so a
                        // connection leaked by a failed subtest would otherwise keep
                        // the close promise (and the whole test run) hanging
                        for (const socket of sockets) {
                            socket.destroy();
                        }
                        mockServer.close(() => done());
                    })
            });
        });
    });
}

function accountPayload(account, port) {
    return {
        account,
        name: `Phantom folder test (${account})`,
        imap: {
            host: '127.0.0.1',
            port,
            secure: false,
            auth: { user: 'testuser', pass: 'pass' },
            // keep periodic resyncs out of the observation windows
            resyncDelay: 3600
        }
    };
}

async function waitForConnected(accountId) {
    await waitForCondition(
        async () => {
            const response = await server.get(`/v1/account/${accountId}`).expect(200);
            switch (response.body.state) {
                case 'authenticationError':
                case 'connectError':
                    throw new Error(`Invalid account state ${response.body.state}`);
                case 'connected':
                    return true;
            }
            return false;
        },
        { timeout: CONNECT_TIMEOUT, message: `Account ${accountId} connection timeout` }
    );
}

test('Phantom folder handling', async t => {
    const suffix = crypto.randomBytes(4).toString('hex');
    const accounts = {
        selectNo: `phantom-ok-${suffix}`,
        statusNo: `phantom-statusno-${suffix}`,
        nonExistent: `phantom-nonexistent-${suffix}`,
        killer: `phantom-killer-${suffix}`
    };
    const mocks = [];

    t.after(async () => {
        for (const account of Object.values(accounts)) {
            try {
                await server.delete(`/v1/account/${account}`);
            } catch (err) {
                // account might not exist if a subtest failed early
            }
        }
        for (const mock of mocks) {
            await mock.close();
        }
        await redis.quit();
    });

    // The live repro: STATUS answers, SELECT is rejected
    const mock = await startMockImap({ sharedStatus: 'ok' });
    mocks.push(mock);

    let loginsAtConnect;
    let connectionsAtConnect;

    await t.test('account connects although a listed folder can not be selected', async () => {
        const response = await server.post(`/v1/account`).send(accountPayload(accounts.selectNo, mock.port)).expect(200);
        assert.equal(response.body.state, 'new');

        await waitForConnected(accounts.selectNo);

        loginsAtConnect = mock.counters.logins;
        connectionsAtConnect = (await redis.hgetall(`iad:${accounts.selectNo}`)).connections;
    });

    await t.test('healthy folders are synced, the phantom folder is skipped', async () => {
        const response = await server.get(`/v1/account/${accounts.selectNo}/mailboxes`).expect(200);
        const paths = response.body.mailboxes.map(entry => entry.path);
        assert.ok(paths.includes('INBOX'), `INBOX must be listed (got ${paths.join(', ')})`);
        assert.ok(paths.includes(`${SHARED}/team`), 'the selectable child folder must be listed');

        // SELECT was attempted, rejected, and not retried in a loop
        assert.ok(mock.counters.sharedSelects >= 1, 'the phantom folder SELECT must have been attempted');
        assert.ok(mock.counters.sharedSelects <= 2, `SELECT of the phantom folder must not loop (got ${mock.counters.sharedSelects})`);
    });

    await t.test('no reconnect storm and no connection counter leak', async () => {
        // Pre-fix the account reconnected about once a second and the connection
        // counter grew by one per cycle, so 5 seconds is more than enough to
        // detect a regression
        await new Promise(resolve => setTimeout(resolve, 5000));

        assert.equal(mock.counters.logins, loginsAtConnect, 'no new logins may happen after the account is connected');
        assert.ok(mock.counters.logins <= 2, `connecting must not take more than a couple of logins (got ${mock.counters.logins})`);

        const response = await server.get(`/v1/account/${accounts.selectNo}`).expect(200);
        assert.equal(response.body.state, 'connected');

        const connections = (await redis.hgetall(`iad:${accounts.selectNo}`)).connections;
        assert.equal(connections, '1', `exactly one tracked connection expected (got ${connections})`);
        assert.equal(connections, connectionsAtConnect, 'connection counter must not grow after connecting');
    });

    await t.test('control: folder that fails STATUS is skipped silently', async () => {
        const statusNoMock = await startMockImap({ sharedStatus: 'no' });
        mocks.push(statusNoMock);

        await server.post(`/v1/account`).send(accountPayload(accounts.statusNo, statusNoMock.port)).expect(200);
        await waitForConnected(accounts.statusNo);

        // STATUS failed, so SELECT must not even be attempted
        assert.ok(statusNoMock.counters.sharedStatuses >= 1, 'STATUS of the phantom folder must have been attempted');
        assert.equal(statusNoMock.counters.sharedSelects, 0, 'phantom folder must not be selected when STATUS already failed');
    });

    await t.test('folders listed as \\NonExistent are ignored', async () => {
        const nonExistentMock = await startMockImap({ listNonExistent: true });
        mocks.push(nonExistentMock);

        await server.post(`/v1/account`).send(accountPayload(accounts.nonExistent, nonExistentMock.port)).expect(200);
        await waitForConnected(accounts.nonExistent);

        const response = await server.get(`/v1/account/${accounts.nonExistent}/mailboxes`).expect(200);
        const paths = response.body.mailboxes.map(entry => entry.path);
        assert.ok(!paths.includes(SHARED), 'the \\NonExistent folder must not be listed');
        assert.ok(paths.includes('INBOX'), 'INBOX must be listed');
        assert.ok(paths.includes(`${SHARED}/team`), 'the selectable child folder must be listed');

        assert.equal(nonExistentMock.counters.sharedStatuses, 0, 'the \\NonExistent folder must not be queried with STATUS');
        assert.equal(nonExistentMock.counters.sharedSelects, 0, 'the \\NonExistent folder must not be selected');
    });

    await t.test('server that drops the connection on a failed SELECT settles instead of login-storming', { timeout: 120000 }, async () => {
        const killMock = await startMockImap({ killOnPhantomSelect: true });
        mocks.push(killMock);

        await server.post(`/v1/account`).send(accountPayload(accounts.killer, killMock.port)).expect(200);

        // Every connection dies right after the phantom SELECT, so the account
        // can only settle once (a) close-triggered reconnects of short-lived
        // connections are throttled instead of immediate, and (b) the phantom
        // marker parks the folder after PHANTOM_SELECT_FAIL_THRESHOLD failed
        // passes, letting the next connection survive. Pre-fix this looped at
        // roughly 17 logins per second indefinitely.
        let stable = { logins: -1, since: 0 };
        await waitForCondition(
            async () => {
                const response = await server.get(`/v1/account/${accounts.killer}`).expect(200);
                if (killMock.counters.logins !== stable.logins) {
                    stable = { logins: killMock.counters.logins, since: Date.now() };
                    return false;
                }
                // connected with no new logins for 6 seconds = settled
                return response.body.state === 'connected' && Date.now() - stable.since >= 6000;
            },
            { timeout: 90000, message: `Account ${accounts.killer} did not settle` }
        );

        assert.ok(killMock.counters.logins <= 8, `settling must take a handful of logins, not a storm (got ${killMock.counters.logins})`);
        assert.ok(killMock.counters.sharedSelects <= 8, `the phantom folder must stop being probed (got ${killMock.counters.sharedSelects} SELECTs)`);

        // the folder is parked for syncing but must still show up in listings
        const response = await server.get(`/v1/account/${accounts.killer}/mailboxes`).expect(200);
        const paths = response.body.mailboxes.map(entry => entry.path);
        assert.ok(paths.includes('INBOX'), 'INBOX must be listed');
        assert.ok(paths.includes(SHARED), 'the phantom folder must still be listed');
    });
});
