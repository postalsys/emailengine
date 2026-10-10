'use strict';

// Hardening of the IMAP proxy's pre-authentication surface (lib/imapproxy/imap-core) and of the
// handoff to the upstream session (lib/imapproxy/proxy-handoff.js).
//
//  - A deeply nested list is a parse error, and the debug-log compile of a parsed command can not
//    throw out of the socket's data handler (it used to overflow the stack and kill the worker).
//  - Literals are refused before any data is accepted when the command can not run in the current
//    state, and a single command can not announce literals without bound.
//  - maxConnections refuses excess connections with a BYE.
//  - A reset while waiting for the PROXY header does not crash, and a silent socket times out.
//  - At handoff, bytes the client sent after LOGIN reach the upstream, a client that left during
//    LOGIN gets its upstream closed, and the proxy logs carry the account id.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');
const { PassThrough } = require('node:stream');

const { IMAPServer, imapHandler } = require('../lib/imapproxy/imap-core/index.js');
const { IMAPCommand } = require('../lib/imapproxy/imap-core/lib/imap-command');
const { MAX_NESTING_DEPTH } = require('../lib/imapproxy/imap-core/lib/handler/imap-parser');
const { createProxyAuthHandler } = require('../lib/imapproxy/proxy-handoff');

function startServer(options, onAuth) {
    return new Promise((resolve, reject) => {
        const server = new IMAPServer(
            Object.assign(
                {
                    secure: false,
                    disableSTARTTLS: true,
                    proxyMode: true,
                    logger: false,
                    id: { name: 'EmailEngine IMAP Proxy Test' }
                },
                options
            )
        );
        if (onAuth) {
            server.onAuth = onAuth;
        }
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.server.address().port }));
    });
}

function closeServer(server) {
    return new Promise(resolve => server.close(() => resolve()));
}

// Connects and collects everything the server sends. `send(text)` writes raw data, `waitFor(re)`
// resolves once the collected text matches.
function connectClient(port, { proxyHeader } = {}) {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.setEncoding('utf8');
    const client = { socket, buffer: '', closed: false };
    let waiters = [];
    const check = () => {
        waiters = waiters.filter(w => {
            if (w.re.test(client.buffer)) {
                clearTimeout(w.timer);
                w.resolve(client.buffer);
                return false;
            }
            if (client.closed) {
                clearTimeout(w.timer);
                w.reject(new Error(`connection closed before ${w.re}; got: ${client.buffer.slice(-500)}`));
                return false;
            }
            return true;
        });
    };
    socket.on('data', chunk => {
        client.buffer += chunk;
        check();
    });
    socket.on('error', () => false);
    socket.on('close', () => {
        client.closed = true;
        check();
    });
    if (proxyHeader) {
        socket.write(proxyHeader);
    }
    client.send = text => socket.write(text);
    client.waitFor = (re, timeout = 4000) =>
        new Promise((resolve, reject) => {
            const w = { re, resolve, reject };
            w.timer = setTimeout(() => {
                waiters = waiters.filter(x => x !== w);
                reject(new Error(`timed out waiting for ${re}; got: ${client.buffer.slice(-500)}`));
            }, timeout);
            waiters.push(w);
            check();
        });
    client.waitClosed = (timeout = 4000) =>
        new Promise((resolve, reject) => {
            if (client.closed) {
                return resolve();
            }
            const timer = setTimeout(() => reject(new Error('connection was not closed')), timeout);
            socket.once('close', () => {
                clearTimeout(timer);
                resolve();
            });
        });
    return client;
}

function nested(depth) {
    return '('.repeat(depth) + 'a' + ')'.repeat(depth);
}

test('parser refuses a list nested deeper than MAX_NESTING_DEPTH', () => {
    assert.throws(() => imapHandler.parser(`A1 ID ${nested(6000)}`), /Too deep nesting/);
    assert.throws(() => imapHandler.parser(`A1 ID ${nested(MAX_NESTING_DEPTH + 1)}`), /Too deep nesting/);

    // ordinary nesting is unaffected
    const parsed = imapHandler.parser('A1 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)]<0.100>)');
    assert.equal(parsed.command, 'UID FETCH');
    assert.ok(imapHandler.parser(`A1 ID ${nested(50)}`).attributes);
});

test('the debug-log compile of a parsed command never throws', () => {
    // A tree deeper than the compiler's stack can handle, built by hand to bypass the parser cap.
    let root = [];
    let cur = root;
    for (let i = 0; i < 200000; i++) {
        let next = [];
        cur.push(next);
        cur = next;
    }
    const command = new IMAPCommand({ _badCount: 0 });
    command.tag = 'A1';
    command.command = 'ID';
    command.parsed = { tag: 'A1', command: 'ID', attributes: root };
    assert.equal(command.compileForLog(), 'A1 ID (* payload not loggable *)');
});

test('a deeply nested command over the socket gets BAD and the connection keeps working', async () => {
    const { server, port } = await startServer();
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        client.send(`A1 ID ${nested(6000)}\r\n`);
        await client.waitFor(/^A1 BAD .*Too deep nesting/m);
        client.send('A2 NOOP\r\n');
        await client.waitFor(/^A2 OK/m);
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('literals are refused before login when the command can not run yet', async () => {
    const { server, port } = await startServer();
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        client.send('A1 APPEND INBOX {1048576}\r\n');
        await client.waitFor(/^A1 BAD APPEND not allowed now/m);
        assert.doesNotMatch(client.buffer, /\+ Go ahead/);

        // the refused command is dropped entirely, the next line is a new command
        client.send('A2 NOOP\r\n');
        await client.waitFor(/^A2 OK/m);
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('a single command can not announce literals without bound', async () => {
    const { server, port } = await startServer();
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        let payload = 'A1 ID (';
        for (let i = 0; i < 40; i++) {
            payload += '{1}\r\na ';
        }
        client.send(payload + ')\r\n');
        await client.waitFor(/^A1 NO Too much literal data/m);
        // Count the continuations that preceded the refusal. The lines left in the payload after
        // it are parsed as new commands, and how many of their answers have already arrived
        // depends on socket chunking (the CI runners deliver them together with the NO)
        const beforeRefusal = client.buffer.split('A1 NO Too much literal data')[0];
        assert.equal(beforeRefusal.split('+ Go ahead').length - 1, 32);
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('maxConnections refuses excess connections with a BYE', async () => {
    const { server, port } = await startServer({ maxConnections: 2 });
    try {
        const first = connectClient(port);
        const second = connectClient(port);
        await first.waitFor(/\* OK /);
        await second.waitFor(/\* OK /);

        const third = connectClient(port);
        await third.waitFor(/\* BYE Too many connections/);
        await third.waitClosed();

        // a slot frees up once a connection closes
        first.socket.destroy();
        const deadline = Date.now() + 4000;
        while (server._socketCount > 1 && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        const fourth = connectClient(port);
        await fourth.waitFor(/\* OK /);

        second.socket.destroy();
        fourth.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('PROXY protocol: a reset before the header does not crash, a silent socket times out', async () => {
    const { server, port } = await startServer({ useProxy: ['*'], proxyHeaderTimeout: 200 });
    try {
        // reset while the server waits for the header
        const reset = net.connect({ port, host: '127.0.0.1' });
        reset.on('error', () => false);
        await new Promise(resolve => reset.once('connect', resolve));
        reset.write('PROX');
        await new Promise(r => setTimeout(r, 50));
        reset.resetAndDestroy();
        await new Promise(r => setTimeout(r, 100));

        // a socket that never sends the header is closed by the server
        const silent = connectClient(port);
        await silent.waitClosed(2000);

        // and a proper header still works
        const client = connectClient(port, { proxyHeader: 'PROXY TCP4 10.0.0.1 10.0.0.2 1234 993\r\n' });
        await client.waitFor(/\* OK .*10\.0\.0\.1/);
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

// Handoff through the real LOGIN path, with a stub upstream (PassThrough pair) and stub auth.

function fakeLogger(records, bindings = {}) {
    const log = {};
    for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
        log[level] = entry => records.push(Object.assign({ level }, bindings, entry));
    }
    log.child = extra => fakeLogger(records, Object.assign({}, bindings, extra));
    return log;
}

function makeHandoff({ authDelay = 0 } = {}) {
    const records = [];
    const state = { records, closed: 0, upstreamLogBindings: null };
    const readSocket = new PassThrough();
    const writeSocket = new PassThrough();
    state.upstreamReceived = '';
    writeSocket.on('data', chunk => {
        state.upstreamReceived += chunk.toString();
    });
    const imapClient = {
        close() {
            state.closed++;
        }
    };
    const handler = createProxyAuthHandler({
        onAuth: async () => {
            if (authDelay) {
                await new Promise(r => setTimeout(r, authDelay));
            }
            return { accountData: { account: 'acct-123' }, imapConfig: { host: 'upstream' } };
        },
        createProxy: async ({ logger }) => {
            logger.info({ msg: 'upstream logger probe' });
            return { readSocket, writeSocket, imapClient };
        },
        logger: fakeLogger(records),
        serverLogger: fakeLogger(records),
        metrics: () => false,
        logRaw: false
    });
    return { handler, state };
}

test('handoff: bytes pipelined after LOGIN reach the upstream, logs carry the account id', async () => {
    const { handler, state } = makeHandoff({ authDelay: 100 });
    const { server, port } = await startServer({}, handler);
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        // one in the same chunk as LOGIN, one written while LOGIN is still running
        client.send('A1 LOGIN user pass\r\nA2 NOOP\r\n');
        await new Promise(r => setTimeout(r, 30));
        client.send('A3 SELECT INBOX\r\n');
        await client.waitFor(/^A1 OK/m);

        const deadline = Date.now() + 4000;
        while (!state.upstreamReceived.includes('A3 SELECT INBOX') && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        assert.equal(state.upstreamReceived, 'A2 NOOP\r\nA3 SELECT INBOX\r\n');

        // later traffic keeps flowing, in order
        client.send('A4 LOGOUT\r\n');
        while (!state.upstreamReceived.includes('A4') && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        assert.match(state.upstreamReceived, /A3 SELECT INBOX\r\nA4 LOGOUT\r\n$/);

        const probe = state.records.find(r => r.msg === 'upstream logger probe');
        assert.equal(probe.account, 'acct-123');
        const enabled = state.records.find(r => r.msg === 'Proxy mode enabled');
        assert.equal(enabled.account, 'acct-123');

        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('handoff: a client that disconnects during LOGIN gets its upstream closed', async () => {
    const { handler, state } = makeHandoff({ authDelay: 200 });
    const { server, port } = await startServer({}, handler);
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        client.send('A1 LOGIN user pass\r\n');
        await new Promise(r => setTimeout(r, 30));
        client.socket.destroy();

        const deadline = Date.now() + 4000;
        while (!state.closed && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        assert.equal(state.closed, 1, 'upstream connection must be closed');
        assert.ok(state.records.some(r => /Client disconnected during login/.test(r.msg)));
    } finally {
        await closeServer(server);
    }
});

test('an internal fault during authentication is not reflected to the client', async () => {
    // AUTHENTICATE PLAIN used to hand an onAuth error straight back, which imap-core sent as
    // `BAD <message>`: an upstream or Redis error text reached a client that had not logged in,
    // and the BAD counted against the connection's bad-command budget. Both commands now answer
    // an error that names no IMAP response with a bare NO [TEMPFAIL], and one that does with
    // exactly that response.
    const faults = {
        fault: new Error('Connection to 10.0.0.5:6379 lost'),
        response: Object.assign(new Error('[UNAVAILABLE] Temporary failure, try again later'), { response: 'NO' })
    };
    const { server, port } = await startServer({}, (login, session, callback) => callback(faults[login.username] || null, null));
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);

        client.send(`A1 AUTHENTICATE PLAIN ${Buffer.from('\0fault\0pass').toString('base64')}\r\n`);
        await client.waitFor(/^A1 /m);
        assert.match(client.buffer, /^A1 NO \[TEMPFAIL\]/m);

        client.send('A2 LOGIN fault pass\r\n');
        await client.waitFor(/^A2 /m);
        assert.match(client.buffer, /^A2 NO \[TEMPFAIL\]/m);

        client.send(`A3 AUTHENTICATE PLAIN ${Buffer.from('\0response\0pass').toString('base64')}\r\n`);
        await client.waitFor(/^A3 /m);
        assert.match(client.buffer, /^A3 NO \[UNAVAILABLE\] Temporary failure, try again later/m);

        assert.doesNotMatch(client.buffer, /10\.0\.0\.5|BAD/, 'the fault text must stay in the log');
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('handoff: an internal fault is answered with a generic NO, its text stays in the log', async () => {
    // The proxy's own auth boundary used to hand a fault (a Redis error, a missing OAuth2 app,
    // an unreachable upstream) back to imap-core as it was, so its message reached the client.
    const records = [];
    const handler = createProxyAuthHandler({
        onAuth: async login => {
            if (login.username === 'fault') {
                throw new Error('Connection to 10.0.0.5:6379 lost');
            }
            return { accountData: { account: 'acct-123' }, imapConfig: { host: 'upstream' } };
        },
        createProxy: async () => {
            throw new Error('connect ECONNREFUSED 192.0.2.10:993');
        },
        logger: fakeLogger(records),
        serverLogger: fakeLogger(records),
        metrics: () => false,
        logRaw: false
    });
    const { server, port } = await startServer({}, handler);
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);

        // the credential check itself failed
        client.send(`A1 AUTHENTICATE PLAIN ${Buffer.from('\0fault\0pass').toString('base64')}\r\n`);
        await client.waitFor(/^A1 /m);
        assert.match(client.buffer, /^A1 NO \[UNAVAILABLE\] Temporary failure, try again later\r\n/m);

        // the upstream connection failed
        client.send('A2 LOGIN user pass\r\n');
        await client.waitFor(/^A2 /m);
        assert.match(client.buffer, /^A2 NO \[UNAVAILABLE\] Temporary failure, try again later\r\n/m);

        assert.doesNotMatch(client.buffer, /10\.0\.0\.5|192\.0\.2\.10|BAD/);
        assert.ok(records.some(r => r.level === 'error' && r.err && /10\.0\.0\.5/.test(r.err.message)));
        assert.ok(records.some(r => r.level === 'error' && r.err && /192\.0\.2\.10/.test(r.err.message)));
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('handoff: an upstream opened for a login that then fails is closed', async () => {
    // The upstream session is opened before the CAPABILITY untagged response is compiled, and a
    // failure there refused the client while the upstream stayed open until the server idled it out
    const records = [];
    let closed = 0;
    const handler = createProxyAuthHandler({
        onAuth: async () => ({ accountData: { account: 'acct-123' }, imapConfig: { host: 'upstream' } }),
        createProxy: async () => ({
            readSocket: new PassThrough(),
            writeSocket: new PassThrough(),
            imapClient: {
                // a capability list the compiler can not render
                get rawCapabilities() {
                    throw new Error('unexpected capability response');
                },
                close() {
                    closed++;
                }
            }
        }),
        logger: fakeLogger(records),
        serverLogger: fakeLogger(records),
        metrics: () => false,
        logRaw: false
    });
    const { server, port } = await startServer({}, handler);
    try {
        const client = connectClient(port);
        await client.waitFor(/\* OK /);
        client.send('A1 LOGIN user pass\r\n');
        await client.waitFor(/^A1 /m);
        assert.match(client.buffer, /^A1 NO /m);
        assert.equal(closed, 1, 'the upstream session is closed');
        client.socket.destroy();
    } finally {
        await closeServer(server);
    }
});

test('an error on a freshly accepted socket is absorbed until a handler takes over', () => {
    // Without the PROXY protocol the accepted socket is handed over a tick later, and until then
    // nothing listened for errors on it: a reset landing in that window was an uncaught 'error'
    // that took down the worker and every session it was proxying.
    const { EventEmitter } = require('node:events');
    const server = new IMAPServer({ secure: false, disableSTARTTLS: true, proxyMode: true, logger: false });
    const socket = Object.assign(new EventEmitter(), { remoteAddress: '192.0.2.1' });

    assert.equal(server._acceptSocket(socket), true);
    assert.doesNotThrow(() => socket.emit('error', Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' })));
    socket.emit('close');
    assert.equal(server._socketCount, 0);
});

test('implicit TLS: a client that never completes the handshake is disconnected', async () => {
    // The PROXY header timeout is cleared once the header is read and the session's own socket
    // timeout only starts after the handshake, so a client that connected and sent nothing held
    // its socket and its maxConnections slot for good.
    const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
    const { cert, privateKey } = await createSelfSignedCertificate({ hostnames: ['localhost'], keyType: 'ec' });
    const { server, port } = await startServer({ secure: true, key: privateKey, cert, tlsHandshakeTimeout: 200 });
    const errors = [];
    server.on('error', err => errors.push(err));
    try {
        const silent = connectClient(port);
        await silent.waitClosed(2000);
        assert.ok(
            errors.some(err => /TLS handshake timed out/.test(err.message) && err.report === false),
            'the timeout is reported as a quiet client-side failure'
        );

        const deadline = Date.now() + 2000;
        while (server._socketCount && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        assert.equal(server._socketCount, 0, 'the connection slot is released');
    } finally {
        await closeServer(server);
    }
});
