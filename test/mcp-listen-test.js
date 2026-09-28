'use strict';

// The subscriptions/listen bridge (lib/mcp/listen.js): which requested subscriptions survive the
// per-account authorization filter, which streams a published account change reaches, and how
// many streams one credential may hold open. The Hapi server is stubbed at inject() - the same
// boundary lib/mcp/inject.js hands every authorization check to - so what is under test is this
// module's own policy, not the REST enforcement behind it.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    acceptFilter,
    openListenStream,
    handleListen,
    reserveListenStream,
    recheckListenStreams,
    publishAccountChange,
    canOpenListenStream,
    MAX_STREAMS_PER_CREDENTIAL,
    MAX_RESOURCE_SUBSCRIPTIONS
} = require('../lib/mcp/listen');
const { accountUri } = require('../lib/mcp/resources');
const { registeredPublishers } = require('../lib/response-stream');

// A server whose injected GET /v1/account/{account} answers 200 for the allowed set and 403
// otherwise, recording each dispatched URL so dedupe is observable
function stubServer(allowedAccounts) {
    const injected = [];
    return {
        injected,
        async inject(opts) {
            injected.push(opts.url);
            const account = decodeURIComponent(opts.url.replace('/v1/account/', ''));
            return allowedAccounts.includes(account)
                ? { statusCode: 200, result: { account } }
                : { statusCode: 403, result: { message: 'Unauthorized account' } };
        }
    };
}

function stubRequest(credential) {
    return {
        auth: { artifacts: { id: credential }, credentials: { token: 'test-token' } },
        headers: {},
        app: {}
    };
}

// The subset of the Hapi response toolkit openSseStream() consumes
function stubToolkit() {
    return {
        response(stream) {
            return {
                stream,
                headers: {},
                header(key, value) {
                    this.headers[key] = value;
                    return this;
                },
                type(value) {
                    this.contentType = value;
                    return this;
                }
            };
        }
    };
}

// Opens a listen stream and swaps its sendMessage for a recorder, so fanout targeting can be
// asserted without parsing SSE frames (delivery itself is lib/response-stream territory)
function openRecordingStream({ credential, accepted }) {
    const sent = [];
    const response = openListenStream({
        h: stubToolkit(),
        request: stubRequest(credential),
        subscriptionId: `sub-${credential}`,
        accepted
    });
    const stream = response.stream;
    stream.sendMessage = message => sent.push(message);
    return { stream, sent };
}

test('MCP listen streams', async t => {
    await t.test('acceptFilter keeps the readable accounts and silently drops the rest', async () => {
        const server = stubServer(['a1', 'a3']);

        const accepted = await acceptFilter({
            server,
            request: stubRequest('cred-1'),
            filter: {
                resourceSubscriptions: [
                    accountUri('a1'),
                    accountUri('a2'), // readable: no
                    accountUri('a3'),
                    accountUri('a1'), // duplicate: checked once
                    'emailengine://message/1', // not an account URI
                    `emailengine://account/%zz` // malformed escape
                ]
            }
        });

        assert.deepEqual(accepted.resourceSubscriptions, [accountUri('a1'), accountUri('a3')]);
        // one authorization check per unique parseable account, nothing for the junk entries
        assert.deepEqual(server.injected.sort(), ['/v1/account/a1', '/v1/account/a2', '/v1/account/a3']);
    });

    await t.test('acceptFilter acknowledges nothing when nothing survives', async () => {
        const server = stubServer([]);

        for (const filter of [{}, { resourceSubscriptions: [] }, { resourceSubscriptions: [accountUri('denied')] }, { toolListChanged: true }]) {
            const accepted = await acceptFilter({ server, request: stubRequest('cred-1'), filter });
            // the acknowledgment omitting a field is what tells the client it is not honored
            assert.deepEqual(accepted, {}, JSON.stringify(filter));
        }
    });

    await t.test('acceptFilter caps how many subscriptions one request may name', async () => {
        const accounts = Array.from({ length: MAX_RESOURCE_SUBSCRIPTIONS + 5 }, (_, i) => `acc-${i}`);
        const server = stubServer(accounts);

        const accepted = await acceptFilter({
            server,
            request: stubRequest('cred-1'),
            filter: { resourceSubscriptions: accounts.map(account => accountUri(account)) }
        });

        assert.equal(accepted.resourceSubscriptions.length, MAX_RESOURCE_SUBSCRIPTIONS);
        assert.equal(server.injected.length, MAX_RESOURCE_SUBSCRIPTIONS, 'entries past the cap must not cost an authorization check');
    });

    await t.test('publishAccountChange reaches exactly the streams subscribed to that account', async () => {
        const one = openRecordingStream({ credential: 'cred-1', accepted: { resourceSubscriptions: [accountUri('a1')] } });
        const two = openRecordingStream({ credential: 'cred-2', accepted: { resourceSubscriptions: [accountUri('a2')] } });
        const silent = openRecordingStream({ credential: 'cred-3', accepted: {} });

        try {
            publishAccountChange({ account: 'a1', state: 'connected' });

            assert.equal(one.sent.length, 1);
            assert.equal(one.sent[0].method, 'notifications/resources/updated');
            assert.equal(one.sent[0].params.uri, accountUri('a1'));
            assert.equal(one.sent[0].params._meta['io.modelcontextprotocol/subscriptionId'], 'sub-cred-1');

            assert.equal(two.sent.length, 0, 'a stream subscribed to another account must not hear it');
            assert.equal(silent.sent.length, 0, 'a stream with no subscriptions must not hear anything');

            // events without an account, and accounts nobody subscribed to, fan out to nobody
            publishAccountChange({ state: 'connected' });
            publishAccountChange({ account: 'a9', state: 'connected' });
            assert.equal(one.sent.length + two.sent.length + silent.sent.length, 1);
        } finally {
            for (const opened of [one, two, silent]) {
                opened.stream.finalize();
            }
        }
    });

    await t.test('listen streams stay out of the admin change-feed registry', async () => {
        const opened = openRecordingStream({ credential: 'cred-reg', accepted: {} });
        try {
            // the two fanouts must not receive each other's frames, which starts with the
            // streams never sharing a registry
            assert.ok(!registeredPublishers.has(opened.stream));
        } finally {
            opened.stream.finalize();
        }
    });

    await t.test('one credential is capped to MAX_STREAMS_PER_CREDENTIAL open streams', async () => {
        const opened = [];
        try {
            for (let i = 0; i < MAX_STREAMS_PER_CREDENTIAL; i++) {
                assert.ok(canOpenListenStream(stubRequest('cred-cap')), `stream ${i + 1} must be admitted`);
                opened.push(openRecordingStream({ credential: 'cred-cap', accepted: {} }));
            }

            assert.ok(!canOpenListenStream(stubRequest('cred-cap')), 'the stream past the cap must be refused');
            assert.ok(canOpenListenStream(stubRequest('cred-other')), 'the cap is per credential, not per worker');

            // closing a stream frees its slot
            opened.pop().stream.finalize();
            assert.ok(canOpenListenStream(stubRequest('cred-cap')));
        } finally {
            for (const entry of opened) {
                entry.stream.finalize();
            }
        }
    });
});

test('MCP listen admission under concurrency', async t => {
    await t.test('concurrent listen requests cannot pass the per-credential cap', async () => {
        // Holds every authorization check open until released, so all requests are in the
        // accept phase at the same time, which is where the old count-only check was blind
        const injected = [];
        let releaseChecks;
        const gate = new Promise(resolve => (releaseChecks = resolve));
        const server = {
            async inject(opts) {
                injected.push(opts.url);
                await gate;
                return { statusCode: 200 };
            }
        };

        const filter = { resourceSubscriptions: [accountUri('acct-1'), accountUri('acct-2')] };
        const attempts = Array.from({ length: 10 }, (v, i) =>
            handleListen({ h: stubToolkit(), server, request: stubRequest('cred-race'), subscriptionId: `race-${i}`, filter })
        );

        // Let every attempt reach its first await
        await new Promise(resolve => setImmediate(resolve));
        releaseChecks();
        const responses = await Promise.all(attempts);

        const opened = responses.filter(Boolean);
        try {
            assert.strictEqual(opened.length, MAX_STREAMS_PER_CREDENTIAL);
            // Only the admitted requests spent injected requests
            assert.strictEqual(injected.length, MAX_STREAMS_PER_CREDENTIAL * 2);
            assert.ok(!canOpenListenStream(stubRequest('cred-race')));
        } finally {
            for (const response of opened) {
                response.stream.finalize();
            }
        }
        assert.ok(canOpenListenStream(stubRequest('cred-race')), 'closing the streams frees the slots');
    });

    await t.test('a reservation is given back when authorization fails', async () => {
        const server = {
            async inject() {
                throw new Error('dispatch failed');
            }
        };
        for (let i = 0; i < MAX_STREAMS_PER_CREDENTIAL + 1; i++) {
            await assert.rejects(
                handleListen({
                    h: stubToolkit(),
                    server,
                    request: stubRequest('cred-fail'),
                    subscriptionId: `fail-${i}`,
                    filter: { resourceSubscriptions: [accountUri('acct-1')] }
                })
            );
        }
        assert.ok(canOpenListenStream(stubRequest('cred-fail')));
    });

    await t.test('reservations count against the cap before the stream exists', async () => {
        const releases = [];
        for (let i = 0; i < MAX_STREAMS_PER_CREDENTIAL; i++) {
            releases.push(reserveListenStream(stubRequest('cred-reserve')));
        }
        assert.ok(releases.every(Boolean));
        assert.strictEqual(reserveListenStream(stubRequest('cred-reserve')), null);
        releases[0]();
        releases[0]();
        const again = reserveListenStream(stubRequest('cred-reserve'));
        assert.ok(again, 'a released slot is available again, and releasing twice frees only one');
        assert.strictEqual(reserveListenStream(stubRequest('cred-reserve')), null);
        for (const release of [...releases, again]) {
            release();
        }
    });
});

test('MCP listen streams re-check their authorization', async t => {
    const waitFor = async (check, timeout) => {
        const until = Date.now() + timeout;
        while (!check() && Date.now() < until) {
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        return check();
    };

    // Answers each account's status from a table the test changes while the stream is open
    function mutableServer(statuses) {
        return {
            async inject(opts) {
                const account = decodeURIComponent(opts.url.replace('/v1/account/', ''));
                return { statusCode: statuses[account] || 200 };
            }
        };
    }

    await t.test('one pass probes each (credential, account) pair once, however many streams share it', async () => {
        // Each stream used to run its own timer and its own round of injected requests
        const server = stubServer(['acct-shared', 'acct-own']);
        const streams = [];
        const subscriptions = [[accountUri('acct-shared')], [accountUri('acct-shared'), accountUri('acct-own')]];
        for (let i = 0; i < subscriptions.length; i++) {
            const response = await handleListen({
                h: stubToolkit(),
                server,
                request: stubRequest('cred-shared'),
                subscriptionId: `shared-${i}`,
                filter: { resourceSubscriptions: subscriptions[i] }
            });
            streams.push(response.stream);
        }
        try {
            server.injected.length = 0;
            await recheckListenStreams();
            assert.deepStrictEqual(server.injected.sort(), ['/v1/account/acct-own', '/v1/account/acct-shared']);
            assert.ok(streams.every(stream => !stream.destroyed));
        } finally {
            for (const stream of streams) {
                stream.finalize();
            }
        }
    });

    await t.test('a revoked token closes the stream', async () => {
        const statuses = {};
        const response = await handleListen({
            h: stubToolkit(),
            server: mutableServer(statuses),
            request: stubRequest('cred-revoke'),
            subscriptionId: 'revoke',
            filter: { resourceSubscriptions: [accountUri('acct-1')] },
            recheckInterval: 20
        });
        const stream = response.stream;
        try {
            await new Promise(resolve => setTimeout(resolve, 60));
            assert.ok(!stream.destroyed, 'a credential that still reads the account keeps its stream');

            statuses['acct-1'] = 401;
            assert.ok(await waitFor(() => stream.destroyed, 1000), 'the stream closed once the token was gone');
        } finally {
            stream.finalize();
        }
    });

    await t.test('a lost grant drops that URI, and the stream once nothing is left', async () => {
        const statuses = {};
        const response = await handleListen({
            h: stubToolkit(),
            server: mutableServer(statuses),
            request: stubRequest('cred-grant'),
            subscriptionId: 'grant',
            filter: { resourceSubscriptions: [accountUri('acct-1'), accountUri('acct-2')] },
            recheckInterval: 20
        });
        const stream = response.stream;
        try {
            statuses['acct-1'] = 403;
            assert.ok(await waitFor(() => !stream.mcpSubscription.resourceUris.has(accountUri('acct-1')), 1000));
            assert.ok(!stream.destroyed);

            // A lost URI no longer receives notifications
            const sent = [];
            stream.sendMessage = message => sent.push(message);
            publishAccountChange({ account: 'acct-1' });
            assert.strictEqual(sent.length, 0);

            // A transient failure changes nothing
            statuses['acct-2'] = 503;
            await new Promise(resolve => setTimeout(resolve, 60));
            assert.ok(!stream.destroyed);

            statuses['acct-2'] = 403;
            assert.ok(await waitFor(() => stream.destroyed, 1000));
        } finally {
            stream.finalize();
        }
    });
});
