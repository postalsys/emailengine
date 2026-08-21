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
