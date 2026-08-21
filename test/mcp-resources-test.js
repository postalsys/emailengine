'use strict';

// The MCP resources module (lib/mcp/resources.js). Pure - the module reaches Redis only through
// the injected requests it dispatches, and the listing/read tests below stub the Hapi server's
// inject() to answer them, so what is under test is exactly this module's own policy: which
// accounts get listed, and how each injected status code maps to an MCP answer.
//
// parseAccountUri is the single validation point for a client-supplied URI, reached from
// resources/read and from the subscriptions/listen filter. Every rejection has to come back as
// null: a throw from here carries no rpcCode, so it escapes the protocol layer's error mapping
// and the endpoint answers 500 with no JSON-RPC envelope at all.

const test = require('node:test');
const assert = require('node:assert').strict;

const { listResources, readResource, parseAccountUri, accountUri, isRepresentableAccountId, ACCOUNT_URI_PREFIX } = require('../lib/mcp/resources');

// A stub Hapi server whose inject() answers from a route map, recording every dispatched URL.
// The shape mirrors what lib/mcp/inject.js consumes from a real injection response.
function stubServer(responses) {
    const injected = [];
    return {
        injected,
        async inject(opts) {
            injected.push(opts);
            const reply = responses[`${opts.method} ${opts.url}`];
            return reply || { statusCode: 404, result: { message: 'Not found' } };
        }
    };
}

// The outer /mcp request as the module sees it: credential, headers, and the parked binding
function stubRequest(boundAccount) {
    return {
        auth: { credentials: { token: 'test-token' } },
        headers: {},
        app: boundAccount ? { mcpBoundAccount: boundAccount } : {}
    };
}

test('MCP account resource URIs', async t => {
    await t.test('round-trips an account id', () => {
        assert.equal(parseAccountUri(accountUri('user123')), 'user123');
        assert.equal(parseAccountUri(accountUri('user name')), 'user name');
        assert.equal(accountUri('a b'), `${ACCOUNT_URI_PREFIX}a%20b`);
    });

    await t.test('refuses an id carrying URI structure, even percent-encoded', () => {
        // These decode back into path, query and fragment separators, so admitting them would
        // let one URI name a different resource than it appears to
        for (const account of ['a/b', 'a?b', 'a#b']) {
            assert.equal(parseAccountUri(accountUri(account)), null, account);
        }
    });

    await t.test('returns null for a malformed percent-escape rather than throwing', () => {
        // decodeURIComponent throws URIError on these; an uncaught throw here became an HTTP 500
        for (const uri of [`${ACCOUNT_URI_PREFIX}%`, `${ACCOUNT_URI_PREFIX}%zz`, `${ACCOUNT_URI_PREFIX}%E0%A4`, `${ACCOUNT_URI_PREFIX}100%`]) {
            assert.doesNotThrow(() => parseAccountUri(uri), `must not throw for ${uri}`);
            assert.equal(parseAccountUri(uri), null, uri);
        }
    });

    await t.test('returns null for anything that is not an account URI', () => {
        for (const uri of [undefined, null, 42, '', 'file:///etc/passwd', 'emailengine://message/1', `${ACCOUNT_URI_PREFIX}`, `${ACCOUNT_URI_PREFIX}a/b`]) {
            assert.equal(parseAccountUri(uri), null, JSON.stringify(uri));
        }
    });
});

test('MCP resource listing and reads', async t => {
    await t.test('lists accounts through the injected listing, skipping unrepresentable ids', async () => {
        const server = stubServer({
            'get /v1/accounts?page=0&pageSize=500': {
                statusCode: 200,
                result: {
                    accounts: [
                        { account: 'user1', name: 'User One', email: 'one@example.com', state: 'connected' },
                        // listed by REST, but its resource URI would be refused by parseAccountUri,
                        // so advertising it here would be a dead link
                        { account: 'has/slash', name: 'Broken', email: 'slash@example.com' },
                        { account: 'user2' }
                    ]
                }
            }
        });

        const resources = await listResources({ server, request: stubRequest() });

        assert.deepEqual(
            resources.map(entry => entry.uri),
            [accountUri('user1'), accountUri('user2')]
        );
        assert.equal(resources[0].title, 'User One');
        assert.match(resources[0].description, /one@example\.com/);
        assert.match(resources[0].description, /state: connected/);
        assert.equal(resources[1].title, 'user2');
    });

    await t.test('a bound credential sees its own account and only that', async () => {
        const server = stubServer({
            'get /v1/account/bound-1': { statusCode: 200, result: { account: 'bound-1', name: 'Bound', email: 'bound@example.com' } }
        });

        const resources = await listResources({ server, request: stubRequest('bound-1') });

        assert.equal(resources.length, 1);
        assert.equal(resources[0].uri, accountUri('bound-1'));
        // the binding decided the listing: no instance-wide request was dispatched
        assert.deepEqual(
            server.injected.map(entry => entry.url),
            ['/v1/account/bound-1']
        );
    });

    await t.test('a refused or failed listing answers empty rather than erroring', async () => {
        const denied = stubServer({ 'get /v1/accounts?page=0&pageSize=500': { statusCode: 403, result: { message: 'Unauthorized scope' } } });
        assert.deepEqual(await listResources({ server: denied, request: stubRequest() }), []);

        const deniedBound = stubServer({ 'get /v1/account/bound-1': { statusCode: 403, result: { message: 'Unauthorized account' } } });
        assert.deepEqual(await listResources({ server: deniedBound, request: stubRequest('bound-1') }), []);
    });

    await t.test('reads one account as JSON contents', async () => {
        const accountData = { account: 'user1', name: 'User One', state: 'connected' };
        const server = stubServer({ 'get /v1/account/user1': { statusCode: 200, result: accountData } });

        const contents = await readResource({ server, request: stubRequest(), uri: accountUri('user1') });

        assert.equal(contents.length, 1);
        assert.equal(contents[0].uri, accountUri('user1'));
        assert.equal(contents[0].mimeType, 'application/json');
        assert.deepEqual(JSON.parse(contents[0].text), accountData);
    });

    await t.test('maps read failures onto the protocol error codes', async () => {
        // an unparseable URI and a missing account are both the standard "resource not found"
        await assert.rejects(readResource({ server: stubServer({}), request: stubRequest(), uri: 'emailengine://message/1' }), err => err.rpcCode === -32002);

        const missing = stubServer({ 'get /v1/account/gone': { statusCode: 404, result: { message: 'Not found' } } });
        await assert.rejects(readResource({ server: missing, request: stubRequest(), uri: accountUri('gone') }), err => err.rpcCode === -32002);

        // any other refusal (a 403 from the account binding, for one) is an invalid-params
        // error carrying the API's own message
        const denied = stubServer({ 'get /v1/account/user1': { statusCode: 403, result: { message: 'Unauthorized account' } } });
        await assert.rejects(
            readResource({ server: denied, request: stubRequest(), uri: accountUri('user1') }),
            err => err.rpcCode === -32602 && /Unauthorized account/.test(err.message)
        );
    });

    await t.test('isRepresentableAccountId matches what parseAccountUri admits', () => {
        for (const account of ['user1', 'user name', 'user.name@example.com']) {
            assert.ok(isRepresentableAccountId(account), account);
            assert.equal(parseAccountUri(accountUri(account)), account);
        }
        for (const account of ['a/b', 'a?b', 'a#b', '', null, undefined]) {
            assert.ok(!isRepresentableAccountId(account), JSON.stringify(account));
        }
    });
});
