'use strict';

// The account resource URI parser (lib/mcp/resources.js). Pure - the module reaches Redis only
// through the injected requests its other exports make, which these tests do not touch.
//
// parseAccountUri is the single validation point for a client-supplied URI, reached from
// resources/read and from the subscriptions/listen filter. Every rejection has to come back as
// null: a throw from here carries no rpcCode, so it escapes the protocol layer's error mapping
// and the endpoint answers 500 with no JSON-RPC envelope at all.

const test = require('node:test');
const assert = require('node:assert').strict;

const { parseAccountUri, accountUri, ACCOUNT_URI_PREFIX } = require('../lib/mcp/resources');

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
