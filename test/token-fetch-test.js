'use strict';

// lib/oauth/token-fetch.js: what the provider clients report when the token endpoint cannot be reached
// at all.
//
// A rejected response is already described in detail by each client (ETokenRefresh, the status, the
// parsed body). A request that never got there was not: undici rejects with a bare `fetch failed`
// whose own `code` is unset, the reason sitting on err.cause, so the connectError webhook carried
// "fetch failed" and no serverResponseCode - indistinguishable from the mail server itself being
// unreachable, which is the one thing it is not.
//
// The classification must not change with it. A token endpoint that could not be reached has NOT
// refused the refresh token, and an error carrying a code of its own would be read as an
// authentication failure and park the account, so both halves are asserted.
//
// No outbound network: the reachable endpoint is a server on a loopback port, and the unreachable one is
// a loopback port a server held just long enough to reserve it and then released - a hardcoded port
// might be in use, and the low ones undici refuses outright as "bad port" before it ever connects.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');

const { fetchTokenRequest } = require('../lib/oauth/token-fetch');
const { isTransientCredentialError, credentialErrorStatus } = require('../lib/email-client/credential-errors');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const CONTEXT = { method: 'post', grant: 'refresh_token', provider: 'gmail', clientId: 'client-id' };

// A loopback port with nothing on it, so the connection is refused without a DNS lookup
async function reserveFreePort() {
    const probe = http.createServer();
    await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address();
    await new Promise(resolve => probe.close(resolve));
    return port;
}

test('fetchTokenRequest()', async t => {
    const server = http.createServer((req, res) => {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const reachableUrl = `http://127.0.0.1:${server.address().port}/token`;
    const unreachableUrl = `http://127.0.0.1:${await reserveFreePort()}/token`;

    await t.test('a reachable endpoint is returned whatever its status', async () => {
        // The helper does not decide what a status means; each client already does that in detail
        const res = await fetchTokenRequest(reachableUrl, { method: 'post', body: 'grant_type=refresh_token' }, CONTEXT);

        assert.equal(res.status, 400);
        assert.deepEqual(await res.json(), { error: 'invalid_grant' });
    });

    await t.test('an unreachable endpoint is named, with the cause code promoted', async () => {
        await assert.rejects(fetchTokenRequest(unreachableUrl, { method: 'post', body: 'grant_type=refresh_token' }, CONTEXT), err => {
            assert.match(err.message, new RegExp(`^Token request to ${unreachableUrl.replace(/[.\\/:]/g, '\\$&')} failed`), err.message);
            // Promoted off err.cause, which is where undici puts it, so the connectError webhook has
            // something to report in serverResponseCode
            assert.equal(err.code, 'ECONNREFUSED');
            assert.match(err.message, /ECONNREFUSED/);

            assert.equal(err.tokenRequest.url, unreachableUrl);
            assert.equal(err.tokenRequest.provider, 'gmail');
            assert.equal(err.tokenRequest.grant, 'refresh_token');
            assert.equal(err.tokenRequest.errorCode, 'ECONNREFUSED');
            assert.equal(err.tokenRequest.status, undefined, 'there is no response, so no status is recorded');
            assert.equal(err.tokenRequest.error, 'fetch failed', 'the original message is kept');
            return true;
        });
    });

    await t.test('the failure stays transient, so the account is not parked', async () => {
        await assert.rejects(fetchTokenRequest(unreachableUrl, { method: 'post' }, CONTEXT), err => {
            assert.equal(isTransientCredentialError(err), true, 'an unreachable token endpoint has not refused the credential');
            assert.equal(credentialErrorStatus(err), 0, 'nothing answered, so there is no status to read');
            return true;
        });
    });
});
