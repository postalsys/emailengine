'use strict';

// Integration tests for the hosted authentication form's unauthenticated (auth:false) endpoints:
//
//  - POST /accounts/new/imap/test - the connection tester. It must require the signed data/sig blob
//    it was issued; otherwise anyone could drive outbound IMAP/SMTP connections to arbitrary hosts
//    (SSRF / internal port scan / credential relay). Covers reject (unsigned/bad sig) + accept.
//  - POST /accounts/new/imap/server - account creation. The single-use nonce must dedupe concurrent
//    double-submits and reject replays so a leaked/retried URL cannot create duplicate accounts.
//
// Runs against the shared test server (config/test.toml).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert').strict;

const baseUrl = `http://127.0.0.1:${config.api.port}`;
// Prepared serviceSecret from config/test.toml - lets the test sign a valid blob without lib/db.
const SERVICE_SECRET = 'a cat';

function signBlob(obj) {
    const data = Buffer.from(JSON.stringify(obj));
    const sig = crypto.createHmac('sha256', SERVICE_SECRET).update(data).digest('base64url');
    return { data: data.toString('base64url'), sig };
}

function extractCrumb(setCookie) {
    for (const cookie of setCookie || []) {
        const match = /(?:^|;\s*)crumb=([^;]+)/.exec(cookie);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
}

// A complete set of imap/smtp fields: absent the signature gate this request would be well-formed
// enough to trigger an outbound connection. The point is that it must never get that far.
const connectionFields = {
    imap_auth_user: 'user@example.com',
    imap_auth_pass: 'secret',
    imap_host: '127.0.0.1',
    imap_port: 993,
    imap_secure: 'true',
    smtp_auth_user: 'user@example.com',
    smtp_auth_pass: 'secret',
    smtp_host: '127.0.0.1',
    smtp_port: 465,
    smtp_secure: 'true'
};

// Fields for the account-creation step (POST /accounts/new/imap/server). A closed port is fine -
// the account is stored regardless of whether the connection later succeeds.
const serverFields = {
    email: 'user@example.com',
    imap_auth_user: 'user@example.com',
    imap_auth_pass: 'secret',
    imap_host: '127.0.0.1',
    imap_port: 1,
    imap_secure: 'false',
    imap_disabled: 'false',
    smtp_auth_user: 'user@example.com',
    smtp_auth_pass: 'secret',
    smtp_host: '127.0.0.1',
    smtp_port: 1,
    smtp_secure: 'false'
};

// Static access token (scope "*") from config/test.toml - verifies created accounts and cleans up.
const TOKEN = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';
const authed = supertest.agent(baseUrl).auth(TOKEN, { type: 'bearer' });

async function crumbAgent() {
    const agent = supertest.agent(baseUrl);
    const page = await agent.get('/admin/login');
    const crumb = extractCrumb(page.headers['set-cookie']);
    assert.ok(crumb, 'expected a crumb cookie');
    return { agent, crumb };
}

test('Hosted form connection test requires a signed blob', async t => {
    await t.test('rejects a request with no signed data/sig', async () => {
        const { agent, crumb } = await crumbAgent();
        const res = await agent.post('/accounts/new/imap/test').set('content-type', 'application/json').send(Object.assign({ crumb }, connectionFields));
        // `data` is now required by the schema, so an unsigned request fails validation (400) and
        // never reaches verifyAccountInfo.
        assert.equal(res.status, 400, `expected 400, got ${res.status}`);
    });

    await t.test('rejects a request with a bad signature', async () => {
        const { agent, crumb } = await crumbAgent();
        const data = Buffer.from(JSON.stringify({ account: 'x', n: 'AAAAAAAAAAAAAAAAAAAAAA', t: Date.now() })).toString('base64url');
        const res = await agent
            .post('/accounts/new/imap/test')
            .set('content-type', 'application/json')
            .send(Object.assign({ crumb, data, sig: 'wrongsignature' }, connectionFields));
        // Signature verification fails inside the handler before any connection is attempted.
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });

    await t.test('accepts a validly signed request and reaches the connection test', async () => {
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({ account: 'ssrf-gate-positive', email: 'user@example.com' });
        // Point at a closed port so verifyAccountInfo fails fast (ECONNREFUSED). A 200 with
        // imap.success=false proves the request passed the signature gate and reached the tester -
        // i.e. the gate does not break the legitimate "Verify connection" flow.
        const res = await agent
            .post('/accounts/new/imap/test')
            .set('content-type', 'application/json')
            .send(Object.assign({ crumb, data, sig }, connectionFields, { imap_port: 1, smtp_port: 1, imap_secure: 'false', smtp_secure: 'false' }));
        assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.text}`);
        assert.equal(res.body && res.body.imap && res.body.imap.success, false, 'connection test should run and fail against the closed port');
    });
});

test('Hosted form account creation dedupes the single-use nonce', async t => {
    const createdAccounts = [];

    t.after(async () => {
        // Best-effort cleanup of accounts this test created.
        for (const id of createdAccounts) {
            await authed.delete(`/v1/account/${id}`).catch(() => {});
        }
    });

    const extractAccountId = text => {
        const m = /account=([^&"'<>\s]+)/.exec(text || '');
        return m ? m[1] : null;
    };

    const submitFields = crumb => {
        const n = crypto.randomBytes(16).toString('base64url');
        const { data, sig } = signBlob({ n, t: Date.now(), redirectUrl: 'https://example.com/done' });
        return Object.assign({ crumb, data, sig }, serverFields);
    };

    await t.test('concurrent identical submissions create the account only once', async () => {
        const { agent, crumb } = await crumbAgent();
        // One signed blob (one nonce) submitted several times in parallel; account id auto-generated.
        const fields = submitFields(crumb);

        const responses = await Promise.all([0, 1, 2].map(() => agent.post('/accounts/new/imap/server').type('form').send(fields)));

        const ok = responses.filter(r => r.status === 200);
        const statuses = responses.map(r => r.status).join(',');
        assert.equal(ok.length, 1, `exactly one submission should succeed, got statuses [${statuses}]`);
        assert.equal(responses.filter(r => r.status === 403).length, responses.length - 1, 'the other submissions must be rejected as replays');

        const id = extractAccountId(ok[0].text);
        assert.ok(id, 'the successful response should reference the created account id');
        createdAccounts.push(id);

        const acct = await authed.get(`/v1/account/${id}`);
        assert.equal(acct.status, 200, 'the created account should exist');
    });

    await t.test('re-submitting the same signed URL is rejected', async () => {
        const { agent, crumb } = await crumbAgent();
        const fields = submitFields(crumb);

        const first = await agent.post('/accounts/new/imap/server').type('form').send(fields);
        assert.equal(first.status, 200, `first submission should succeed, got ${first.status}`);
        const id = extractAccountId(first.text);
        if (id) {
            createdAccounts.push(id);
        }

        // Same signed blob (same nonce): now consumed, so the replay must be rejected.
        const replay = await agent.post('/accounts/new/imap/server').type('form').send(fields);
        assert.equal(replay.status, 403, `replay should be rejected, got ${replay.status}`);
    });
});
