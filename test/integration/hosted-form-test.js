'use strict';

// Integration tests for the hosted authentication form's unauthenticated (auth:false) endpoints:
//
//  - POST /accounts/new/imap - email autodiscovery (outbound DNS/HTTP) before rendering page 2. Gated
//    like its siblings: requires the signed blob AND a single-use nonce (n/t), and shares a per-blob
//    probe cap so a leaked link cannot drive an unbounded autodiscovery SSRF oracle.
//  - POST /accounts/new/imap/test - the connection tester. It must require the signed data/sig blob
//    it was issued; otherwise anyone could drive outbound IMAP/SMTP connections to arbitrary hosts
//    (SSRF / internal port scan / credential relay). Covers reject (unsigned/bad sig) + accept, plus
//    the shared per-blob probe cap.
//  - POST /accounts/new/imap/server - account creation. The single-use nonce must dedupe concurrent
//    double-submits and reject replays so a leaked/retried URL cannot create duplicate accounts.
//
// Runs against the shared test server (config/test.toml).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const he = require('he');
const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert').strict;

const { signBlob, extractCrumb, ACCESS_TOKEN } = require('./helpers');

const baseUrl = `http://127.0.0.1:${config.api.port}`;

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

// The same connection fields pointed at closed local ports, so a request that passes the gate fails
// fast (immediate ECONNREFUSED) without real outbound traffic.
const closedPortConnectionFields = Object.assign({}, connectionFields, { imap_port: 1, smtp_port: 1, imap_secure: 'false', smtp_secure: 'false' });

// Fields for the account-creation step (POST /accounts/new/imap/server). A closed port is fine -
// the account is stored regardless of whether the connection later succeeds.
const serverFields = Object.assign({ email: 'user@example.com', imap_disabled: 'false' }, closedPortConnectionFields);

// Static access token (scope "*") from config/test.toml - verifies created accounts and cleans up.
const authed = supertest.agent(baseUrl).auth(ACCESS_TOKEN, { type: 'bearer' });

// The setup endpoints answer with an HTML redirect page rather than a Location header, so the created
// account id has to come out of the rendered link.
function extractAccountId(text) {
    const m = /account=([^&"'<>\s]+)/.exec(text || '');
    return m ? m[1] : null;
}

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
        // Include a nonce (n/t): the connection tester now requires it (see the require-nonce test below).
        const { data, sig } = signBlob({
            account: 'ssrf-gate-positive',
            email: 'user@example.com',
            n: crypto.randomBytes(16).toString('base64url'),
            t: Date.now()
        });
        // Point at a closed port so verifyAccountInfo fails fast (ECONNREFUSED). A 200 with
        // imap.success=false proves the request passed the signature gate and reached the tester -
        // i.e. the gate does not break the legitimate "Verify connection" flow.
        const res = await agent
            .post('/accounts/new/imap/test')
            .set('content-type', 'application/json')
            .send(Object.assign({ crumb, data, sig }, closedPortConnectionFields));
        assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.text}`);
        assert.equal(res.body && res.body.imap && res.body.imap.success, false, 'connection test should run and fail against the closed port');
    });
});

test('Hosted form connection/create endpoints require a nonce in the signed blob', async t => {
    // A validly-signed blob issued WITHOUT a single-use nonce (n/t) - e.g. the existing-account reauth
    // blob before it was hardened - must be rejected at the connection/create endpoints so a leaked,
    // never-expiring blob cannot drive outbound connections (SSRF) or overwrite an account.
    await t.test('/imap/test rejects a validly signed blob that carries no nonce', async () => {
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({ account: 'no-nonce', email: 'user@example.com' });
        const res = await agent
            .post('/accounts/new/imap/test')
            .set('content-type', 'application/json')
            .send(Object.assign({ crumb, data, sig }, closedPortConnectionFields));
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });

    await t.test('/imap/server rejects a validly signed blob that carries no nonce', async () => {
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({ account: 'no-nonce-server', email: 'user@example.com' });
        const res = await agent.post('/accounts/new/imap/server').type('form').send(Object.assign({ crumb, data, sig }, serverFields));
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });

    await t.test('/accounts/new/imap (page-1 autodetect) rejects a validly signed blob that carries no nonce', async () => {
        // The signed blob is valid, but without n/t requireNonce rejects it with 403 BEFORE the handler
        // runs autodetectImapSettings - so a leaked never-expiring blob cannot drive outbound autodiscovery.
        // email + password are supplied so the request passes payload validation and reaches the nonce gate.
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({ account: 'no-nonce-page1', email: 'user@example.com' });
        const res = await agent.post('/accounts/new/imap').type('form').send({ crumb, data, sig, email: 'user@example.com', password: 'secret' });
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });
});

test('Hosted form bounds outbound probes per issued blob', async t => {
    // The autodetect (/accounts/new/imap) and connection-test (/accounts/new/imap/test) endpoints authorize
    // by signature but do NOT consume the single-use nonce (a form autodetects/tests several times before
    // submitting), so a shared per-blob counter caps how many outbound probes one signed link can drive -
    // otherwise a leaked link is an unbounded SSRF / port-scan oracle. Exhaust the budget via the connection
    // tester (closed ports fail fast without real outbound traffic), then confirm the cap is enforced, is
    // shared with the page-1 autodetect endpoint, and is scoped per nonce.
    const probeFields = (data, sig, crumb) => Object.assign({ crumb, data, sig }, closedPortConnectionFields);

    await t.test('rejects probes past the cap, shared across endpoints and scoped per nonce', { timeout: 60000 }, async () => {
        const { agent, crumb } = await crumbAgent();
        const n = crypto.randomBytes(16).toString('base64url');
        const { data, sig } = signBlob({ account: 'probe-cap', email: 'user@example.com', n, t: Date.now() });

        // The cap size is defense-in-depth, not a contract, so discover it rather than hardcoding: keep
        // probing until a 429. Bounded so a missing/broken cap fails the test instead of looping forever.
        const MAX_PROBES = 200;
        let capped = false;
        for (let i = 0; i < MAX_PROBES; i++) {
            const r = await agent
                .post('/accounts/new/imap/test')
                .set('content-type', 'application/json')
                .send(probeFields(data, sig, crumb));
            if (r.status === 429) {
                capped = true;
                break;
            }
            // Under the cap the tester runs against the closed port and returns 200 (imap.success=false).
            assert.equal(r.status, 200, `probe ${i + 1} should be under the cap (200), got ${r.status}`);
        }
        assert.ok(capped, `the tester should reject a probe with 429 within ${MAX_PROBES} attempts`);

        // Shared counter: the page-1 autodetect endpoint uses the same per-nonce budget, so the exhausted
        // nonce is rejected there too - with 429 raised BEFORE autodetect, so no outbound lookup happens.
        const page1 = await agent.post('/accounts/new/imap').type('form').send({ crumb, data, sig, email: 'user@example.com', password: 'secret' });
        assert.equal(page1.status, 429, `the exhausted nonce must be capped on the autodetect endpoint too, got ${page1.status}`);

        // Per-nonce scope: a freshly issued blob has its own budget and is not collateral-capped.
        const fresh = signBlob({ account: 'probe-cap-fresh', email: 'user@example.com', n: crypto.randomBytes(16).toString('base64url'), t: Date.now() });
        const freshRes = await agent
            .post('/accounts/new/imap/test')
            .set('content-type', 'application/json')
            .send(probeFields(fresh.data, fresh.sig, crumb));
        assert.notEqual(freshRes.status, 429, `a fresh nonce must have its own probe budget, got ${freshRes.status}`);
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

test('Hosted form enforces the expected account identity on the IMAP arm', async t => {
    // The IMAP arm is the sidestep the OAuth-only version of this constraint left open: a form that offers
    // both tabs would let the user pick IMAP and attach any mailbox with a password. The evidence here is
    // only the submitted address (working credentials do not prove the address belongs to that mailbox),
    // so what is asserted is "the account is registered under the expected address, or not at all".
    const createdAccounts = [];

    t.after(async () => {
        for (const id of createdAccounts) {
            await authed.delete(`/v1/account/${id}`).catch(() => {});
        }
    });

    const submit = async (blob, overrides) => {
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob(Object.assign({ n: crypto.randomBytes(16).toString('base64url'), t: Date.now() }, blob));
        return agent
            .post('/accounts/new/imap/server')
            .type('form')
            .send(Object.assign({ crumb, data, sig }, serverFields, overrides));
    };

    await t.test('a matching address is accepted and the pin is stored on the account', async () => {
        const res = await submit({ expectedEmail: 'user@example.com', redirectUrl: 'https://example.com/done' });
        assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.text}`);

        const id = extractAccountId(res.text);
        assert.ok(id, 'the successful response should reference the created account id');
        createdAccounts.push(id);

        // Persisted, so it also applies to later setups driven by a link that carries no expectation.
        const acct = await authed.get(`/v1/account/${id}`);
        assert.equal(acct.status, 200, 'the created account should exist');
        assert.equal(acct.body.expectedEmail, 'user@example.com', 'the expectation should be pinned to the account');
    });

    await t.test('a different address is rejected and no account is created', async () => {
        const account = `identity-mismatch-${crypto.randomBytes(6).toString('hex')}`;
        const res = await submit({ account, expectedEmail: 'owner@example.com' }, { email: 'someone-else@example.com' });

        assert.equal(res.status, 403, `expected 403, got ${res.status}: ${res.text}`);
        // The rejection must happen before create(), not after - an account written and then reported as
        // rejected would be the exact failure this constraint exists to prevent.
        const acct = await authed.get(`/v1/account/${account}`);
        assert.equal(acct.status, 404, 'the rejected setup must not have created an account');
    });

    await t.test('the rejection names both addresses and offers a way back', async () => {
        // The user picked the wrong account, which is correctable, so the flow stops on an error page with
        // a retry link rather than redirecting to the calling application - the hosted form only ever
        // redirects on success. Naming both addresses is what lets someone spot a near-miss, since the
        // comparison is exact.
        const account = `identity-retry-${crypto.randomBytes(6).toString('hex')}`;
        const res = await submit(
            { account, expectedEmail: 'owner@example.com', redirectUrl: 'https://example.com/done' },
            { email: 'someone-else@example.com' }
        );

        assert.equal(res.status, 403, `expected the error page, got ${res.status}: ${res.text}`);
        // Handlebars entity-escapes the `=` inside the href, so compare against the decoded markup.
        const html = he.decode(res.text);
        assert.match(html, /owner@example\.com/, 'the page must name the expected address');
        assert.match(html, /someone-else@example\.com/, 'the page must name the address that was used');
        // The blob is still unspent (the nonce is claimed after this check), so the retry link works.
        // type=imap keeps the user on the arm they chose instead of re-asking the provider question.
        assert.match(html, /href="\/accounts\/new\?data=[^"]+&sig=[^"]+&type=imap"/, 'the page must offer a way back into the form they were on');
        assert.ok(!/example\.com\/done/.test(html), 'a rejected setup must not redirect to the calling application');
    });

    await t.test('a stored pin applies to a link that carries no expectation of its own', async () => {
        const account = `identity-stored-${crypto.randomBytes(6).toString('hex')}`;
        const created = await authed.post('/v1/account').send({
            account,
            name: 'Pinned Account',
            email: 'owner@example.com',
            expectedEmail: 'owner@example.com',
            imap: { auth: { user: 'owner@example.com', pass: 'secret' }, host: '127.0.0.1', port: 1, secure: false },
            smtp: { auth: { user: 'owner@example.com', pass: 'secret' }, host: '127.0.0.1', port: 1, secure: false }
        });
        assert.equal(created.status, 200, `account setup failed: ${created.text}`);
        createdAccounts.push(account);

        // No expectedEmail in the blob: this is the admin re-authenticate case, and an older API-issued
        // link behaves the same. The pin must be inherited rather than dropped.
        const rejected = await submit({ account }, { email: 'someone-else@example.com' });
        assert.equal(rejected.status, 403, `expected the stored pin to reject, got ${rejected.status}`);

        // And clearing it through the authenticated API lets the same submission through, which is the
        // escape hatch for a legitimate mailbox migration.
        const cleared = await authed.put(`/v1/account/${account}`).send({ expectedEmail: null });
        assert.equal(cleared.status, 200, `failed to clear the pin: ${cleared.text}`);

        const accepted = await submit({ account }, { email: 'someone-else@example.com' });
        assert.equal(accepted.status, 200, `expected the cleared account to accept, got ${accepted.status}: ${accepted.text}`);
    });

    await t.test('page 1 rejects a mismatched address before autodiscovery runs', async () => {
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({
            expectedEmail: 'owner@example.com',
            n: crypto.randomBytes(16).toString('base64url'),
            t: Date.now()
        });

        const res = await agent.post('/accounts/new/imap').type('form').send({ crumb, data, sig, email: 'someone-else@example.com', password: 'secret' });

        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });
});

test('Hosted form re-renders with the signed blob on validation failure', async t => {
    // When server-side validation fails, the form is re-rendered. It must carry the signed data/sig
    // blob forward - otherwise the hidden inputs render empty and both re-submit and the "Verify
    // connection" button (which now requires `data`) break.
    await t.test('a validation error preserves data/sig in the re-rendered form', async () => {
        const { agent, crumb } = await crumbAgent();
        const n = crypto.randomBytes(16).toString('base64url');
        const { data, sig } = signBlob({ n, t: Date.now(), redirectUrl: 'https://example.com/done' });
        // A malformed email makes server-side Joi validation fail, triggering the failAction re-render.
        const fields = Object.assign({ crumb, data, sig }, serverFields, { email: 'not-a-valid-email' });

        const res = await agent.post('/accounts/new/imap/server').type('form').send(fields);

        assert.ok(res.text && res.text.includes(`value="${data}"`), 'the data blob must survive into the re-rendered form');
        assert.ok(res.text && res.text.includes(`value="${sig}"`), 'the sig must survive into the re-rendered form');
        // The submitted IMAP/SMTP passwords ('secret') must not be echoed back into the HTML response.
        assert.ok(!res.text.includes('value="secret"'), 'the submitted password must NOT be echoed into the re-rendered form');
    });

    await t.test('boolean checkbox fields reflect the raw submission on re-render', async () => {
        // failAction runs on the RAW (un-Joi-converted) payload, so imap_secure/smtp_secure arrive as
        // strings. Without normalization the template's {{#if values.imap_secure}} treats the string
        // 'false' as truthy and re-renders an unchecked TLS box as CHECKED. Verify both directions (the
        // 'true' case also confirms the assertion actually detects a checked box).
        const boxChecked = (html, id) => new RegExp(`id="${id}"[^>]*\\bchecked\\b`).test(html);

        const render = async secure => {
            const { agent, crumb } = await crumbAgent();
            const { data, sig } = signBlob({ n: crypto.randomBytes(16).toString('base64url'), t: Date.now() });
            const fields = Object.assign({ crumb, data, sig }, serverFields, {
                email: 'not-a-valid-email',
                imap_secure: secure,
                smtp_secure: secure
            });
            return (await agent.post('/accounts/new/imap/server').type('form').send(fields)).text;
        };

        const off = await render('false');
        assert.ok(!boxChecked(off, 'imap_secure'), "imap_secure='false' must not re-render checked");
        assert.ok(!boxChecked(off, 'smtp_secure'), "smtp_secure='false' must not re-render checked");

        const on = await render('true');
        assert.ok(boxChecked(on, 'imap_secure'), "imap_secure='true' must re-render checked");
        assert.ok(boxChecked(on, 'smtp_secure'), "smtp_secure='true' must re-render checked");

        // A string OUTSIDE the truthy/falsy lists fails coercion, and Joi then keeps the RAW value
        // ('no', which is truthy) in its output - rebuildFormValues must drop the failed key so the
        // checkbox re-renders unchecked instead of flipping to checked against the user's intent.
        const outOfList = await render('no');
        assert.ok(!boxChecked(outOfList, 'imap_secure'), "imap_secure='no' (failed coercion) must not re-render checked");
        assert.ok(!boxChecked(outOfList, 'smtp_secure'), "smtp_secure='no' (failed coercion) must not re-render checked");
    });

    await t.test('a duplicated data field does not corrupt the re-rendered hidden blob', async () => {
        // Duplicate form fields parse as an array; Joi fails the string check but keeps the raw
        // array, which would render value="A,B" into the hidden input and permanently break every
        // resubmit. rebuildFormValues drops the failed key, so the input re-renders empty instead.
        const { agent, crumb } = await crumbAgent();
        const { data, sig } = signBlob({ n: crypto.randomBytes(16).toString('base64url'), t: Date.now() });

        // Hand-build the urlencoded body: supertest's .send(object) cannot produce duplicate keys.
        const body = new URLSearchParams();
        body.append('crumb', crumb);
        body.append('data', data);
        body.append('data', data);
        body.append('sig', sig);
        for (const [key, value] of Object.entries(serverFields)) {
            body.append(key, value);
        }

        const res = await agent.post('/accounts/new/imap/server').type('form').send(body.toString());

        assert.ok(!res.text.includes(`value="${data},${data}"`), 'the array value must not be echoed into the hidden data input');
    });
});
