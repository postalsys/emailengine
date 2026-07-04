'use strict';

// Integration test for the unsubscribe / resubscribe webhook events, which the browser e2e tier
// cannot observe (it has no webhook receiver). Covers the two firing paths:
//   - RFC 8058 one-click POST /unsubscribe        -> listUnsubscribe
//   - the hosted form POST /unsubscribe/address   -> listUnsubscribe (unsubscribe) / listSubscribe (subscribe)
// Signed blobs are forged directly with the known test serviceSecret, so no message is sent; the
// routes only need the account to exist (loadAccountData) - the events are emitted from the main
// thread regardless of connection state (server.js cmd 'unsubscribe'/'subscribe').
//
// Runs against the shared live test server (config/test.toml): global webhooks deliver to the
// shared webhooks-server on 7078.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');
const { waitForCondition, signBlob, ACCESS_TOKEN: accessToken } = require('./helpers');

const baseUrl = `http://127.0.0.1:${config.api.port}`;

const server = supertest.agent(baseUrl).auth(accessToken, { type: 'bearer' });

const accountId = 'unsub-events-account';
// Keep the recipient lowercase: entries are stored lowercased, and the unsubscribe page decides its
// rendered state via hexists() against the original-case address - a mixed-case value would mismatch.
const rcpt = 'unsub-rcpt@example.com';
const messageId = `<unsub-events-${Date.now()}@example.com>`;
// Distinct, hostname-format list ids per path so their blocklist state and events do not overlap.
const listIdOneClick = `unsub-oneclick-${Date.now()}`;
const listIdForm = `unsub-form-${Date.now()}`;

// Find the crumb (CSRF token) the unsubscribe page embeds in its form, so a scripted POST passes
// the crumb plugin the same way a browser would. Named distinctly from helpers.js extractCrumb(setCookie),
// which parses the cookie header instead of the rendered HTML - do not conflate the two.
function extractCrumbFromHtml(html) {
    const match = html.match(/name="crumb"\s+value="([^"]+)"/);
    assert.ok(match, 'crumb token was not found in the rendered unsubscribe page');
    return match[1];
}

// True if `recipient` is currently listed on `listId`. A removed list 404s (deterministic), which
// we treat as "not listed".
async function blocklistEntry(listId, recipient) {
    const res = await server.get(`/v1/blocklist/${listId}`);
    if (res.status === 404) {
        return null;
    }
    assert.strictEqual(res.status, 200, `GET /v1/blocklist/${listId} -> ${res.status}`);
    return (res.body.addresses || []).find(a => a.recipient === recipient) || null;
}

test('Unsubscribe / resubscribe webhook events', async t => {
    t.before(async () => {
        await webhooksServer.init();

        // A registered account row is enough - the routes only call loadAccountData(), and the
        // events fire from the main thread without needing the account to be connected. Use local
        // closed-port credentials (POST /v1/account stores without verifying connectivity, same as
        // hosted-form-test's serverFields) instead of provisioning a real Ethereal account: zero
        // external network, no flake source, identical coverage.
        const authUser = 'unsub-events@example.com';
        await server
            .post(`/v1/account`)
            .send({
                account: accountId,
                name: 'Unsub Events',
                email: authUser,
                imap: {
                    host: '127.0.0.1',
                    port: 1,
                    secure: false,
                    auth: { user: authUser, pass: 'secret' }
                },
                smtp: {
                    host: '127.0.0.1',
                    port: 1,
                    secure: false,
                    auth: { user: authUser, pass: 'secret' }
                }
            })
            .expect(200);
    });

    t.after(async () => {
        await server.delete(`/v1/account/${accountId}`).catch(() => false);
        await webhooksServer.quit();
    });

    await t.test('One-click POST /unsubscribe fires listUnsubscribe', { timeout: 90000 }, async () => {
        const { data, sig } = signBlob({ act: 'unsub', acc: accountId, list: listIdOneClick, rcpt, msg: messageId });

        const res = await supertest(baseUrl).post('/unsubscribe').query({ data, sig }).type('form').send({ 'List-Unsubscribe': 'One-Click' });
        assert.strictEqual(res.text, 'ok');

        const webhook = await waitForCondition(
            async () => {
                const webhooks = webhooksServer.webhooks.get(accountId);
                return webhooks?.find(wh => wh.event === 'listUnsubscribe' && wh.data.listId === listIdOneClick) || null;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'listUnsubscribe (one-click) webhook timeout' }
        );

        assert.strictEqual(webhook.data.recipient, rcpt);

        const entry = await blocklistEntry(listIdOneClick, rcpt);
        assert.ok(entry, 'recipient should be on the one-click blocklist');
        assert.strictEqual(entry.source, 'one-click');
    });

    await t.test('Form POST /unsubscribe/address fires listUnsubscribe', { timeout: 90000 }, async () => {
        const { data, sig } = signBlob({ act: 'unsub', acc: accountId, list: listIdForm, rcpt, msg: messageId });

        // GET the page first to obtain the crumb cookie (agent) + value (form).
        const pageRes = await server.get('/unsubscribe').query({ data, sig }).expect(200);
        const crumb = extractCrumbFromHtml(pageRes.text);

        const res = await server.post('/unsubscribe/address').type('form').send({ action: 'unsubscribe', data, sig, crumb }).expect(200);
        assert.match(res.text, /was unsubscribed/, 'the page should confirm the unsubscribe');

        const webhook = await waitForCondition(
            async () => {
                const webhooks = webhooksServer.webhooks.get(accountId);
                return webhooks?.find(wh => wh.event === 'listUnsubscribe' && wh.data.listId === listIdForm) || null;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'listUnsubscribe (form) webhook timeout' }
        );

        assert.strictEqual(webhook.data.recipient, rcpt);

        const entry = await blocklistEntry(listIdForm, rcpt);
        assert.ok(entry, 'recipient should be on the form blocklist');
        assert.strictEqual(entry.source, 'form');
    });

    await t.test('Form POST /unsubscribe/address (subscribe) fires listSubscribe and clears the entry', { timeout: 90000 }, async () => {
        const { data, sig } = signBlob({ act: 'unsub', acc: accountId, list: listIdForm, rcpt, msg: messageId });

        // Re-read the page (now in the unsubscribed state) to get a current crumb for the subscribe form.
        const pageRes = await server.get('/unsubscribe').query({ data, sig }).expect(200);
        const crumb = extractCrumbFromHtml(pageRes.text);

        const res = await server.post('/unsubscribe/address').type('form').send({ action: 'subscribe', data, sig, crumb }).expect(200);
        assert.match(res.text, /re-subscribed|Subscription resumed/, 'the page should confirm the resubscribe');

        const webhook = await waitForCondition(
            async () => {
                const webhooks = webhooksServer.webhooks.get(accountId);
                return webhooks?.find(wh => wh.event === 'listSubscribe' && wh.data.listId === listIdForm) || null;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'listSubscribe webhook timeout' }
        );

        assert.strictEqual(webhook.data.recipient, rcpt);

        const entry = await blocklistEntry(listIdForm, rcpt);
        assert.strictEqual(entry, null, 'recipient should have been removed from the blocklist after resubscribe');
    });
});
