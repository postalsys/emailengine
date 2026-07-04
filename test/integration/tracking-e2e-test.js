'use strict';

// End-to-end integration test for open + click tracking. Complements tracking-signature-test.js
// (which only checks signature accept/reject on hand-crafted blobs) by exercising the full
// pipeline: send an HTML message with tracking enabled through a real Ethereal account, let it
// loop back into INBOX, read the DELIVERED HTML, extract the injected open-pixel + rewritten click
// link, hit both routes, and assert the HTTP behaviour (200 gif / 302 redirect) plus the emitted
// trackOpen / trackClick webhook events.
//
// Runs against the shared live test server (config/test.toml): serviceUrl is http://127.0.0.1:7077
// so the injected tracker URLs point at this server, and global webhooks deliver to the shared
// webhooks-server on 7078.

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const he = require('he');
const webhooksServer = require('./webhooks-server');
const { createUsableTestAccount, waitForCondition, etherealAccountPayload, ACCESS_TOKEN: accessToken } = require('./helpers');

const baseUrl = `http://127.0.0.1:${config.api.port}`;

// Authenticated client for the REST API; unauthenticated client for the public tracking routes.
const server = supertest.agent(baseUrl).auth(accessToken, { type: 'bearer' });
const trackClient = supertest(baseUrl);

const accountId = 'track-e2e-account';
const LANDING_URL = 'https://example.com/landing';
// A realistic browser UA. The automated-request gate is IP-based (localhost is never flagged), so
// this is not needed to make the events fire - it only lets us assert data.userAgent is echoed.
const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

test('Open and click tracking - full send-to-event pipeline', async t => {
    let testAccount;
    const messageId = `<track-e2e-${Date.now()}@example.com>`;
    const subject = `Tracking e2e ${Date.now()}`;
    let openUrl;
    let clickUrl;

    t.before(async () => {
        testAccount = await createUsableTestAccount();
        await webhooksServer.init();
    });

    t.after(async () => {
        await webhooksServer.quit();
    });

    await t.test('Register the Ethereal account', { timeout: 30000 }, async () => {
        const response = await server
            .post(`/v1/account`)
            .send(Object.assign({ account: accountId, name: 'Tracking E2E' }, etherealAccountPayload(testAccount)))
            .expect(200);

        assert.strictEqual(response.body.state, 'new');
    });

    await t.test('Wait until the account is connected', { timeout: 120000 }, async () => {
        await waitForCondition(
            async () => {
                // Check the status manually and retry on a transient non-200 instead of .expect(200),
                // which would throw out of the poll loop and fail the test on a momentary hiccup.
                const response = await server.get(`/v1/account/${accountId}`);
                if (response.status !== 200) {
                    return false;
                }
                switch (response.body.state) {
                    case 'authenticationError':
                    case 'connectError':
                        throw new Error('Invalid account state ' + response.body.state);
                    case 'connected':
                        return true;
                }
                return false;
            },
            { timeout: testConfig.CONNECTION_TIMEOUT, message: 'Account connection timeout' }
        );
    });

    await t.test('Submit an HTML message with tracking enabled', { timeout: 30000 }, async () => {
        // Enable tracking per-message (not via global /v1/settings) so this file does not leak
        // tracking state into the other serial integration files.
        const response = await server
            .post(`/v1/account/${accountId}/submit`)
            .send({
                to: [{ address: testAccount.user }],
                subject,
                text: 'Hello tracking',
                html: `<html><body><p>Hello tracking</p><a href="${LANDING_URL}">Click here</a></body></html>`,
                trackOpens: true,
                trackClicks: true,
                messageId
            })
            .expect(200);

        assert.ok(response.body.messageId, 'Should have messageId in response');
        assert.ok(response.body.queueId, 'Should have queueId in response');
    });

    await t.test('Read the delivered message and extract the tracker URLs', { timeout: 180000 }, async () => {
        // Ethereal loops the sent message back into the account's own INBOX.
        const found = await waitForCondition(
            async () => {
                const res = await server.get(`/v1/account/${accountId}/messages?path=INBOX&pageSize=20`);
                if (res.status !== 200) {
                    return null;
                }
                return (res.body.messages || []).find(msg => msg.subject === subject) || null;
            },
            { timeout: 120000, message: 'tracked message did not appear in INBOX' }
        );

        // textType=* returns the unsanitized delivered HTML verbatim (webSafeHtml would sanitize it).
        const messageResponse = await server.get(`/v1/account/${accountId}/message/${found.id}?textType=*`).expect(200);
        const html = messageResponse.body.text && messageResponse.body.text.html;
        assert.ok(html, 'delivered message should carry an HTML body');

        const openMatch = html.match(/src="([^"]*\/open\.gif[^"]*)"/i);
        const clickMatch = html.match(/href="([^"]*\/redirect\?[^"]*)"/i);
        assert.ok(openMatch, 'open-tracking pixel was not injected into the delivered HTML');
        assert.ok(clickMatch, 'click tracker did not rewrite the link in the delivered HTML');

        // The click href is HTML-entity-encoded in the delivered markup (& -> &amp;), so decode
        // before parsing or `sig` would land in a param named `amp;sig` and /redirect would 403.
        // The open-pixel src is raw, so he.decode is a harmless no-op there.
        openUrl = new URL(he.decode(openMatch[1]));
        clickUrl = new URL(he.decode(clickMatch[1]));

        assert.strictEqual(openUrl.origin, baseUrl, 'open pixel should point at the local server (serviceUrl)');
        assert.strictEqual(openUrl.pathname, '/open.gif');
        assert.ok(openUrl.searchParams.get('data') && openUrl.searchParams.get('sig'), 'open pixel needs data + sig');

        assert.strictEqual(clickUrl.origin, baseUrl, 'click tracker should point at the local server (serviceUrl)');
        assert.strictEqual(clickUrl.pathname, '/redirect');
        assert.ok(clickUrl.searchParams.get('data') && clickUrl.searchParams.get('sig'), 'click tracker needs data + sig');
    });

    await t.test('Hitting the open pixel returns a GIF and fires trackOpen', { timeout: 90000 }, async () => {
        const res = await trackClient
            .get(openUrl.pathname + openUrl.search)
            .set('User-Agent', BROWSER_UA)
            .redirects(0);
        assert.strictEqual(res.status, 200);
        assert.match(res.headers['content-type'] || '', /image\/gif/);

        const webhook = await waitForCondition(
            async () => {
                const webhooks = webhooksServer.webhooks.get(accountId);
                return webhooks?.find(wh => wh.event === 'trackOpen' && wh.data.messageId === messageId) || null;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'trackOpen webhook timeout' }
        );

        assert.ok(webhook.data.remoteAddress, 'trackOpen should include remoteAddress');
        assert.strictEqual(webhook.data.userAgent, BROWSER_UA);
    });

    await t.test('Hitting the click link redirects and fires trackClick', { timeout: 90000 }, async () => {
        const res = await trackClient
            .get(clickUrl.pathname + clickUrl.search)
            .set('User-Agent', BROWSER_UA)
            .redirects(0);
        assert.strictEqual(res.status, 302);
        assert.strictEqual(res.headers.location, LANDING_URL);

        const webhook = await waitForCondition(
            async () => {
                const webhooks = webhooksServer.webhooks.get(accountId);
                return webhooks?.find(wh => wh.event === 'trackClick' && wh.data.messageId === messageId) || null;
            },
            { timeout: testConfig.WEBHOOK_TIMEOUT, message: 'trackClick webhook timeout' }
        );

        assert.strictEqual(webhook.data.url, LANDING_URL);
        assert.strictEqual(webhook.data.userAgent, BROWSER_UA);
    });

    await t.test('Cleanup - delete the account', { timeout: 15000 }, async () => {
        await server.delete(`/v1/account/${accountId}`).expect(200);
    });
});
