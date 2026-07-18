'use strict';

// End-to-end, browser-driven List-Unsubscribe + resubscribe journey:
//
//   1. bootstrap the shared instance (admin session, trial, API token)   -> admin UI
//   2. provision an Ethereal account and register it                     -> REST API
//   3. send a message carrying a List-Unsubscribe header (listId)        -> REST API
//   4. read it back, extract the signed unsubscribe URL                  -> REST API
//   5. drive the unsubscribe page + resubscribe modal in the browser     -> browser
//   6. confirm the blocklist state flips (added, then removed)           -> REST API
//
// The e2e tier has no webhook receiver, so state is verified through the blocklist REST API rather
// than the listUnsubscribe/listSubscribe events (those are covered by
// test/integration/unsubscribe-events-test.js).
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('@playwright/test');
const { createUsableTestAccount, waitFor, etherealAccountPayload } = require('./helpers/ethereal');
const { ensureAdminSession, ensureTrial, createApiToken, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');

const ACCOUNT_ID = 'e2e-unsub';

test('List-Unsubscribe: unsubscribe then resubscribe through the browser', async ({ page }) => {
    const errors = trackConsoleErrors(page);
    let token;

    await test.step('bootstrap: admin session, trial, API token', async () => {
        await ensureAdminSession(page);
        await ensureTrial(page);
        token = await createApiToken(page, 'e2e unsubscribe token');
        expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    const acct = await createUsableTestAccount();

    const api = await request.newContext({
        baseURL: BASE_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` }
    });

    // Per-run uniques (the suite shares Redis db 14 across specs). listId is a single-label hostname.
    const stamp = Date.now();
    const listId = `e2e-unsub-${stamp}`;
    const recipient = 'e2e-unsub-rcpt@example.com'; // lowercase: entries are stored lowercased
    const subject = `E2E unsubscribe ${stamp}`;
    const messageId = `<e2e-unsub-${stamp}@e2e.emailengine.app>`;

    try {
        await test.step('register the Ethereal account', async () => {
            const res = await api.post('/v1/account', {
                data: Object.assign({ account: ACCOUNT_ID, name: 'E2E Unsubscribe' }, etherealAccountPayload(acct))
            });
            expect(res.ok(), `POST /v1/account -> ${res.status()} ${await res.text()}`).toBeTruthy();
        });

        await test.step('wait for the account to connect', async () => {
            await expect
                .poll(
                    async () => {
                        const res = await api.get(`/v1/account/${ACCOUNT_ID}`);
                        if (!res.ok()) {
                            return `http-${res.status()}`;
                        }
                        return (await res.json()).state;
                    },
                    { timeout: 120000, intervals: [1000, 2000, 3000] }
                )
                .toBe('connected');
        });

        await test.step('send a message with a List-Unsubscribe header', async () => {
            // listId requires mailMerge (submit route Joi). A single-entry mailMerge to one recipient
            // still injects the per-recipient List-Unsubscribe header. baseUrl points the emitted URL
            // at the local server (e2e serviceUrl is the public trial-bypass host).
            const res = await api.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                data: {
                    from: { name: 'E2E Unsub Sender', address: acct.user },
                    subject,
                    html: '<p>List-Unsubscribe e2e test.</p>',
                    listId,
                    baseUrl: BASE_URL,
                    mailMerge: [{ to: { address: recipient }, messageId }]
                }
            });
            expect(res.ok(), `POST submit -> ${res.status()} ${await res.text()}`).toBeTruthy();
            const body = await res.json();
            expect(Array.isArray(body.mailMerge) && body.mailMerge.length, 'submit should return a mailMerge result').toBeTruthy();
        });

        let unsubUrl;
        await test.step('read the message back and extract the unsubscribe URL', async () => {
            const found = await waitFor(
                async () => {
                    const res = await api.get(`/v1/account/${ACCOUNT_ID}/messages?path=INBOX&pageSize=20`);
                    if (!res.ok()) {
                        return null;
                    }
                    const body = await res.json();
                    return (body.messages || []).find(msg => msg.subject === subject) || null;
                },
                { timeout: 120000, message: 'seed message did not appear in INBOX' }
            );

            const srcRes = await api.get(`/v1/account/${ACCOUNT_ID}/message/${found.id}/source`);
            expect(srcRes.ok(), `GET message source -> ${srcRes.status()}`).toBeTruthy();
            const raw = await srcRes.text();

            // Unfold folded headers, then match the List-Unsubscribe URL (the colon excludes
            // List-Unsubscribe-Post). The signed blob is host-independent, so rebuild it against the
            // local server regardless of the emitted host.
            const unfolded = raw.replace(/\r?\n[ \t]+/g, '');
            const m = unfolded.match(/List-Unsubscribe:\s*<([^>]+)>/i);
            expect(m, 'List-Unsubscribe header not found in the delivered message').toBeTruthy();
            const parsed = new URL(m[1]);
            unsubUrl = `${BASE_URL}${parsed.pathname}${parsed.search}`;
            expect(unsubUrl).toContain('/unsubscribe?data=');
        });

        await test.step('unsubscribe page: pre-state form', async () => {
            await page.goto(unsubUrl);
            await expect(page.locator('input#email')).toHaveValue(recipient);
            await expect(page.locator('form[action="/unsubscribe/address"] button[type="submit"]')).toBeVisible();
        });

        await test.step('click Unsubscribe', async () => {
            await page.click('form[action="/unsubscribe/address"] button[type="submit"]');
            await expect(page.getByText('Your email address was unsubscribed.')).toBeVisible({ timeout: 15000 });
            await expect(page.locator('#resubscribe-link')).toBeVisible();
        });

        await test.step('blocklist lists the recipient', async () => {
            const res = await api.get(`/v1/blocklist/${listId}`);
            expect(res.ok(), `GET /v1/blocklist/${listId} -> ${res.status()}`).toBeTruthy();
            const body = await res.json();
            expect((body.addresses || []).some(a => a.recipient === recipient)).toBe(true);
        });

        await test.step('resubscribe via the modal', async () => {
            await page.click('#resubscribe-link');
            await expect(page.locator('#resubscribeModal')).toBeVisible();
            await page.click('#resubscribeModal button[type="submit"]');
            await expect(page.getByText('Subscription resumed')).toBeVisible({ timeout: 15000 });
        });

        await test.step('blocklist no longer lists the recipient', async () => {
            // Removing the only entry empties the list, which 404s. Treat 404 or an absent entry as removed.
            const res = await api.get(`/v1/blocklist/${listId}`);
            if (res.status() === 200) {
                const body = await res.json();
                expect((body.addresses || []).some(a => a.recipient === recipient)).toBe(false);
            } else {
                expect(res.status()).toBe(404);
            }
        });
    } finally {
        await api.dispose();
    }

    expect(errors, errors.join('\n')).toHaveLength(0);
});
