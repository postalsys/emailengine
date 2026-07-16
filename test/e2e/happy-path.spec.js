'use strict';

// Happy-path end-to-end journey through a fresh EmailEngine instance, driven by a real browser
// for the admin-UI bootstrap and by the REST API for the email operations:
//
//   1. enable authentication (set the admin password)        -> admin UI
//   2. activate a 14-day trial (hits postalsys.com)          -> admin UI
//   3. create a REST API access token                        -> admin UI
//   4. register an Ethereal account (nodemailer test account)-> REST API
//   5. send a message through the submit endpoint            -> REST API
//   6. read it back from INBOX (Ethereal loops sent mail)    -> REST API
//
// The Playwright webServer (playwright.config.js) flushes the isolated Redis db 14 and boots
// EmailEngine with NODE_ENV=e2e before this runs.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('@playwright/test');
const { createUsableTestAccount, waitFor } = require('./helpers/ethereal');
const { ADMIN_PASSWORD } = require('./helpers/bootstrap');

const PORT = 7099;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ACCOUNT_ID = 'e2e-ethereal';

test('fresh instance: bootstrap, register Ethereal account, send and read back', async ({ page }) => {
    let token;

    await test.step('enable authentication (set admin password)', async () => {
        // On a fresh instance authentication is not yet enforced, so the password form is
        // reachable unauthenticated. password0 (current password) only renders once a password
        // already exists, so a fresh instance just needs the new password twice.
        await page.goto('/admin/account/password');
        await page.fill('#password', ADMIN_PASSWORD);
        await page.fill('#password2', ADMIN_PASSWORD);
        await page.click('button[type="submit"]');
        await page.waitForLoadState();

        // Setting the first password enables auth and auto-logs-in. The dashboard must no longer
        // show the "Authentication not enabled" banner, and must render (i.e. we are logged in).
        await page.goto('/admin');
        await expect(page.getByText('Authentication not enabled')).toHaveCount(0);
        await expect(page.locator('#start-trial-btn')).toBeVisible({ timeout: 15000 });
    });

    await test.step('activate a 14-day trial', async () => {
        // The "Start a 14-day trial" button opens a modal whose JS POSTs to
        // /admin/config/license/trial (which provisions a trial from postalsys.com) and then
        // reloads the page. Once the trial is active the button is no longer rendered.
        const trialBtn = page.locator('#start-trial-btn');
        await trialBtn.click();
        await expect(trialBtn).toHaveCount(0, { timeout: 60000 });
    });

    await test.step('create a REST API access token', async () => {
        await page.goto('/admin/tokens/new');
        await page.fill('#description', 'e2e happy-path token');
        await page.check('#scopesAll'); // data-scope="*" -> full access
        await page.click('#token-form button[type="submit"]');

        // The token is revealed once in the modal input #showTokenValue.
        const tokenInput = page.locator('#showTokenValue');
        await expect(tokenInput).not.toHaveValue('', { timeout: 20000 });
        token = await tokenInput.inputValue();
        expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    // From here on, talk to the REST API with the freshly minted bearer token.
    const api = await request.newContext({
        baseURL: BASE_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` }
    });

    try {
        await test.step('trial is active (REST API)', async () => {
            const res = await api.get('/v1/license');
            expect(res.ok(), `GET /v1/license -> ${res.status()}`).toBeTruthy();
            const body = await res.json();
            expect(body.active).toBe(true);
            expect(body.details && body.details.trial).toBe(true);
        });

        const acct = await createUsableTestAccount();

        await test.step('register the Ethereal account', async () => {
            const res = await api.post('/v1/account', {
                data: {
                    account: ACCOUNT_ID,
                    name: 'E2E Ethereal',
                    email: acct.user,
                    imap: {
                        host: acct.imap.host,
                        port: acct.imap.port,
                        secure: acct.imap.secure,
                        auth: { user: acct.user, pass: acct.pass }
                    },
                    smtp: {
                        host: acct.smtp.host,
                        port: acct.smtp.port,
                        secure: acct.smtp.secure,
                        auth: { user: acct.user, pass: acct.pass }
                    }
                }
            });
            expect(res.ok(), `POST /v1/account -> ${res.status()} ${await res.text()}`).toBeTruthy();
            const body = await res.json();
            expect(body.account).toBe(ACCOUNT_ID);
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

        const stamp = Date.now();
        const subject = `E2E happy-path ${stamp}`;
        const messageId = `<e2e-${stamp}@e2e.emailengine.app>`;

        await test.step('send a message via the submit endpoint', async () => {
            const res = await api.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                data: {
                    from: { name: 'E2E Sender', address: acct.user },
                    to: [{ address: 'recipient@example.com' }],
                    subject,
                    text: 'Hello from the EmailEngine e2e happy-path test.',
                    html: '<p>Hello from the EmailEngine e2e happy-path test.</p>',
                    messageId
                }
            });
            expect(res.ok(), `POST submit -> ${res.status()} ${await res.text()}`).toBeTruthy();
            const body = await res.json();
            expect(body.queueId).toBeTruthy();
        });

        await test.step('list mailboxes (INBOX present)', async () => {
            const res = await api.get(`/v1/account/${ACCOUNT_ID}/mailboxes`);
            expect(res.ok(), `GET mailboxes -> ${res.status()}`).toBeTruthy();
            const body = await res.json();
            expect(body.mailboxes.some(mbox => mbox.path === 'INBOX')).toBe(true);
        });

        let found;
        await test.step('find the message in INBOX', async () => {
            // Ethereal loops a sent message back into the account's own INBOX.
            found = await waitFor(
                async () => {
                    const res = await api.get(`/v1/account/${ACCOUNT_ID}/messages?path=INBOX&pageSize=20`);
                    if (!res.ok()) {
                        return null;
                    }
                    const body = await res.json();
                    return (body.messages || []).find(msg => msg.subject === subject) || null;
                },
                { timeout: 120000, message: 'sent message did not appear in INBOX' }
            );
            expect(found).toBeTruthy();
        });

        await test.step('get message details', async () => {
            const res = await api.get(`/v1/account/${ACCOUNT_ID}/message/${found.id}?textType=*`);
            expect(res.ok(), `GET message -> ${res.status()}`).toBeTruthy();
            const body = await res.json();
            expect(body.subject).toBe(subject);
            expect(body.messageId).toBe(messageId);
        });
    } finally {
        await api.dispose();
    }
});
