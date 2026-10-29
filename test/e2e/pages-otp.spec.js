'use strict';

// The one-time passcode path end to end: a message submitted with the otp option goes out with an
// OTP-Token header, comes back from Ethereal (which loops sent mail into the sender's inbox) with
// the otp field on its details, and the message browser offers the code in its "Code requested"
// box. Ethereal's own receiving server is not one EmailEngine trusts for Authentication-Results,
// so the code arrives unauthenticated; the authenticated rendering is checked by rewriting the
// details response, since no test mailbox can produce a trusted header.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker), and registers its own account rather than relying on happy-path.spec.js.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('@playwright/test');
const { useAdminSession, createApiToken, dismissTokenReveal, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');
const { createUsableTestAccount, etherealAccountPayload } = require('./helpers/ethereal');

const ACCOUNT_ID = 'e2e-otp';
const CODE = '600686';

test.describe('one-time passcodes', () => {
    useAdminSession(test, 'otp');

    test('a submitted otp comes back on the message and is offered for copying', async ({ page }) => {
        test.setTimeout(240000);
        const errors = trackConsoleErrors(page);

        const token = await createApiToken(page, `e2e otp ${Date.now()}`);
        await dismissTokenReveal(page);
        const api = await request.newContext({ baseURL: BASE_URL, extraHTTPHeaders: { Authorization: `Bearer ${token}` } });

        try {
            const acct = await createUsableTestAccount();
            const created = await api.post('/v1/account', { data: { account: ACCOUNT_ID, name: 'E2E OTP', ...etherealAccountPayload(acct) } });
            expect(created.ok(), `POST /v1/account -> ${created.status()} ${await created.text()}`).toBeTruthy();
            await expect
                .poll(async () => (await (await api.get(`/v1/account/${ACCOUNT_ID}`)).json()).state, { timeout: 120000, intervals: [1000, 2000, 3000] })
                .toBe('connected');

            const subject = `${CODE} is your verification code ${Date.now()}`;

            await test.step('an otp the header can not carry is refused', async () => {
                const res = await api.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                    data: { to: [{ address: acct.user }], subject, text: CODE, otp: { code: CODE, origin: 'http://example.com' } }
                });
                expect(res.status()).toBe(400);
            });

            await test.step('submit with otp', async () => {
                const res = await api.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                    data: {
                        from: { name: 'Example Login', address: acct.user },
                        to: [{ address: acct.user }],
                        subject,
                        text: `Your code is ${CODE}`,
                        otp: { code: CODE, origin: 'https://login.example.com/verify' }
                    }
                });
                expect(res.ok(), `POST submit -> ${res.status()} ${await res.text()}`).toBeTruthy();
            });

            let messageId;
            await test.step('the message details carry the otp', async () => {
                await expect
                    .poll(
                        async () => {
                            const res = await api.get(`/v1/account/${ACCOUNT_ID}/messages?path=INBOX&pageSize=20`);
                            const found = res.ok() && (await res.json()).messages.find(message => message.subject === subject);
                            messageId = found && found.id;
                            return !!messageId;
                        },
                        { timeout: 120000, intervals: [2000, 3000, 5000] }
                    )
                    .toBe(true);

                const details = await (await api.get(`/v1/account/${ACCOUNT_ID}/message/${messageId}`)).json();
                expect(details.otp).toEqual({ code: CODE, origin: 'https://login.example.com', authenticated: false });
            });

            const openMessage = async () => {
                await page.goto(`/admin/accounts/${ACCOUNT_ID}/browse`, { waitUntil: 'load' });
                await page.locator('.ee-message-item').filter({ hasText: subject }).click();
                await expect(page.locator('.ee-otp')).toBeVisible();
            };

            await test.step('the message browser offers an unverified code without naming the site', async () => {
                await openMessage();
                await expect(page.locator('.ee-otp-char')).toHaveText(CODE.split(''));
                await expect(page.locator('.ee-otp-title')).toHaveText('Code requested');
                await expect(page.locator('.ee-otp-note')).toBeVisible();

                await page.locator('[data-action="copy-otp"]').click();
                await expect(page.locator('.ee-otp-status')).toHaveText('Code copied to the clipboard');
            });

            await test.step('an authenticated code names the site', async () => {
                await page.route(`**/v1/account/${ACCOUNT_ID}/message/*?*`, async route => {
                    const response = await route.fetch();
                    const body = await response.json();
                    body.otp.authenticated = true;
                    await route.fulfill({ response, json: body });
                });
                await openMessage();
                await expect(page.locator('.ee-otp-site')).toHaveText('login.example.com');
                await expect(page.locator('.ee-otp-note')).toHaveCount(0);
            });

            expect(errors, 'no console errors').toEqual([]);
        } finally {
            await api.delete(`/v1/account/${ACCOUNT_ID}`);
            await api.dispose();
        }
    });
});
