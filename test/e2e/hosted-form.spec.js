'use strict';

// End-to-end: add an IMAP email account through the HOSTED AUTHENTICATION FORM - the signed
// /accounts/new flow an operator hands to a user - exercising the IMAP path (not OAuth2):
//
//   1. bootstrap the shared instance (admin session, trial, API token)  -> admin UI
//   2. provision an Ethereal account (nodemailer test account)          -> nodemailer
//   3. generate a signed hosted-auth URL                                -> REST API
//   4. drive the hosted form: choose IMAP, enter email/password, then   -> browser
//      the IMAP + SMTP server details, and submit
//   5. confirm the account was created and reaches "connected"          -> REST API
//
// This shares the Playwright webServer and Redis db 14 with the other specs, so the bootstrap is
// idempotent (helpers/bootstrap.js) and the account id is unique to this spec.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('@playwright/test');
const { createUsableTestAccount } = require('./helpers/ethereal');
const { ensureAdminSession, ensureTrial, createApiToken } = require('./helpers/bootstrap');

const PORT = 7099;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ADMIN_PASSWORD = 'E2e-Test-Password-123!';
const ACCOUNT_ID = 'e2e-hosted-imap';

test('hosted auth form: add an IMAP account (Ethereal) and reach connected', async ({ page }) => {
    let token;

    await test.step('bootstrap: admin session, trial, API token', async () => {
        await ensureAdminSession(page, ADMIN_PASSWORD);
        await ensureTrial(page);
        token = await createApiToken(page, 'e2e hosted-form token');
        expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    const acct = await createUsableTestAccount();

    const api = await request.newContext({
        baseURL: BASE_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` }
    });

    try {
        let formUrl;
        await test.step('generate the hosted authentication URL', async () => {
            const res = await api.post('/v1/authentication/form', {
                data: {
                    account: ACCOUNT_ID,
                    name: 'E2E Hosted IMAP',
                    email: acct.user,
                    redirectUrl: `${BASE_URL}/admin`
                }
            });
            expect(res.ok(), `POST /v1/authentication/form -> ${res.status()} ${await res.text()}`).toBeTruthy();
            const body = await res.json();
            // The URL is generated against the public serviceUrl (config/e2e.toml), so reuse its
            // signed query string (data/sig/type) against the local test server - the signed blob
            // is host-independent.
            formUrl = `${BASE_URL}/accounts/new${new URL(body.url).search}`;
        });

        await test.step('hosted form: choose IMAP and enter email + password', async () => {
            await page.goto(formUrl);
            // A fresh instance has no OAuth2 apps, so the URL carries type=imap and lands directly
            // on the email/password form. If the provider-selection screen shows (e.g. another spec
            // added an OAuth2 app to the shared instance), pick the Standard IMAP provider. Anchor on
            // the form's action + hidden type field rather than the localized button text.
            const imapBtn = page.locator('form[action="/accounts/new"]:has(input[name="type"][value="imap"]) button[type="submit"]');
            if (await imapBtn.count()) {
                await imapBtn.click();
            }
            await page.fill('#name', 'E2E Hosted IMAP');
            await page.fill('#email', acct.user);
            await page.fill('#password', acct.pass);
            await page.click('form[action="/accounts/new/imap"] button[type="submit"]');
        });

        await test.step('hosted form: enter IMAP + SMTP server details and submit', async () => {
            await expect(page.locator('#imap_host')).toBeVisible({ timeout: 30000 });

            // Autodetect does not know ethereal.email, so set every field explicitly.
            await page.fill('#imap_auth_user', acct.user);
            await page.fill('#imap_auth_pass', acct.pass);
            await page.fill('#imap_host', acct.imap.host);
            await page.fill('#imap_port', String(acct.imap.port));
            await page.locator('#imap_secure').setChecked(!!acct.imap.secure);

            await page.fill('#smtp_auth_user', acct.user);
            await page.fill('#smtp_auth_pass', acct.pass);
            await page.fill('#smtp_host', acct.smtp.host);
            await page.fill('#smtp_port', String(acct.smtp.port));
            await page.locator('#smtp_secure').setChecked(!!acct.smtp.secure);

            // Submit via "Skip verification" (in the split-button dropdown): a deterministic submit
            // with no live connection test. Real connectivity is proven by the connected poll below.
            await page.click('#submit-settings-btn-down');
            await page.click('#submit-wo-testing');

            // The server creates the account and renders redirect.hbs (a link only). Its continue
            // link points at redirectUrl?account=<id>&state=... - proof the account was created.
            await expect(page.locator(`a[href*="account=${ACCOUNT_ID}"]`)).toBeVisible({ timeout: 30000 });
        });

        await test.step('account exists and reaches connected', async () => {
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
    } finally {
        await api.dispose();
    }
});
