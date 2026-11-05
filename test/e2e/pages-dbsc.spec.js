'use strict';

// Device-bound admin sessions (lib/dbsc) in a real browser that binds them.
//
// Chrome only registers a device-bound session on an https origin with a trusted certificate (not
// http, not localhost, not with a certificate error), and only when it can create a key in the
// platform's key store - which the unsigned Chrome for Testing Playwright downloads cannot do on
// macOS. So this spec needs two things the normal run does not have, and skips without them:
//
//   EE_E2E_DBSC_CHROME  path to a signed Chrome binary, e.g.
//                       "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
//   EE_E2E_DBSC_URL     a public https URL that reaches the e2e instance on port 7099, e.g. a
//                       cloudflared quick tunnel: cloudflared tunnel --url http://localhost:7099
//
// Chrome is launched with a throwaway profile, never the user's own. The protocol itself (every
// status, header and refusal) is covered without a browser by test/dbsc-test.js; what only a real
// browser shows is that Chrome accepts what EmailEngine sends, binds, renews, and that a copy of
// the session cookie in another browser is refused.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect, chromium } = require('./helpers/test');
const { ensureAdminSession, trackConsoleErrors } = require('./helpers/bootstrap');

const CHROME = process.env.EE_E2E_DBSC_CHROME;
const PUBLIC_URL = (process.env.EE_E2E_DBSC_URL || '').replace(/\/+$/, '');

test.describe('Device-bound admin sessions', () => {
    test.skip(!CHROME || !PUBLIC_URL, 'needs EE_E2E_DBSC_CHROME (a signed Chrome) and EE_E2E_DBSC_URL (a public https URL for the e2e instance)');

    let context;
    let profile;

    test.beforeAll(async () => {
        profile = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2e-dbsc-profile-'));
        // chrome://flags "Device Bound Session Credentials (Standard)": Enabled. On macOS the
        // feature is still switched on by a gradual server-side rollout, which a fresh profile
        // has not received
        fs.writeFileSync(
            path.join(profile, 'Local State'),
            JSON.stringify({ browser: { enabled_labs_experiments: ['enable-standard-device-bound-session-credentials@1'] } })
        );
        context = await chromium.launchPersistentContext(profile, {
            executablePath: CHROME,
            baseURL: PUBLIC_URL,
            headless: true,
            // The mock keychain Playwright selects leaves Chrome no key store to create the key in
            ignoreDefaultArgs: ['--use-mock-keychain', '--password-store=basic']
        });
    });

    test.afterAll(async () => {
        if (context) {
            const page = await context.newPage();
            await setDbsc(page, false).catch(() => {});
            await context.close();
        }
        if (profile) {
            fs.rmSync(profile, { recursive: true, force: true });
        }
    });

    async function setDbsc(page, enabled) {
        await page.goto('/admin/config/security');
        await page.locator('#dbscEnabled').setChecked(enabled);
        await page.getByRole('button', { name: 'Save changes' }).click();
        await page.waitForLoadState();
    }

    test('Chrome binds the admin session, renews it, and a copied cookie is refused', async () => {
        const page = context.pages()[0] || (await context.newPage());
        const errors = trackConsoleErrors(page);

        await ensureAdminSession(page);
        await setDbsc(page, true);

        // Sessions bind on the next page that offers it; the Security page says when it has
        const thisBrowser = page.locator('#dbscCurrentSession');
        await expect(async () => {
            await page.goto('/admin/config/security');
            await expect(thisBrowser).toContainText('bound to this device', { timeout: 1000 });
        }).toPass({ timeout: 30000 });
        expect((await context.cookies()).map(cookie => cookie.name)).toContain('eeb');

        // Without its bound cookie, Chrome renews it through the refresh endpoint before the next
        // request goes out, so the page simply loads
        await context.clearCookies({ name: 'eeb' });
        const renewed = await page.goto('/admin');
        expect(renewed.status()).toBe(200);
        expect((await context.cookies()).map(cookie => cookie.name)).toContain('eeb');

        // The session cookie alone, in a browser that holds no key, is a stolen cookie
        const cookies = await context.cookies();
        const stolen = cookies.find(cookie => cookie.name === 'ee');
        const thief = await chromium.launch();
        try {
            const other = await thief.newContext({ baseURL: PUBLIC_URL });
            await other.addCookies([stolen]);
            const otherPage = await other.newPage();
            await otherPage.goto('/admin/accounts');
            await expect(otherPage).toHaveURL(/\/admin\/login\?next=%2Fadmin%2Faccounts/);

            // A browser of the session's own (it holds the crumb cookie the flash messages are
            // kept under) is told why it was signed out; a bare copied cookie is told nothing
            const owner = await thief.newContext({ baseURL: PUBLIC_URL });
            await owner.addCookies([stolen, cookies.find(cookie => cookie.name === 'crumb')]);
            const ownerPage = await owner.newPage();
            await ownerPage.goto('/admin/accounts');
            await expect(ownerPage).toHaveURL(/\/admin\/login/);
            await expect(ownerPage.locator('body')).toContainText('could not confirm it is the device you signed in on');
        } finally {
            await thief.close();
        }

        // The owner of the session keeps it
        expect((await page.goto('/admin')).status()).toBe(200);
        await expect(page).toHaveURL(/\/admin$/);
        expect(errors).toHaveLength(0);
    });
});
