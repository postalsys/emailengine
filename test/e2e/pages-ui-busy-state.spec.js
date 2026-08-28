/* global document */

'use strict';

// Busy state on the buttons behind slow actions, and the double-submit guard that comes with it.
//
// These actions take as long as a mail server, an OAuth provider or an autoconfig lookup takes to
// answer. Nothing on the page moves while that happens, so without feedback the button gets pressed
// again - and the second POST either duplicates the work or loses a race against a single-use nonce
// and reports an error for something that actually succeeded. The guards live in static/js/ui.js
// (admin) and static/js/public.js (the framework-free public pages).
//
// Covered here: a plain admin settings form, the MCP OAuth consent page (whose Approve button
// carries the decision as its own name/value - the case a naive "disable on submit" silently
// breaks), the hosted authentication form on the public side, and one async action button that
// posts with fetch() instead of navigating.
//
// Shares the Playwright webServer and Redis db 14 with the other specs. Sorts after the other
// pages-* specs on purpose: the consent test mints an mcp-scoped token on the shared instance.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('@playwright/test');
const { ensureAdminSession, ensureTrial, createApiToken, trackConsoleErrors, hostedAuthFormUrl, BASE_URL } = require('./helpers/bootstrap');

// Submits `selector`'s form the way pressing Enter in one of its fields does. The latch has to
// cancel that itself: disabling the buttons does not close this path.
const requestSubmit = selector => document.querySelector(selector).requestSubmit();

// How long to give a submit that must NOT happen. Asserting a negative needs a wait of some kind,
// and the cheaper-looking alternatives do not survive contact: a fetch() issued from the page to
// order the check behind a round trip is cancelled by the pending navigation ("Failed to fetch"),
// and a reload cannot distinguish "never posted" from "posted and was dropped on unload".
const NO_SUBMIT_SETTLE_MS = 500;

/**
 * Answers every POST to `url` with 204 No Content, which a browser treats as "nothing to navigate
 * to" and leaves the current document alone. The busy state a form POST normally shows for a few
 * milliseconds therefore stays on screen for as long as the assertions need, with no sleeping and
 * no race against a real navigation. The recorded request bodies are what prove a repeat submit
 * never left the browser, and what the submitter's own name/value has to survive into.
 */
async function stubPosts(page, url) {
    const posts = [];

    await page.route(url, async route => {
        if (route.request().method() !== 'POST') {
            return route.continue();
        }
        posts.push(route.request().postData() || '');
        await route.fulfill({ status: 204 });
    });

    return posts;
}

test('admin form: the submit button goes busy and a repeat submit is dropped', async ({ page }) => {
    const errors = trackConsoleErrors(page);
    await ensureAdminSession(page);

    const posts = await stubPosts(page, '**/admin/config/logging');
    await page.goto('/admin/config/logging');

    const form = 'form[action="/admin/config/logging"]';
    const submitBtn = page.locator(`${form} button[type="submit"]`);

    await submitBtn.click();

    // Pressed once: the button is out of action and its icon says why.
    await expect(submitBtn).toBeDisabled();
    await expect(submitBtn.locator('span').first()).toHaveClass(/animate-spin/);
    await expect.poll(() => posts.length).toBe(1);

    await page.evaluate(requestSubmit, form);
    await page.waitForTimeout(NO_SUBMIT_SETTLE_MS);
    expect(posts.length).toBe(1);

    // The same call on a freshly loaded document does post, which is what makes the assertion above
    // mean "the latch dropped it" rather than "requestSubmit does nothing here".
    await page.reload();
    await page.evaluate(requestSubmit, form);
    await expect.poll(() => posts.length).toBe(2);

    expect(errors, errors.join('\n')).toHaveLength(0);
});

test('MCP consent: Approve goes busy and still posts its decision', async ({ page }) => {
    const errors = trackConsoleErrors(page);
    await ensureAdminSession(page);

    const REDIRECT_URI = `${BASE_URL}/admin`;

    await test.step('enable the MCP endpoint and its OAuth sign-in', async () => {
        await page.goto('/admin/config/mcp');
        await page.locator('#settingsMcpEnabled').setChecked(true);
        await page.locator('#settingsMcpOAuthEnabled').setChecked(true);
        await page.click('form[action="/admin/config/mcp"] button[type="submit"]');
        await expect(page.locator('#settingsMcpOAuthEnabled')).toBeChecked({ timeout: 15000 });
    });

    const api = await request.newContext({ baseURL: BASE_URL });

    try {
        let clientId;
        await test.step('register an MCP client (dynamic client registration)', async () => {
            const res = await api.post('/mcp/oauth/register', {
                data: { client_name: 'E2E Busy State', redirect_uris: [REDIRECT_URI] }
            });
            expect(res.status(), `POST /mcp/oauth/register -> ${res.status()} ${await res.text()}`).toBe(201);
            clientId = (await res.json()).client_id;
        });

        const authorizeUrl = `/admin/mcp/authorize?${new URLSearchParams({
            client_id: clientId,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            state: 'e2e-busy-state',
            code_challenge: 'a'.repeat(43),
            code_challenge_method: 'S256'
        }).toString()}`;

        const approveBtn = page.locator('button[name="decision"][value="approve"]');
        const denyBtn = page.locator('button[name="decision"][value="deny"]');

        await test.step('Approve goes busy and posts decision=approve', async () => {
            const posts = await stubPosts(page, '**/admin/mcp/authorize');
            await page.goto(authorizeUrl);
            await expect(approveBtn).toBeVisible();

            await approveBtn.click();

            await expect(approveBtn).toBeDisabled();
            await expect(approveBtn.locator('span').first()).toHaveClass(/animate-spin/);
            // The other decision goes out of reach too - one press, one answer.
            await expect(denyBtn).toBeDisabled();

            // The decision rides on the button's own name/value, and the form data set skips
            // disabled controls - so a guard that just disabled the submitter would post no
            // decision at all. The route requires the field and reads anything but "approve" as a
            // denial, which is what makes this the failure to guard against.
            await expect.poll(() => posts.length).toBe(1);
            expect(new URLSearchParams(posts[0]).get('decision')).toBe('approve');

            await page.unroute('**/admin/mcp/authorize');
        });

        await test.step('approving for real returns an authorization code to the client', async () => {
            await page.goto(authorizeUrl);
            await approveBtn.click();
            await page.waitForURL(/[?&]code=/, { timeout: 15000 });
            expect(new URL(page.url()).searchParams.get('state')).toBe('e2e-busy-state');
        });
    } finally {
        await api.dispose();

        // Leave the instance as the other specs expect to find it (both settings default to off).
        await page.goto('/admin/config/mcp');
        await page.locator('#settingsMcpEnabled').setChecked(false);
        await page.locator('#settingsMcpOAuthEnabled').setChecked(false);
        await page.click('form[action="/admin/config/mcp"] button[type="submit"]');
        await expect(page.locator('#settingsMcpEnabled')).not.toBeChecked({ timeout: 15000 });
    }

    expect(errors, errors.join('\n')).toHaveLength(0);
});

test('hosted auth form: Continue goes busy while the server looks the mail server up', async ({ page }) => {
    const errors = trackConsoleErrors(page);
    let token;

    await test.step('bootstrap: admin session, trial, API token', async () => {
        await ensureAdminSession(page);
        await ensureTrial(page);
        token = await createApiToken(page, 'e2e busy-state token');
        expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    const api = await request.newContext({
        baseURL: BASE_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` }
    });

    try {
        const formUrl = await hostedAuthFormUrl(api, {
            account: 'e2e-busy-state',
            name: 'E2E Busy State',
            email: 'e2e-busy-state@example.com',
            redirectUrl: `${BASE_URL}/admin`
        });

        // The step behind this button runs autodiscovery against DNS and the provider's autoconfig
        // endpoints, so it is the longest wait in the hosted form and the likeliest to be clicked
        // twice. Stubbed out here - what is under test is the button, not the lookup (the real
        // journey through this form is test/e2e/hosted-form.spec.js).
        const posts = await stubPosts(page, '**/accounts/new/imap');
        await page.goto(formUrl);

        // A fresh instance has no OAuth2 apps and lands straight on the email/password step; pick
        // the IMAP provider if another spec left an app behind and the chooser rendered instead.
        const imapProvider = page.locator('form[action="/accounts/new"]:has(input[name="type"][value="imap"]) button[type="submit"]');
        if (await imapProvider.count()) {
            await imapProvider.click();
        }

        await page.fill('#name', 'E2E Busy State');
        await page.fill('#email', 'e2e-busy-state@example.com');
        await page.fill('#password', 'e2e-not-a-real-password');

        const form = 'form[action="/accounts/new/imap"]';
        const continueBtn = page.locator(`${form} button[type="submit"]`);

        await continueBtn.click();

        await expect(continueBtn).toBeDisabled();
        await expect(continueBtn.locator('.ee-icon')).toHaveClass(/ee-spin/);
        await expect.poll(() => posts.length).toBe(1);

        await page.evaluate(requestSubmit, form);
        await page.waitForTimeout(NO_SUBMIT_SETTLE_MS);
        expect(posts.length).toBe(1);
    } finally {
        await api.dispose();
    }

    expect(errors, errors.join('\n')).toHaveLength(0);
});

test('gateway connection test: the action button stays busy for the round trip', async ({ page }) => {
    const errors = trackConsoleErrors(page);
    await ensureAdminSession(page);

    await page.goto('/admin/gateways/new');

    let release;
    const held = new Promise(resolve => {
        release = resolve;
    });
    let calls = 0;

    // Fulfilled rather than forwarded, and held open: what is under test is the button's state
    // while an SMTP connection is being attempted, not the connection. Holding a fetch() is safe
    // where holding a navigation is not - nothing in the page is waiting on it.
    await page.route('**/admin/gateways/test', async route => {
        calls++;
        await held;
        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ success: true, message: 'Connection successful' })
        });
    });

    await page.fill('#host', 'smtp.example.com');
    await page.fill('#port', '587');

    const testBtn = page.locator('#test-verify-btn');
    await testBtn.click();

    await expect(testBtn).toBeDisabled();
    await expect(testBtn.locator('span').first()).toHaveClass(/animate-spin/);
    expect(calls).toBe(1);

    release();

    await expect(testBtn).toBeEnabled();
    await expect(page.locator('#toastContainer')).toContainText('Connection successful');
    // The idle icon comes back rather than the button being left spinning.
    await expect(testBtn.locator('span').first()).not.toHaveClass(/animate-spin/);

    expect(errors, errors.join('\n')).toHaveLength(0);
});
