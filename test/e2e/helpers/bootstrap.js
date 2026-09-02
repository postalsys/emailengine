'use strict';

/* global Event, document */

// Idempotent admin-UI bootstrap helpers for the e2e suite. Every spec shares one booted
// EmailEngine instance and the isolated Redis db 14 (see playwright.config.js), so these must
// tolerate an instance another spec has already bootstrapped: set the first admin password on a
// fresh instance, otherwise log in; activate a trial only when the instance is not yet licensed.

const { expect } = require('@playwright/test');
const Redis = require('ioredis');

// Shared admin password for the whole e2e suite - every spec authenticates against the same
// booted instance, so there must be exactly one source for this value.
const ADMIN_PASSWORD = 'E2e-Test-Password-123!';

// The webServer origin - single source for playwright.config.js and for specs that
// need an absolute URL (API request contexts, redirect rewrites).
const PORT = 7099;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// The isolated database config/e2e.toml points the instance at. Restated here rather than read
// through wild-config, which resolves the database from NODE_ENV - that is set for the webServer
// process, not for this one, so reading the config here would target the development database.
const REDIS_URL = 'redis://127.0.0.1:6379/14';

// Per-test console error collection: browser console.error output, uncaught page errors and
// Content-Security-Policy violations. Every spec should end with expect(errors).toHaveLength(0)
// so silent JS breakage (a broken selector, a missing global) fails the test even when the DOM
// assertions still pass.
//
// Chromium already logs an enforced CSP violation as a console error, but a report-only policy
// (EENGINE_CSP_MODE=report-only) only fires the document event, so the page reports those
// itself. The init script runs in every document the page navigates to, including the popup a
// spec may open through the same context.
function trackConsoleErrors(page) {
    const errors = [];
    page.on('console', msg => {
        if (msg.type() === 'error') {
            errors.push(msg.text());
        }
    });
    page.on('pageerror', err => errors.push(`pageerror: ${err.message}`));
    page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', e => {
            console.error(
                `csp violation: ${e.violatedDirective} blocked ${e.blockedURI || 'inline'} (${e.disposition}) at ${e.sourceFile || document.location.href}:${e.lineNumber}`
            );
        });
    });
    return errors;
}

// Log in through the admin sign-in form. The set-password flow stores an empty username, so the
// server's username check is bypassed and any non-empty username works.
async function loginAsAdmin(page, password) {
    await page.fill('#loginUsername', 'admin');
    await page.fill('#loginPassword', password);
    await page.click('form[action="/admin/login"] button[type="submit"]');
    await page.waitForURL(url => !url.pathname.startsWith('/admin/login'), { timeout: 15000 });
}

// Guarantee the browser context holds an authenticated admin session on return.
async function ensureAdminSession(page, password = ADMIN_PASSWORD) {
    await page.goto('/admin');
    if (page.url().includes('/admin/login')) {
        // Auth already enabled by an earlier spec - just log in.
        await loginAsAdmin(page, password);
        return;
    }

    // Fresh instance: setting the first password enables auth and auto-logs-in.
    await page.goto('/admin/account/password');
    await page.fill('#password', password);
    await page.fill('#password2', password);
    await page.click('button[type="submit"]');
    await page.waitForLoadState();

    // Confirm we actually hold a session; log in explicitly if the auto-login did not take.
    await page.goto('/admin');
    if (page.url().includes('/admin/login')) {
        await loginAsAdmin(page, password);
    }
}

// Activate a 14-day trial if the instance is not already licensed. The "Start a 14-day trial"
// button is only rendered while unlicensed, so its absence means we are done.
async function ensureTrial(page) {
    await page.goto('/admin');
    const trialBtn = page.locator('#start-trial-btn');
    if (await trialBtn.count()) {
        await trialBtn.click();
        await expect(trialBtn).toHaveCount(0, { timeout: 60000 });
    }
}

// Create a full-access REST API token via the admin UI and return the 64-hex secret.
async function createApiToken(page, description = 'e2e token') {
    await page.goto('/admin/tokens/new');
    await page.fill('#description', description);
    await page.check('#scopesAll'); // data-scope="*" -> full access
    await page.click('#token-form button[type="submit"]');

    // The token is revealed once in the modal input #showTokenValue.
    const tokenInput = page.locator('#showTokenValue');
    await expect(tokenInput).not.toHaveValue('', { timeout: 20000 });
    return tokenInput.inputValue();
}

/**
 * Dismisses the one-time token reveal modal createApiToken leaves open.
 *
 * Two waits, and both are load-bearing. The opening transition has to settle first, because a click
 * landing mid-animation is swallowed and the modal never emits its close event - the Done button
 * then appears to do nothing and whatever waits for the listing waits forever. And the close handler
 * navigates by location.assign, so the caller has to wait that out rather than issue a navigation of
 * its own into it, which aborts with ERR_ABORTED.
 *
 * The URL pattern is anchored on what follows the path on purpose: an unanchored /\/admin\/tokens/
 * also matches the /admin/tokens/new the page is still on, so the wait returns against the CURRENT
 * url and gives none of the protection above.
 *
 * Lives here rather than in a spec because it is the counterpart of createApiToken, and a spec that
 * re-derived it got both waits wrong - one failing only on a slower machine, the other only in CI.
 */
async function dismissTokenReveal(page) {
    await expect(page.locator('#showToken')).toHaveCSS('opacity', '1');
    await page.locator('#showToken button', { hasText: 'Done' }).click();
    await page.waitForURL(/\/admin\/tokens(\?|$)/);
}

/**
 * Puts an account id into an account picker without going through the search box.
 *
 * The picker (views/partials/ui/account-picker.hbs) writes the hidden input and fires `input` on
 * it, and that event is the whole contract anything else on the page follows. Tests about what
 * FOLLOWS the field use this, so they need no account fixture; the picker's own behaviour is
 * covered by driving the search box in test/e2e/pages-tokens.spec.js.
 *
 * @param {Object} page - Playwright page
 * @param {String} selector - selector for the picker's hidden input
 * @param {String} account - account id to set, or '' to clear
 */
const setPickedAccount = (page, selector, account) =>
    page.locator(selector).evaluate((elm, value) => {
        elm.value = value;
        elm.dispatchEvent(new Event('input', { bubbles: true }));
    }, account);

/**
 * Generates a signed hosted authentication form URL and points it at the local test server.
 *
 * The URL the API returns is built against the public serviceUrl (config/e2e.toml names a host
 * that is not this process), so only its signed query string is reusable - the blob is
 * host-independent. Lives here because two specs need the same rewrite, and a spec that
 * re-derived it would be one signing change away from testing nothing.
 *
 * @param {Object} api - Playwright APIRequestContext carrying an API token
 * @param {Object} payload - POST /v1/authentication/form body (account, name, email, redirectUrl)
 * @returns {Promise<String>} absolute URL of the form's first step on the test server
 */
async function hostedAuthFormUrl(api, payload) {
    const res = await api.post('/v1/authentication/form', { data: payload });
    if (!res.ok()) {
        throw new Error(`POST /v1/authentication/form -> ${res.status()} ${await res.text()}`);
    }
    return `${BASE_URL}/accounts/new${new URL((await res.json()).url).search}`;
}

/**
 * Write passkey credentials straight into the instance's Redis, and remove them again.
 *
 * Registering one for real is not reachable from a test: it needs an authenticator the browser
 * does not have, and config/e2e.toml's serviceUrl names a different host than the one under test,
 * so WebAuthn would reject the rpId regardless. The security page's passkey list is only
 * meaningfully covered with rows in it, so the rows are seeded instead.
 *
 * Mirrors the hash lib/passkeys.js writes (unprefixed keys - EENGINE_REDIS_PREFIX is unset for
 * e2e). `user` is what the security page resolves the session down to: the set-password flow
 * stores an empty username, which both the page and the delete route fall back to "admin" for.
 *
 * @param {Array} credentials - {id, name, transports, createdAt?, lastUsedAt?} entries
 * @param {String} [user] - owning username
 */
async function seedPasskeys(credentials, user = 'admin') {
    const redis = new Redis(REDIS_URL);
    try {
        for (const credential of credentials) {
            const fields = {
                id: credential.id,
                publicKey: 'e2e-seeded-public-key',
                counter: '0',
                transports: JSON.stringify(credential.transports || []),
                name: credential.name,
                user,
                createdAt: credential.createdAt || new Date().toISOString()
            };
            if (credential.lastUsedAt) {
                fields.lastUsedAt = credential.lastUsedAt;
            }
            await redis.hset(`webauthn:cred:${credential.id}`, fields);
            await redis.sadd(`webauthn:creds:${user}`, credential.id);
            await redis.sadd('webauthn:all', credential.id);
        }
    } finally {
        await redis.quit();
    }
}

/**
 * Drop seeded credentials again. Tolerates ids the test already removed through the UI, and must
 * run even when the test fails: a leftover credential puts a passkey button on the login page for
 * every later spec.
 *
 * @param {Array} ids - credential ids
 * @param {String} [user] - owning username
 */
async function removePasskeys(ids, user = 'admin') {
    const redis = new Redis(REDIS_URL);
    try {
        for (const id of ids) {
            await redis.del(`webauthn:cred:${id}`);
            await redis.srem(`webauthn:creds:${user}`, id);
            await redis.srem('webauthn:all', id);
        }
    } finally {
        await redis.quit();
    }
}

module.exports = {
    ADMIN_PASSWORD,
    PORT,
    BASE_URL,
    ensureAdminSession,
    ensureTrial,
    createApiToken,
    dismissTokenReveal,
    trackConsoleErrors,
    setPickedAccount,
    hostedAuthFormUrl,
    seedPasskeys,
    removePasskeys
};
