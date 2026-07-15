'use strict';

// Idempotent admin-UI bootstrap helpers for the e2e suite. Every spec shares one booted
// EmailEngine instance and the isolated Redis db 14 (see playwright.config.js), so these must
// tolerate an instance another spec has already bootstrapped: set the first admin password on a
// fresh instance, otherwise log in; activate a trial only when the instance is not yet licensed.

const { expect } = require('@playwright/test');

// Shared admin password for the whole e2e suite - every spec authenticates against the same
// booted instance, so there must be exactly one source for this value.
const ADMIN_PASSWORD = 'E2e-Test-Password-123!';

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

module.exports = { ADMIN_PASSWORD, ensureAdminSession, ensureTrial, createApiToken };
