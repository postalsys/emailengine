/* global document, window */
'use strict';

// Per-page smoke tests for the admin UI (Tailwind v4 + FlyonUI theme). Each admin page gets at
// least one test here as it is converted: the page renders for an authenticated admin, its
// primary interaction works, and the browser logs no console errors.
//
// Phase 1 covers the global shell: sidebar menu + accordion, topbar dropdowns, theme toggle,
// toast helper, and the login redirect for anonymous visitors.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker; this file sorts after happy-path/hosted-form, which may already have
// bootstrapped the instance - the helpers are idempotent, and these tests do not depend on the
// license state).
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect } = require('@playwright/test');
const { ensureAdminSession } = require('./helpers/bootstrap');

// Per-test console error collection; every test asserts the page stayed clean.
function trackConsoleErrors(page) {
    const errors = [];
    page.on('console', msg => {
        if (msg.type() === 'error') {
            errors.push(msg.text());
        }
    });
    page.on('pageerror', err => errors.push(`pageerror: ${err.message}`));
    return errors;
}

test.describe('admin shell', () => {
    test('dashboard shell: sidebar, topbar and footer render', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        // Sidebar: brand + primary menu entries
        const sidebar = page.locator('#layout-sidebar');
        await expect(sidebar.getByRole('link', { name: 'Dashboard' })).toBeVisible();
        await expect(sidebar.getByRole('link', { name: 'Email Accounts' })).toBeVisible();
        await expect(sidebar.getByRole('link', { name: 'Webhook Routing' })).toBeVisible();

        // Topbar: theme toggle and user menu
        await expect(page.locator('.theme-toggle-btn')).toBeVisible();
        await expect(page.locator('#userDropdown')).toBeVisible();

        // Footer
        await expect(page.getByText(/Postal Systems/)).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('sidebar accordion: Configuration expands and collapses', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        const generalSettings = page.getByRole('link', { name: 'General Settings' });
        await expect(generalSettings).toBeHidden();

        await page.locator('#menu-config .accordion-toggle').click();
        await expect(generalSettings).toBeVisible();

        await page.locator('#menu-config .accordion-toggle').click();
        await expect(generalSettings).toBeHidden();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('topbar user dropdown opens', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        const securityLink = page.getByRole('link', { name: 'Account security' });
        await expect(securityLink).toBeHidden();

        await page.locator('#userDropdown').click();
        await expect(securityLink).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('theme toggle switches to dark, persists across reload', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        const htmlTheme = () => page.evaluate(() => document.documentElement.getAttribute('data-theme'));

        await page.locator('.theme-toggle-btn').click();
        expect(await htmlTheme()).toBe('dark');

        await page.reload();
        expect(await htmlTheme()).toBe('dark');

        // leave the instance in light mode for subsequent tests
        await page.locator('.theme-toggle-btn').click();
        expect(await htmlTheme()).toBe('light');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('showToast helper renders and auto-dismisses a toast', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        await page.evaluate(() => window.showToast('e2e toast check', 'info'));
        const toast = page.locator('#toastContainer .alert', { hasText: 'e2e toast check' });
        await expect(toast).toBeVisible();

        // auto-dismisses after ~5s
        await expect(toast).toHaveCount(0, { timeout: 10000 });

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('anonymous visitor is redirected to the login page', async ({ page, browser }) => {
        // make sure auth is enabled even when this test runs alone
        await ensureAdminSession(page);

        // fresh context without the admin session cookie
        const context = await browser.newContext();
        const anonPage = await context.newPage();
        const errors = trackConsoleErrors(anonPage);

        await anonPage.goto('/admin');
        await anonPage.waitForURL(/\/admin\/login/);
        await expect(anonPage.locator('#loginUsername')).toBeVisible();
        await expect(anonPage.locator('#loginPassword')).toBeVisible();
        await expect(anonPage.locator('form[action="/admin/login"] button[type="submit"]')).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
        await context.close();
    });
});
