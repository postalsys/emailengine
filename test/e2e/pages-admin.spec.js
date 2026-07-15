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

const os = require('os');
const path = require('path');
const { test, expect } = require('@playwright/test');
const { ensureAdminSession, createApiToken } = require('./helpers/bootstrap');

// One real login per run: the admin session cookie is captured in beforeAll and
// reused by every test via storageState. Logging in per test trips the login
// rate limiter once the suite grows past ~10 tests.
const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-admin-state.json');

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
    test.use({ storageState: STATE_FILE });

    test.beforeAll(async ({ browser }) => {
        // plain context (storageState explicitly unset - the file does not
        // exist yet) performs the single real login
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        await page.context().storageState({ path: STATE_FILE });
        await page.close();
    });
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

    test('dashboard: stat cards, tooltips and versions panel', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        // stat cards with accent borders
        await expect(page.locator('.card.border-s-4').first()).toBeVisible();
        await expect(page.getByText('Accounts total')).toBeVisible();
        await expect(page.getByText('Webhooks queue')).toBeVisible();

        // FlyonUI tooltip on a stat-card label
        await page.locator('.tooltip-toggle', { hasText: 'Accounts total' }).hover();
        await expect(page.locator('.tooltip.show')).toHaveCount(1, { timeout: 5000 });

        // software versions panel toggles open
        const imapflowRow = page.getByText('ImapFlow');
        await expect(imapflowRow).toBeHidden();
        await page.locator('summary', { hasText: 'Software versions' }).click();
        await expect(imapflowRow).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('accounts list: renders and opens the add-account modal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin/accounts');

        await expect(page.locator('h1', { hasText: 'Email Accounts' })).toBeVisible();

        // FlyonUI overlay opens with focus on the name field, Escape closes and clears
        await page.locator('[data-overlay="#addAccount"]').first().click();
        await expect(page.locator('#addAccount.open')).toHaveCount(1);
        await expect(page.locator('#account-name')).toBeFocused();
        await page.fill('#account-name', 'wiped-on-close');
        await page.keyboard.press('Escape');
        await expect(page.locator('#addAccount.open')).toHaveCount(0);
        await expect(page.locator('#account-name')).toHaveValue('');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    // The detail/edit/browse page tests need an existing account. The happy-path spec
    // registers one when the full suite runs; standalone runs skip gracefully.
    async function firstAccountUrl(page) {
        await page.goto('/admin/accounts');
        const row = page.locator('tbody tr td a[href^="/admin/accounts/"]').first();
        if (!(await row.count())) {
            return null;
        }
        return row.getAttribute('href');
    }

    test('account detail page: toolbar tooltips and modals', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');

        await page.goto(url);
        await expect(page.locator('#delete-btn')).toBeVisible();

        // toolbar tooltip on hover
        await page.locator('#request-reconnect').hover();
        await expect(page.locator('.tooltip.show')).toHaveCount(1, { timeout: 5000 });
        await page.mouse.move(0, 0);

        // delete confirmation modal opens and closes without submitting
        await page.locator('#delete-btn').click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
        await page.keyboard.press('Escape');
        await expect(page.locator('#deleteModal.open')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('account edit page: form renders', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');

        await page.goto(`${url}/edit`);
        await expect(page.locator('#name')).toBeVisible();
        await expect(page.locator('#email')).toBeVisible();
        await expect(page.locator('button[type="submit"]', { hasText: 'Update account' })).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('account browse page: ee-client widget initializes', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');

        await page.goto(`${url}/browse`);
        await expect
            .poll(
                async () =>
                    page.evaluate(() => {
                        const elm = document.getElementById('email-client');
                        return elm ? elm.children.length : -1;
                    }),
                { timeout: 20000 }
            )
            .toBeGreaterThan(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('gateways: create, view and delete a gateway', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // list page renders
        await page.goto('/admin/gateways');
        await expect(page.locator('h1', { hasText: 'Email Gateways' })).toBeVisible();

        // create via the new-gateway form
        await page.goto('/admin/gateways/new');
        await page.fill('#gateway', 'e2e-smoke-gw');
        await page.fill('#name', 'E2E Smoke Gateway');
        await page.fill('#host', '127.0.0.1');
        await page.fill('#port', '2525');
        await page.locator('button[type="submit"]', { hasText: 'Create Gateway' }).click();
        // the create redirect lands on the gateway detail page
        await page.waitForURL(/\/admin\/gateways\/gateway\//);

        // detail page shows the gateway
        await page.goto('/admin/gateways/gateway/e2e-smoke-gw');
        await expect(page.locator('.ee-dl dt', { hasText: 'Gateway ID' })).toBeVisible();
        await expect(page.getByRole('heading', { name: 'E2E Smoke Gateway' })).toBeVisible();

        // delete through the confirmation modal
        await page.locator('#delete-btn').click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
        await page.locator('#deleteModal button[type="submit"]').click();
        await page.waitForURL(/\/admin\/gateways(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('tokens: list renders, delete modal wires the description', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // guarantee at least one token exists via the shared reveal-flow helper
        await createApiToken(page, 'e2e tokens-page token');
        // let the overlay's opening transition finish (opacity 0 -> 1) - a close
        // click during the animation is swallowed by the overlay plugin
        await expect(page.locator('#showToken')).toHaveCSS('opacity', '1');
        await page.locator('#showToken button', { hasText: 'Done' }).click();
        await expect(page.locator('#showToken.open')).toHaveCount(0);
        // anchored: /admin/tokens/new also matches an unanchored /admin\/tokens/
        await page.waitForURL(/\/admin\/tokens(\?|$)/);

        await expect(page.locator('h1', { hasText: 'Access Tokens' })).toBeVisible();
        await expect(page.locator('tbody tr').first()).toBeVisible();

        // delete modal carries the token description; close without deleting
        const firstDelete = page.locator('.delete-token-btn').first();
        const description = await firstDelete.getAttribute('data-token-description');
        await firstDelete.click();
        await expect(page.locator('#deleteToken.open')).toHaveCount(1);
        await expect(page.locator('#delete-token-description')).toHaveText(description);
        await page.keyboard.press('Escape');
        await expect(page.locator('#deleteToken.open')).toHaveCount(0);

        // usage instructions panel toggles
        await page.locator('summary', { hasText: 'Usage instructions' }).click();
        await expect(page.getByText('Prometheus endpoint')).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('templates: create via editor form, tabs on the detail page, delete', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/templates');
        await expect(page.locator('h1', { hasText: 'Email Templates' })).toBeVisible();

        // create through the ACE-backed form (editor content is optional)
        await page.goto('/admin/templates/new');
        await page.fill('#inputName', 'E2E Smoke Template');
        await page.fill('#inputSubject', 'e2e subject');
        // FlyonUI tabs switch the editor panes
        await page.locator('#text-tab').click();
        await expect(page.locator('#text')).toBeVisible();
        await expect(page.locator('#html')).toBeHidden();
        await page.locator('button[type="submit"]', { hasText: 'Create template' }).click();
        await page.waitForURL(/\/admin\/templates\/template\//);

        // detail page: ACE preview initialized, send-test modal opens with the
        // send button gated on the recipient
        await expect(page.locator('#html-preview .ace_content')).toBeAttached();
        await page.locator('#test-btn').click();
        await expect(page.locator('#sendTestModal.open')).toHaveCount(1);
        expect(await page.evaluate(() => document.getElementById('send-test-btn').disabled)).toBe(true);
        await page.keyboard.press('Escape');
        await expect(page.locator('#sendTestModal.open')).toHaveCount(0);

        // delete through the confirmation modal
        await page.locator('#delete-btn').click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
        await page.locator('#deleteModal button[type="submit"]').click();
        await page.waitForURL(/\/admin\/templates(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('webhooks: create a route with live filter evaluation, tabs on the detail page, delete', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/webhooks');
        await expect(page.locator('h1', { hasText: 'Webhook Routing' })).toBeVisible();

        // create through the ACE-backed editor form
        await page.goto('/admin/webhooks/new');
        await page.fill('#inputName', 'E2E Smoke Route');
        await page.fill('#inputTargetUrl', 'https://example.com/e2e-webhook');
        await expect(page.locator('#editor-fn .ace_content')).toBeAttached();

        // the filter function is evaluated live in the evaluation Web Worker
        await page.evaluate(() => window.ace.edit('editor-fn').setValue('return true;'));
        await expect(page.locator('#filter-res')).toHaveText('filter matches');

        // test-payload modal opens and offers predefined payloads
        await page.locator('#test-payload-btn').click();
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(1);
        await expect(page.locator('#setPayloadModal')).toHaveCSS('opacity', '1');
        expect(await page.locator('#select-predefined-payload option').count()).toBeGreaterThan(1);
        await page.keyboard.press('Escape');
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(0);

        await page.locator('button[type="submit"]', { hasText: 'Create routing' }).click();
        await page.waitForURL(/\/admin\/webhooks\/webhook\//);

        // detail page: read-only ACE previews, FlyonUI tabs switch fn/map panes
        await expect(page.locator('#fn-preview .ace_content')).toBeAttached();
        await page.locator('#map-tab').click();
        await expect(page.locator('#map')).toBeVisible();
        await expect(page.locator('#fn')).toBeHidden();

        // delete through the confirmation modal
        await page.locator('#delete-btn').click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
        await page.locator('#deleteModal button[type="submit"]').click();
        await page.waitForURL(/\/admin\/webhooks(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config network: or-else-all gating, IP rescan and remove-address modal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/network');
        await expect(page.locator('h1', { hasText: 'Network' })).toBeVisible();

        // the proxy checkbox is disabled until a proxy URL is entered (app.js or-else-all)
        expect(await page.evaluate(() => document.getElementById('proxy_enabled').disabled)).toBe(true);
        await page.fill('#proxyUrl', 'socks://localhost:1080');
        await page.locator('#proxyUrl').dispatchEvent('change');
        expect(await page.evaluate(() => document.getElementById('proxy_enabled').disabled)).toBe(false);

        // scan for IPs re-renders the address list through the browser-side
        // Handlebars template; the delete trigger is delegated so it works on
        // re-rendered rows
        await page.locator('#reload-btn').click();
        await page.waitForFunction(() => !document.getElementById('reload-btn').disabled);
        await expect(page.locator('#address-list tr').first()).toBeVisible();

        const firstDelete = page.locator('#address-list .address-action-delete').first();
        const address = await firstDelete.getAttribute('data-address');
        await firstDelete.click();
        await expect(page.locator('#deleteAddress.open')).toHaveCount(1);
        await expect(page.locator('#deleteAddressLabel')).toHaveText(`Remove ${address}?`);
        await page.keyboard.press('Escape');
        await expect(page.locator('#deleteAddress.open')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config webhooks: event-type gating and test-webhook button state', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/webhooks');
        await expect(page.locator('h1', { hasText: 'Webhooks' })).toBeVisible();
        expect(await page.locator('.event-type').count()).toBeGreaterThan(10);

        // "All events" disables the individual event checkboxes
        await page.locator('#notifyAll').check();
        expect(await page.evaluate(() => [...document.querySelectorAll('.event-type')].every(e => e.disabled))).toBe(true);
        await page.locator('#notifyAll').uncheck();
        expect(await page.evaluate(() => [...document.querySelectorAll('.event-type')].every(e => !e.disabled))).toBe(true);

        // the send-test button is gated on the webhook URL
        await page.fill('#settingsWebhooks', '');
        await page.locator('#settingsWebhooks').dispatchEvent('change');
        expect(await page.evaluate(() => document.getElementById('test-payload-btn').disabled)).toBe(true);
        await page.fill('#settingsWebhooks', 'https://example.com/e2e-hook');
        await page.locator('#settingsWebhooks').dispatchEvent('change');
        expect(await page.evaluate(() => document.getElementById('test-payload-btn').disabled)).toBe(false);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config smtp: integration examples render through highlight.js tabs', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/smtp');
        await expect(page.locator('h1', { hasText: 'SMTP Interface' })).toBeVisible();
        await expect(page.locator('h1 .state-info')).toBeVisible();

        await page.locator('summary', { hasText: 'Integration Examples' }).click();
        await expect(page.locator('#example-nodemailer-code')).toContainText('createTransport');
        await page.locator('#example-phpmailer-tab').click();
        await expect(page.locator('#example-phpmailer')).toBeVisible();
        await expect(page.locator('#example-phpmailer-code')).toContainText('PHPMailer');

        // editing the port re-renders the examples
        await page.fill('#smtpServerPort', '3535');
        await page.locator('#smtpServerPort').dispatchEvent('change');
        await expect(page.locator('#example-phpmailer-code')).toContainText('3535');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config imap-proxy: client examples and password reveal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/imap-proxy');
        await expect(page.locator('h1', { hasText: 'IMAP Proxy' })).toBeVisible();

        await page.locator('summary', { hasText: 'Client Configuration Examples' }).click();
        await expect(page.locator('#example-node-imap-code')).toContainText('new Imap');

        await page.fill('#imapProxyServerPassword', 'e2e-secret');
        await page.locator('#showPassword').click();
        expect(await page.evaluate(() => document.getElementById('imapProxyServerPassword').type)).toBe('text');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config ai: ACE editors, live filter evaluation and test-filter modal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/ai');
        await expect(page.locator('#editor-fn .ace_content')).toBeAttached();
        await expect(page.locator('#editor-prompt .ace_content')).toBeAttached();

        await page.evaluate(() => window.ace.edit('editor-fn').setValue('return true;'));
        await expect(page.locator('#filter-res')).toHaveText('match - will process');

        await page.locator('#test-payload-btn').click();
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(1);
        await expect(page.locator('#setPayloadModal')).toHaveCSS('opacity', '1');
        await page.keyboard.press('Escape');
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config service: editors, language override details and queue cleanup toast', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/service');
        await expect(page.locator('h1', { hasText: 'General Settings' })).toBeVisible();
        await expect(page.locator('#editor-html .ace_content')).toBeAttached();
        await expect(page.locator('#editor-env .ace_content')).toBeAttached();

        await page.locator('#languageDetails summary').click();
        await expect(page.locator('#languageDetails .alert')).toBeVisible();

        // clear-completed-jobs posts to the server and reports through a toast
        await page.locator('#clean-queues-btn').click();
        await expect(page.locator('#toastContainer .alert', { hasText: 'Cleanup request sent' })).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config logging and license: forms render', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/logging');
        await expect(page.locator('h1', { hasText: 'Logging' })).toBeVisible();
        await expect(page.locator('#settingsLogsMaxLogLines')).toBeVisible();

        await page.goto('/admin/config/license');
        await expect(page.locator('h1', { hasText: 'License' })).toBeVisible();
        // the add-license panel is collapsible; the e2e instance runs on a
        // trial so it starts collapsed
        const details = page.locator('details', { has: page.locator('summary', { hasText: 'Add License Key' }) });
        if (!(await details.evaluate(d => d.open))) {
            await details.locator('summary').click();
        }
        await expect(page.locator('#licenseTextElement')).toBeVisible();
        await expect(page.locator('#licenseFile')).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('oauth apps: create via provider dropdown, verify-setup modal, delete', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // apps list with the create-app dropdown
        await page.goto('/admin/config/oauth');
        await expect(page.locator('h1', { hasText: 'OAuth2' })).toBeVisible();
        await page.locator('#create-app-dropdown').click();
        await expect(page.locator('#create-app-dropdown ~ ul .dropdown-item', { hasText: 'Gmail Service Accounts' })).toBeVisible();
        await page.keyboard.press('Escape');

        // create a Gmail app with dummy credentials through the converted form;
        // base-scope radios gate the pubsub select + account-type helper
        await page.goto('/admin/config/oauth/new?provider=gmail');
        expect(await page.evaluate(() => document.getElementById('select-pubsub-app').classList.contains('hidden'))).toBe(true);
        await page.locator('#baseScopesAPI').check();
        expect(await page.evaluate(() => document.getElementById('account-type-card-gmail').classList.contains('hidden'))).toBe(false);
        await page.locator('#baseScopesImap').check();
        await page.fill('#name', 'E2E OAuth App');
        await page.fill('#clientId', '1234567890-e2e.apps.googleusercontent.com');
        await page.fill('#clientSecret', 'GOCSPX-e2e-dummy');
        await page.locator('button[type="submit"]', { hasText: 'Register app' }).click();
        await page.waitForURL(/\/admin\/config\/oauth\/app\//);

        // detail page: verify-setup modal auto-runs the configuration checks
        await expect(page.locator('#appIdValue')).toBeVisible();
        await page.locator('#verify-btn').click();
        await expect(page.locator('#verifySetupModal.open')).toHaveCount(1);
        await expect(page.locator('#verifySetupModal')).toHaveCSS('opacity', '1');
        // the run finishes (dummy credentials, so the verdict may report failures)
        await page.waitForFunction(() => !document.getElementById('verify-run-btn').disabled);
        expect(await page.locator('#verify-steps li').count()).toBeGreaterThan(0);
        await page.keyboard.press('Escape');
        await expect(page.locator('#verifySetupModal.open')).toHaveCount(0);

        // delete through the confirmation modal
        await page.locator('#delete-btn').click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
        await page.locator('#deleteModal button[type="submit"]').click();
        await page.waitForURL(/\/admin\/config\/oauth(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('anonymous visitor is redirected to the login page', async ({ page, browser }) => {
        // make sure auth is enabled even when this test runs alone
        await ensureAdminSession(page);

        // fresh context without the admin session cookie (storageState must be
        // explicitly unset - manual contexts inherit the fixture options)
        const context = await browser.newContext({ storageState: undefined });
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
