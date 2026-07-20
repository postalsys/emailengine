/* global document, window, navigator, localStorage, fetch */
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
const { test, expect, request } = require('@playwright/test');
const { ensureAdminSession, createApiToken, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');

// One real login per run: the admin session cookie is captured in beforeAll and
// reused by every test via storageState. Logging in per test trips the login
// rate limiter once the suite grows past ~10 tests.
const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-admin-state.json');

// Resolves --color-primary for the active theme into the rgb() form that
// getComputedStyle returns, so the tab assertions below stay theme-agnostic.
function resolvePrimaryColor(page) {
    return page.evaluate(() => {
        const probe = document.createElement('span');
        probe.style.color = 'var(--color-primary)';
        document.body.appendChild(probe);
        const color = window.getComputedStyle(probe).color;
        probe.remove();
        return color;
    });
}

// Asserts that a FlyonUI tab strip actually *shows* which tab is selected.
// The panes and the toggled class are checked separately; this guards the
// styling hook specifically, which is a separate class (`tab-active`, applied
// via the `active-tab:` variant) from the one the FlyonUI JS toggles
// (`active`). Hovering a tab also paints it primary, so the pointer is parked
// away from the strip before the colors are read.
async function expectSelectedTab(page, selectedId, otherIds) {
    const primary = await resolvePrimaryColor(page);
    await page.mouse.move(0, 0);
    await expect(page.locator(`#${selectedId}`)).toHaveCSS('color', primary);
    for (const id of otherIds) {
        await expect(page.locator(`#${id}`)).not.toHaveCSS('color', primary);
    }
}

// Asserts the HSTogglePassword round-trip on a secret field: revealing flips
// the input type and swaps the eye icon to eye-off, toggling again hides it.
async function expectPasswordToggle(page, btnId, inputId) {
    const input = page.locator(`#${inputId}`);
    const eye = page.locator(`#${btnId} .icon-\\[tabler--eye\\]`);
    const eyeOff = page.locator(`#${btnId} .icon-\\[tabler--eye-off\\]`);

    await expect(input).toHaveAttribute('type', 'password');
    await expect(eye).toBeVisible();
    await expect(eyeOff).toBeHidden();

    await page.locator(`#${btnId}`).click();
    await expect(input).toHaveAttribute('type', 'text');
    await expect(eye).toBeHidden();
    await expect(eyeOff).toBeVisible();

    await page.locator(`#${btnId}`).click();
    await expect(input).toHaveAttribute('type', 'password');
    await expect(eye).toBeVisible();
    await expect(eyeOff).toBeHidden();
}

// Hovers a trigger and asserts a FlyonUI tooltip bubble shows, then parks the
// pointer away again so the tooltip (and any hover paint) clears.
async function expectTooltipOnHover(page, trigger) {
    await trigger.hover();
    await expect(page.locator('.tooltip.show')).toHaveCount(1, { timeout: 5000 });
    await page.mouse.move(0, 0);
}

// Waits for a FlyonUI overlay to be open and fully faded in - a click or key
// press during the opening transition is swallowed by the overlay plugin.
async function expectModalOpen(page, id) {
    await expect(page.locator(`#${id}.open`)).toHaveCount(1);
    await expect(page.locator(`#${id}`)).toHaveCSS('opacity', '1');
}

// Drives the standard delete-confirmation flow on a detail page: open the modal
// with #delete-btn, submit it, and wait for the redirect back to the list page.
// Submit a search through the topbar form and wait for the filtered list page
async function searchTopbar(page, target, query) {
    await page.fill(`header form[action="${target}"] input[name="query"]`, query);
    await page.locator(`header form[action="${target}"] button[type="submit"]`).click();
    await page.waitForURL(url => url.pathname === target && url.searchParams.get('query') === query);
}

// On detail views the destructive Delete now lives inside a ui/overflow-menu kebab
// (id="delete-btn" on the dropdown item), so it is hidden until the kebab is opened.
// Open the containing dropdown if collapsed, then click the item. Retry the whole
// open-then-click since the dropdown can close on its own between the two (animations).
async function openDeleteAction(page) {
    const del = page.locator('#delete-btn');
    await expect(async () => {
        if (!(await del.isVisible())) {
            await page.locator('.dropdown:has(#delete-btn) .dropdown-toggle').click();
            await expect(del).toBeVisible({ timeout: 2000 });
        }
        await del.click({ timeout: 2000 });
    }).toPass({ timeout: 15000 });
}

async function deleteViaModal(page, listUrlRe, opts) {
    await openDeleteAction(page);
    await expect(page.locator('#deleteModal.open')).toHaveCount(1);
    if (opts && opts.checkCancel) {
        // the footer Cancel closes without submitting; its data-overlay target
        // is the closeOverlay value ui/modal hands to the block (it once
        // rendered as a dead "#" because the id hash param is neutralized
        // inside the block). The shared ui/confirm-modal partial renders
        // identically on every page, so one call site opting in covers all
        // confirm modals without slowing the other delete flows down.
        await page.locator('#deleteModal button', { hasText: 'Cancel' }).click();
        await expect(page.locator('#deleteModal.open')).toHaveCount(0);
        await expect(page.locator('.overlay-backdrop')).toHaveCount(0);
        await openDeleteAction(page);
        await expect(page.locator('#deleteModal.open')).toHaveCount(1);
    }
    await page.locator('#deleteModal button[type="submit"]').click();
    await page.waitForURL(listUrlRe);
}

// Dismisses the one-time token reveal modal createApiToken leaves open: settle
// the opening transition (a click mid-animation is swallowed), then wait out the
// location.assign the Done button triggers - navigating while it is in flight
// aborts with ERR_ABORTED.
async function dismissTokenReveal(page) {
    await expect(page.locator('#showToken')).toHaveCSS('opacity', '1');
    await page.locator('#showToken button', { hasText: 'Done' }).click();
    await page.waitForURL(/\/admin\/tokens(\?|$)/);
}

// Asserts the TLS certificate label's FlyonUI tooltip: the cert status text
// shows on hover, and the structure paintCertData() repaints through (the
// badge's .tooltip ancestor > .tooltip-body) is present with the title text.
async function expectTlsLabelTooltip(page) {
    const tlsTooltipText = await page.evaluate(() => {
        const label = document.getElementById('tls-label');
        const wrap = label && label.closest('.tooltip');
        const body = wrap && wrap.querySelector('.tooltip-body');
        return body ? body.textContent.trim() : null;
    });
    expect(tlsTooltipText).toBeTruthy();
    await expectTooltipOnHover(page, page.locator('#tls-label'));
}

// Per-test console error collection lives in helpers/bootstrap.js
// (trackConsoleErrors); every test asserts the page stayed clean.

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
        await expect(sidebar.getByRole('link', { name: 'Accounts' })).toBeVisible();
        await expect(sidebar.getByRole('link', { name: 'Webhook Routes' })).toBeVisible();

        // Topbar: theme toggle and user menu
        await expect(page.locator('.theme-toggle-btn')).toBeVisible();
        await expect(page.locator('#userDropdown')).toBeVisible();

        // Footer
        await expect(page.getByText(/Postal Systems/)).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('copy button falls back to execCommand without the Clipboard API', async ({ page }) => {
        // Self-hosted installs on plain HTTP get no navigator.clipboard (not a
        // secure context); the ui.js handler must stage the value in a
        // throwaway textarea and run document.execCommand('copy') on it
        // (selecting the target itself would not work for password inputs or
        // ACE editors, which only render the visible lines). The API cannot be
        // deleted from an already-secure context, so stub it out and spy on
        // execCommand, capturing the staged value from the focused element.
        await page.addInitScript(() => {
            Object.defineProperty(window.navigator, 'clipboard', { value: undefined });
            window.__copyCalls = [];
            const orig = document.execCommand.bind(document);
            document.execCommand = cmd => {
                const active = document.activeElement;
                window.__copyCalls.push({ cmd, value: active && 'value' in active ? active.value : null });
                return orig(cmd);
            };
        });
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        // fixture exercising the real delegated .copy-btn handler from ui.js;
        // fixed-positioned on top so the layout wrapper cannot cover the button
        await page.evaluate(() => {
            document.body.insertAdjacentHTML(
                'beforeend',
                '<div style="position:fixed;top:8px;left:8px;z-index:99999;background:#fff">' +
                    '<input id="copy-fixture" value="fallback-copy-value">' +
                    '<button type="button" class="copy-btn" data-copy-target="#copy-fixture">copy</button>' +
                    '</div>'
            );
        });
        await page.locator('button.copy-btn').click();
        expect(await page.evaluate(() => window.__copyCalls)).toEqual([{ cmd: 'copy', value: 'fallback-copy-value' }]);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('sidebar accordion: Configuration expands and collapses', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin');

        const generalSettings = page.getByRole('link', { name: 'General', exact: true });
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

        // stat cards in the FlyonUI idiom: the variant color tints a rounded
        // icon container; the Bootstrap-style edge stripes are gone
        await expect(page.locator('.card .rounded-field[class*="bg-"]').first()).toBeVisible();
        expect(await page.locator('[class*="border-s-4"]').count()).toBe(0);

        // grouped sections: Accounts cards, Activity counters, System queues
        await expect(page.locator('h1', { hasText: 'Dashboard' })).toBeVisible();
        await expect(page.getByText('Total accounts')).toBeVisible();
        await expect(page.getByText('Needs attention')).toBeVisible();
        await expect(page.getByText('Webhooks queue')).toBeVisible();

        // FlyonUI tooltip on a stat-card label
        await expectTooltipOnHover(page, page.locator('.tooltip-toggle', { hasText: 'Total accounts' }));

        // the Activity window switcher reloads with the ?seconds= argument
        await page.getByRole('link', { name: '1h', exact: true }).click();
        await page.waitForURL(/\/admin\?seconds=3600/);
        await expect(page.getByText('New emails', { exact: true })).toBeVisible();
        await page.getByRole('link', { name: '24h', exact: true }).click();
        await page.waitForURL(url => url.pathname === '/admin' && !url.search);

        // the header Add account button opens the add-account modal
        await page.getByRole('button', { name: 'Add account', exact: true }).click();
        await expectModalOpen(page, 'addAccount');
        await page.keyboard.press('Escape');
        await expect(page.locator('#addAccount.open')).toHaveCount(0);

        // software versions panel toggles open
        const imapflowRow = page.getByText('ImapFlow');
        await expect(imapflowRow).toBeHidden();
        await page.locator('summary', { hasText: 'Software versions' }).click();
        await expect(imapflowRow).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('swagger reference renders as a light island in the dark theme', async ({ page }) => {
        // swagger-ui ships no dark styles (its stylesheet assumes a light
        // page); with a dark admin theme its transparent panels used to sit
        // unreadably on the dark page background, so the reference is pinned
        // to a light data-theme subtree
        await page.addInitScript(() => {
            localStorage.setItem('eeTheme', 'dark');
        });
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin/swagger');
        await expect(page.locator('#swagger-ui .info')).toBeVisible({ timeout: 20000 });
        const probe = await page.evaluate(() => {
            const island = document.querySelector('[data-theme="light"]');
            const cs = window.getComputedStyle(island);
            return {
                background: cs.backgroundColor,
                colorScheme: cs.colorScheme,
                pageTheme: document.documentElement.getAttribute('data-theme')
            };
        });
        expect(probe.pageTheme).toBe('dark');
        expect(probe.background).toBe('rgb(255, 255, 255)');
        expect(probe.colorScheme).toBe('light');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('accounts list: renders and opens the add-account modal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        await page.goto('/admin/accounts');

        await expect(page.locator('h1', { hasText: 'Accounts' })).toBeVisible();

        // regression: every account row must render its trailing actions kebab, and the
        // header/body column counts must match. The cell once silently vanished because
        // {{#if showActions}} inside {{#each}} resolved against the row, not the partial
        // params, leaving a phantom empty trailing column that showed on row hover.
        const rowCount = await page.locator('tbody tr').count();
        if (rowCount) {
            await expect(page.locator('tbody tr [aria-label="Account actions"]')).toHaveCount(rowCount);
            const cols = await page.evaluate(() => ({
                th: document.querySelectorAll('table thead th').length,
                td: document.querySelectorAll('table tbody tr:first-child td').length
            }));
            expect(cols.td, 'header/body column count mismatch (phantom cell)').toBe(cols.th);
        }

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

        // toolbar tooltip on hover
        await expectTooltipOnHover(page, page.locator('#request-reconnect'));

        // delete now lives in the overflow (kebab) menu; open it, then the confirm
        // modal opens and closes without submitting.
        await openDeleteAction(page);
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

        // the embed follows the admin theme: its own toggle is hidden and the
        // topbar theme switch flips the client's dark mode live
        await expect(page.locator('.ee-dark-mode-toggle')).toHaveCount(0);
        const isClientDark = () => page.evaluate(() => document.querySelector('.ee-client').classList.contains('ee-dark-mode'));
        const startedDark = await isClientDark();
        await page.locator('.theme-toggle-btn').first().click();
        await expect.poll(isClientDark).toBe(!startedDark);
        await page.locator('.theme-toggle-btn').first().click();
        await expect.poll(isClientDark).toBe(startedDark);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('gateways: create, view and delete a gateway', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // list page renders
        await page.goto('/admin/gateways');
        await expect(page.locator('h1', { hasText: 'Gateways' })).toBeVisible();

        // create via the new-gateway form
        await page.goto('/admin/gateways/new');
        await page.fill('#gateway', 'e2e-smoke-gw');

        // long tooltip texts wrap inside the capped bubble instead of
        // rendering as one viewport-wide line
        const tlsTipToggle = page.locator('#secure').locator('..').locator('.tooltip .tooltip-toggle').first();
        await tlsTipToggle.hover();
        await expect(page.locator('.tooltip.show')).toHaveCount(1, { timeout: 5000 });
        const tipWidth = await page.evaluate(() => document.querySelector('.tooltip.show .tooltip-content').getBoundingClientRect().width);
        expect(tipWidth).toBeLessThanOrEqual(320);
        await page.mouse.move(0, 0);

        // typing a well-known service key into the name field autofills the
        // connection settings (uiDatalist + the gateway_js input listener)
        await expect(page.locator('#name')).toHaveAttribute('list', 'well-known-services-list');
        expect(await page.locator('#well-known-services-list option').count()).toBeGreaterThan(0);
        await page.fill('#name', 'gmail');
        await page.locator('#name').dispatchEvent('input');
        await expect(page.locator('#host')).toHaveValue('smtp.gmail.com');

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

        // topbar search filters the list; a miss renders an empty result set
        await page.goto('/admin/gateways');
        await searchTopbar(page, '/admin/gateways', 'e2e-smoke');
        await expect(page.getByText('Results for "e2e-smoke"')).toBeVisible();
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Gateway' })).toBeVisible();
        await page.goto('/admin/gateways?query=no-such-gateway-zzz');
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Gateway' })).toHaveCount(0);

        // the clear button in the topbar search input drops the query and
        // returns the unfiltered list
        await page.locator('#topbar-search-clear').click();
        await page.waitForURL(url => url.pathname === '/admin/gateways' && !url.searchParams.has('query'));
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Gateway' })).toBeVisible();

        // delete from the list via the row-actions kebab. This exercises the
        // path-param delete route wired through data-delete-action (the shared
        // .list-delete-btn handler rewrites the confirm-modal form action), plus
        // the Open item and the confirm-modal Cancel button on a list page.
        const gwRow = page.locator('tbody tr', { hasText: 'E2E Smoke Gateway' }).first();
        await gwRow.locator('.dropdown-toggle').click();
        await expect(gwRow.locator('.dropdown-menu a', { hasText: 'Open' })).toHaveAttribute('href', /\/admin\/gateways\/gateway\/e2e-smoke-gw$/);
        await gwRow.locator('.list-delete-btn').click();
        await expect(page.locator('#deleteGateway.open')).toHaveCount(1);
        await expect(page.locator('#deleteGateway .delete-target-name')).toHaveText('E2E Smoke Gateway');
        // Cancel closes without submitting
        await page.locator('#deleteGateway button', { hasText: 'Cancel' }).click();
        await expect(page.locator('#deleteGateway.open')).toHaveCount(0);
        // reopen and confirm - the gateway is actually removed
        await gwRow.locator('.dropdown-toggle').click();
        await gwRow.locator('.list-delete-btn').click();
        await expect(page.locator('#deleteGateway.open')).toHaveCount(1);
        await page.locator('#deleteGateway button[type="submit"]').click();
        await page.waitForURL(/\/admin\/gateways(\?|$)/);
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Gateway' })).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('row-actions: the kebab wrapper does not trap the open menu', async ({ page, request }) => {
        // Regression: the row-actions wrapper must not carry a z-index. A per-row
        // stacking context traps the open menu (FlyonUI gives .dropdown-menu
        // z-index:10) inside it, so the next row's kebab painted over the menu.
        // Asserted structurally (computed z-index) rather than by pixel occlusion,
        // which depends on floating-ui's viewport-driven flip direction.
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // seed two gateways so the list renders row-actions kebabs
        const token = await createApiToken(page, 'e2e kebab-z token');
        const auth = { Authorization: `Bearer ${token}`, 'Content-type': 'application/json' };
        const seeded = ['e2e-zorder-1', 'e2e-zorder-2'];
        for (const g of seeded) {
            await request.post('/v1/gateway', { headers: auth, data: { gateway: g, name: g, host: '127.0.0.1', port: 2525 } });
        }

        try {
            await page.goto('/admin/gateways');
            const rows = page.locator('tbody tr');
            expect(await rows.count()).toBeGreaterThanOrEqual(2);

            // the wrapper must resolve to z-index:auto (no stacking context) while
            // FlyonUI keeps the open menu at z-index:10, position:fixed
            const wrap = rows.nth(0).locator('.dropdown').first();
            expect(await wrap.evaluate(el => window.getComputedStyle(el).zIndex)).toBe('auto');

            await rows.nth(0).locator('.dropdown-toggle').click();
            const menu = rows.nth(0).locator('.dropdown-menu');
            await expect(menu.locator('.list-delete-btn')).toBeVisible();
            const menuStyle = await menu.evaluate(el => ({ z: window.getComputedStyle(el).zIndex, pos: window.getComputedStyle(el).position }));
            expect(menuStyle.pos).toBe('fixed');
            expect(Number(menuStyle.z)).toBeGreaterThan(1);
        } finally {
            for (const g of seeded) {
                await request.delete(`/v1/gateway/${g}`, { headers: auth }).catch(() => {});
            }
        }

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('tokens: list renders, delete modal wires the description', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // guarantee at least one token exists via the shared reveal-flow helper
        await createApiToken(page, 'e2e tokens-page token');
        await dismissTokenReveal(page);

        await expect(page.locator('h1', { hasText: 'Access Tokens' })).toBeVisible();
        await expect(page.locator('tbody tr').first()).toBeVisible();

        // the ui/entity-id copy button copies the full row id via the
        // data-copy-value branch of the ui.js .copy-btn handler
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        const idBtn = page.locator('tbody tr').first().locator('.copy-btn[data-copy-value]');
        const idValue = await idBtn.getAttribute('data-copy-value');
        expect(idValue).toBeTruthy();
        await idBtn.click();
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(idValue);

        // topbar search filters the token list by description (case-insensitive)
        await searchTopbar(page, '/admin/tokens', 'TOKENS-page');
        await expect(page.locator('tbody tr', { hasText: 'e2e tokens-page token' }).first()).toBeVisible();
        await page.goto('/admin/tokens');

        // the row-actions kebab opens the shared delete modal, which the
        // .list-delete-btn handler fills with the token description; close
        // without deleting
        const firstRow = page.locator('tbody tr').first();
        const deleteItem = firstRow.locator('.list-delete-btn');
        const description = await deleteItem.getAttribute('data-delete-name');
        await firstRow.locator('.dropdown-toggle').click();
        await deleteItem.click();
        await expect(page.locator('#deleteToken.open')).toHaveCount(1);
        await expect(page.locator('#deleteToken .delete-target-name')).toHaveText(description);
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
        await expect(page.locator('h1', { hasText: 'Templates' })).toBeVisible();

        // create through the ACE-backed form (editor content is optional)
        await page.goto('/admin/templates/new');
        await page.fill('#inputName', 'E2E Smoke Template');
        await page.fill('#inputSubject', 'e2e subject');

        // editor fullscreen round-trip through the shared uiEditorFullscreen
        // helper. Assert the effect, not the class: ACE's runtime stylesheet
        // once overrode .full-screen-div so the class was on but the editor
        // collapsed - the rect must actually cover the viewport.
        const editorRect = () =>
            page.evaluate(() => {
                const r = document.getElementById('editor-html').getBoundingClientRect();
                return { x: r.x, y: r.y, w: r.width, h: r.height, vw: window.innerWidth, vh: window.innerHeight };
            });
        await expect(page.locator('#fullscreen-close-btn')).toBeHidden();
        await page.locator('.toggle-fullscreen[data-target="editor-html"]').click();
        let rect = await editorRect();
        expect(rect.x).toBe(0);
        expect(rect.y).toBe(0);
        expect(rect.w).toBe(rect.vw);
        expect(rect.h).toBe(rect.vh);

        // the floating close button is the touch-device exit (no Escape key there)
        await expect(page.locator('#fullscreen-close-btn')).toBeVisible();
        await page.locator('#fullscreen-close-btn').click();
        rect = await editorRect();
        expect(rect.h).toBeLessThan(rect.vh / 2);
        await expect(page.locator('#fullscreen-close-btn')).toBeHidden();

        // Escape still exits for keyboard users
        await page.locator('.toggle-fullscreen[data-target="editor-html"]').click();
        rect = await editorRect();
        expect(rect.h).toBe(rect.vh);
        await page.keyboard.press('Escape');
        rect = await editorRect();
        expect(rect.h).toBeLessThan(rect.vh / 2);

        // the toolbar copy control puts the full editor content on the
        // clipboard (the ACE branch of the ui.js .copy-btn handler); compare
        // against the editor's own value - ACE auto-closes typed tags
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await page.locator('#editor-html').click();
        await page.keyboard.type('<p>e2e copy</p>');
        await page.locator('.copy-btn[data-copy-target="#editor-html"]').click();
        const editorContent = await page.evaluate(() => document.getElementById('editor-html').env.editor.getValue());
        expect(editorContent).toContain('e2e copy');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(editorContent);

        // FlyonUI tabs switch the editor panes and mark the selected one
        await expectSelectedTab(page, 'html-tab', ['text-tab']);
        await page.locator('#text-tab').click();
        await expect(page.locator('#text')).toBeVisible();
        await expect(page.locator('#html')).toBeHidden();
        await expectSelectedTab(page, 'text-tab', ['html-tab']);
        await page.locator('button[type="submit"]', { hasText: 'Create template' }).click();
        await page.waitForURL(/\/admin\/templates\/template\//);

        // detail page: ACE preview initialized, send-test modal opens with the
        // send button gated on the recipient
        await expect(page.locator('#html-preview .ace_content')).toBeAttached();

        // the copy button puts the template ID on the clipboard (ui.js handler)
        // and briefly swaps its icon to a check mark as feedback
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        const templateId = await page.locator('#templateIdValue').inputValue();
        expect(templateId).not.toBe('');
        await page.locator('.copy-btn').click();
        await expect(page.locator('.copy-btn [class*="icon-"]')).toHaveClass(/tabler--check\]/);
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(templateId);
        await expect(page.locator('.copy-btn [class*="icon-"]')).toHaveClass(/tabler--copy\]/, { timeout: 3000 });
        await page.locator('#test-btn').click();
        await expect(page.locator('#sendTestModal.open')).toHaveCount(1);
        expect(await page.evaluate(() => document.getElementById('send-test-btn').disabled)).toBe(true);
        await page.keyboard.press('Escape');
        await expect(page.locator('#sendTestModal.open')).toHaveCount(0);

        // topbar search matches the name with normalized case and whitespace
        const templateUrl = page.url();
        await page.goto('/admin/templates');
        await searchTopbar(page, '/admin/templates', 'e2e  smoke');
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Template' })).toBeVisible();
        await page.goto(templateUrl);

        await deleteViaModal(page, /\/admin\/templates(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('webhooks: create a route with live filter evaluation, tabs on the detail page, delete', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/webhooks');
        await expect(page.locator('h1', { hasText: 'Webhook Routes' })).toBeVisible();

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
        await expectModalOpen(page, 'setPayloadModal');
        expect(await page.locator('#select-predefined-payload option').count()).toBeGreaterThan(1);
        await page.keyboard.press('Escape');
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(0);

        // the editor toolbar: the title cell reads as a label (distinct
        // background from the action cells), and the scope-info tooltip
        // renders as one solid bubble (an inline body once fragmented its
        // background around the block list, leaving ghost text)
        const titleBg = await page
            .locator('.editor-embed-title')
            .first()
            .evaluate(el => window.getComputedStyle(el).backgroundColor);
        const actionBg = await page
            .locator('.editor-embed-content:not(.editor-embed-title)')
            .first()
            .evaluate(el => window.getComputedStyle(el).backgroundColor);
        expect(titleBg).not.toBe(actionBg);

        await page.locator('.editor-embed-content .tooltip-toggle').last().hover();
        const bubble = await page
            .locator('.editor-embed-content .tooltip-body')
            .last()
            .evaluate(el => {
                const cs = window.getComputedStyle(el);
                const bodyRect = el.getBoundingClientRect();
                const listRect = el.querySelector('ul').getBoundingClientRect();
                return {
                    background: cs.backgroundColor,
                    display: cs.display,
                    enclosesList: bodyRect.top <= listRect.top && bodyRect.bottom >= listRect.bottom && bodyRect.height > 0
                };
            });
        expect(bubble.background).not.toBe('rgba(0, 0, 0, 0)');
        expect(bubble.display).toBe('block');
        expect(bubble.enclosesList).toBe(true);
        await page.mouse.move(0, 0);

        await page.locator('button[type="submit"]', { hasText: 'Create routing' }).click();
        await page.waitForURL(/\/admin\/webhooks\/webhook\//);

        // detail page: read-only ACE previews, FlyonUI tabs switch fn/map panes
        // and mark the selected one
        await expect(page.locator('#fn-preview .ace_content')).toBeAttached();
        await expectSelectedTab(page, 'fn-tab', ['map-tab']);
        await page.locator('#map-tab').click();
        await expect(page.locator('#map')).toBeVisible();
        await expect(page.locator('#fn')).toBeHidden();
        await expectSelectedTab(page, 'map-tab', ['fn-tab']);

        // topbar search also matches the target URL of a route
        const routeUrl = page.url();
        await page.goto('/admin/webhooks');
        await searchTopbar(page, '/admin/webhooks', 'e2e-webhook');
        await expect(page.locator('tbody tr', { hasText: 'E2E Smoke Route' })).toBeVisible();
        await page.goto(routeUrl);

        await deleteViaModal(page, /\/admin\/webhooks(\?|$)/);

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

        // the script-variables (env) ACE editor lives on this page now
        await expect(page.locator('#editor-env .ace_content')).toBeAttached();

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
        await expect(page.locator('h1', { hasText: 'SMTP Server' })).toBeVisible();
        await expect(page.locator('h1 .state-info')).toBeVisible();

        await page.locator('summary', { hasText: 'Integration Examples' }).click();
        await expect(page.locator('#example-nodemailer-code')).toContainText('createTransport');
        await expectSelectedTab(page, 'example-nodemailer-tab', ['example-phpmailer-tab']);
        await page.locator('#example-phpmailer-tab').click();
        await expect(page.locator('#example-phpmailer')).toBeVisible();
        await expect(page.locator('#example-phpmailer-code')).toContainText('PHPMailer');
        await expectSelectedTab(page, 'example-phpmailer-tab', ['example-nodemailer-tab']);

        // editing the port re-renders the examples
        await page.fill('#smtpServerPort', '3535');
        await page.locator('#smtpServerPort').dispatchEvent('change');
        await expect(page.locator('#example-phpmailer-code')).toContainText('3535');

        // the reveal and copy buttons are disabled while the password field is
        // empty and enable as soon as a value is typed (ui.js .secret-field)
        await expect(page.locator('#showPassword')).toBeDisabled();
        await expect(page.locator('.secret-field .copy-btn')).toBeDisabled();
        await page.fill('#smtpServerPassword', 'e2e-secret');
        await expect(page.locator('#showPassword')).toBeEnabled();
        await expect(page.locator('.secret-field .copy-btn')).toBeEnabled();
        await expectPasswordToggle(page, 'showPassword', 'smtpServerPassword');

        // the copy button puts the secret on the clipboard without revealing it
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await page.locator('.secret-field .copy-btn').click();
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('e2e-secret');

        // the listen-address input gets native datalist suggestions (uiDatalist)
        await expect(page.locator('#smtpServerHost')).toHaveAttribute('list', 'available-addresses-list');
        expect(await page.locator('#available-addresses-list option').count()).toBeGreaterThan(0);

        await expectTlsLabelTooltip(page);

        // hovering an errorless state badge must not show a bubble; the gate
        // is ee-tooltip-empty on the wrapper, since HSTooltip's show() strips
        // the hidden class from the content on hover
        await page.locator('.state-info[data-type="smtp"]').hover();
        await page.waitForTimeout(300);
        await expect(page.locator('.tooltip.show .tooltip-content')).not.toBeVisible();
        await page.mouse.move(0, 0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config smtp: TLS provisioning is gated on a usable service domain', async ({ page, request }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const token = await createApiToken(page, 'e2e tls-gate token');
        const auth = { Authorization: `Bearer ${token}` };

        const orig = await (await request.get('/v1/settings?serviceUrl=true', { headers: auth })).json();
        // the TLS card is duplicated on both server config pages; gate both
        const pages = [
            { path: '/admin/config/smtp', box: '#smtpServerTLSEnabled' },
            { path: '/admin/config/imap-proxy', box: '#imapProxyServerTLSEnabled' }
        ];

        try {
            // without a usable domain the TLS checkbox must not be operable
            // and must carry no domain for the cert-provisioning flow (it
            // once rendered data-domain="false" - the string is truthy, so
            // the flow tried to provision a certificate for "false")
            const cleared = await request.post('/v1/settings', { headers: auth, data: { serviceUrl: '' } });
            expect(cleared.ok(), `POST /v1/settings -> ${cleared.status()}`).toBeTruthy();

            for (const { path: pagePath, box } of pages) {
                await page.goto(pagePath);
                await expect(page.locator(box)).toBeDisabled();
                expect(await page.locator(box).getAttribute('data-domain')).toBe(null);
            }
        } finally {
            const restored = await request.post('/v1/settings', { headers: auth, data: { serviceUrl: orig.serviceUrl || '' } });
            expect(restored.ok(), `restore serviceUrl -> ${restored.status()}`).toBeTruthy();
        }

        // with the domain back the checkboxes are operable and carry it again
        for (const { path: pagePath, box } of pages) {
            await page.goto(pagePath);
            await expect(page.locator(box)).toBeEnabled();
            expect(await page.locator(box).getAttribute('data-domain')).toBeTruthy();
        }

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
        await expectPasswordToggle(page, 'showPassword', 'imapProxyServerPassword');

        // the listen-address input gets native datalist suggestions (uiDatalist)
        await expect(page.locator('#imapProxyServerHost')).toHaveAttribute('list', 'available-addresses-list');
        expect(await page.locator('#available-addresses-list option').count()).toBeGreaterThan(0);

        await expectTlsLabelTooltip(page);

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
        await expectModalOpen(page, 'setPayloadModal');
        await page.keyboard.press('Escape');
        await expect(page.locator('#setPayloadModal.open')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config service: language override details and queue cleanup toast', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/service');
        await expect(page.locator('h1', { hasText: 'General' })).toBeVisible();

        await page.locator('#languageDetails summary').click();
        await expect(page.locator('#languageDetails .alert')).toBeVisible();

        // clear-completed-jobs posts to the server and reports through a toast
        await page.locator('#clean-queues-btn').click();
        await expect(page.locator('#toastContainer .alert', { hasText: 'Cleanup request sent' })).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config forms: a validation error keeps the submitted values and the menu highlight', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // the content-size field takes free text ("1MB"), so an invalid value reaches
        // the server-side Joi validation instead of being blocked by the browser
        await page.goto('/admin/config/webhooks');
        const sizeField = page.locator('#settingsNotifyTextSize');
        const origSize = await sizeField.inputValue();
        await sizeField.fill('not-a-size');
        await page.getByRole('button', { name: 'Save Changes' }).click();

        await expect(page.locator('.flash-alert', { hasText: "Couldn't save settings" })).toBeVisible();
        // the submitted value stays in the field instead of resetting to the stored one
        await expect(sizeField).toHaveValue('not-a-size');
        // and the sidebar still highlights the page being edited
        await expect(page.locator('#menu-config .menu-active', { hasText: 'Webhooks' })).toBeVisible();

        // restore and confirm the form still saves
        await sizeField.fill(origSize);
        await page.getByRole('button', { name: 'Save Changes' }).click();
        await expect(page.locator('.flash-alert', { hasText: 'Configuration updated' })).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config security: status badges and service secret reveal', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/security');
        await expect(page.locator('h1', { hasText: 'Security' })).toBeVisible();
        await expect(page.locator('#enableTokens')).toBeVisible();
        await expect(page.locator('#encryption')).toBeDisabled();

        await expectPasswordToggle(page, 'showServiceSecret', 'settingsServiceSecret');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config email-processing: form renders with effective export defaults', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/email-processing');
        await expect(page.locator('h1', { hasText: 'Email Processing' })).toBeVisible();
        await expect(page.locator('#settingsImapIndexer')).toBeVisible();
        await expect(page.locator('#trackOpens')).toBeVisible();
        // the export batch inputs render the effective defaults (they were
        // dead fields before the page split - never loaded, silently dropped)
        await expect(page.locator('#settingsGmailExportBatchSize')).toHaveValue(/^\d+$/);
        await expect(page.locator('#settingsOutlookExportBatchSize')).toHaveValue(/^\d+$/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config branding: ACE editors and public-page preview form', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/branding');
        await expect(page.locator('h1', { hasText: 'Branding' })).toBeVisible();
        await expect(page.locator('#editor-html .ace_content')).toBeAttached();
        await expect(page.locator('#editor-html-head .ace_content')).toBeAttached();
        await expect(page.locator('#settingsPageBrandName')).toBeVisible();
        await expect(page.locator('#preview-header-btn')).toBeVisible();

        // the ACE editors follow the admin theme: toggling swaps in the dark
        // theme (ace marks the container with ace_dark) and back again
        const editorIsDark = id => page.evaluate(id => document.getElementById(id).classList.contains('ace_dark'), id);
        const startedDark = await page.evaluate(() => window.uiEffectiveTheme() === 'dark');
        await expect.poll(() => editorIsDark('editor-html')).toBe(startedDark);
        await page.locator('.theme-toggle-btn').first().click();
        await expect.poll(() => editorIsDark('editor-html')).toBe(!startedDark);
        await expect.poll(() => editorIsDark('editor-html-head')).toBe(!startedDark);
        await page.locator('.theme-toggle-btn').first().click();
        await expect.poll(() => editorIsDark('editor-html')).toBe(startedDark);

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
        await expect(page.locator('h1', { hasText: 'OAuth2 Apps' })).toBeVisible();
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

        // the service-account form carries its own auth-method tab strip (not a
        // FlyonUI data-tabs instance): it marks the selection and swaps sections
        await page.goto('/admin/config/oauth/new?provider=gmailService');
        await expectSelectedTab(page, 'auth-method-tab-serviceKey', ['auth-method-tab-externalAccount']);
        await expect(page.locator('.auth-method-section-externalAccount').first()).toBeHidden();
        await page.locator('#auth-method-tab-externalAccount').click();
        await expectSelectedTab(page, 'auth-method-tab-externalAccount', ['auth-method-tab-serviceKey']);
        await expect(page.locator('.auth-method-section-externalAccount').first()).toBeVisible();
        await expect(page.locator('.auth-method-section-serviceKey').first()).toBeHidden();

        await page.goto('/admin/config/oauth/new?provider=gmail');
        await page.locator('#baseScopesImap').check();
        await page.fill('#name', 'E2E OAuth App');
        await page.fill('#clientId', '1234567890-e2e.apps.googleusercontent.com');
        await page.fill('#clientSecret', 'GOCSPX-e2e-dummy');
        await page.locator('button[type="submit"]', { hasText: 'Register app' }).click();
        await page.waitForURL(/\/admin\/config\/oauth\/app\//);

        // detail page: the join-variant ui/copy-field copies the provider ID
        await expect(page.locator('#appIdValue')).toBeVisible();
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await page.locator('.copy-btn').click();
        const appId = await page.locator('#appIdValue').inputValue();
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(appId);

        // verify-setup modal auto-runs the configuration checks
        await page.locator('#verify-btn').click();
        await expectModalOpen(page, 'verifySetupModal');
        // the run finishes (dummy credentials, so the verdict may report failures)
        await page.waitForFunction(() => !document.getElementById('verify-run-btn').disabled);
        expect(await page.locator('#verify-steps li').count()).toBeGreaterThan(0);
        await page.keyboard.press('Escape');
        await expect(page.locator('#verifySetupModal.open')).toHaveCount(0);

        await deleteViaModal(page, /\/admin\/config\/oauth(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('document store: settings, chat modal, mappings and pre-processing editors', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // the deprecated-feature gate is opened for e2e via
        // EENGINE_DOCUMENT_STORE_ENABLED in playwright.config.js
        await page.goto('/admin/config/document-store');
        await expect(page.locator('h1', { hasText: 'Document Store' })).toBeVisible();
        await expect(page.getByText('Deprecation Notice')).toBeVisible();
        await expect(page.locator('#documentStoreUrl')).toBeVisible();

        // chat page: try-it modal resets and reports errors through the hidden toggles
        await page.goto('/admin/config/document-store/chat');
        await page.locator('#try-chat-btn').click();
        await expectModalOpen(page, 'tryChatModal');
        await page.fill('#inputAccount', 'no-such-account');
        await page.fill('#question', 'anything?');
        await page.locator('#send-question-btn').click();
        await expect(page.locator('#chat-error')).toBeVisible({ timeout: 15000 });
        // close via the button: the failed request disabled/re-enabled the
        // submit button, which drops focus to <body>, and FlyonUI only closes
        // on Escape while focus is inside the overlay
        await page.locator('#tryChatModal button', { hasText: 'Close' }).click();
        await expect(page.locator('#tryChatModal.open')).toHaveCount(0);

        // mappings: built-in list renders, new-mapping confirmation modal opens
        await page.goto('/admin/config/document-store/mappings');
        expect(await page.locator('tbody tr').count()).toBeGreaterThan(5);
        await page.goto('/admin/config/document-store/mappings/new');
        await page.fill('#field', 'e2e_field');
        await page.locator('button', { hasText: 'Add mapping' }).first().click();
        await expect(page.locator('#submitModal.open')).toHaveCount(1);
        await page.keyboard.press('Escape');
        await expect(page.locator('#submitModal.open')).toHaveCount(0);

        // pre-processing: ACE editors + live filter evaluation via the worker
        await page.goto('/admin/config/document-store/pre-processing');
        await expect(page.locator('#editor-fn .ace_content')).toBeAttached();
        await page.evaluate(() => window.ace.edit('editor-fn').setValue('return true;'));
        await expect(page.locator('#filter-res')).toHaveText('filter matches');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('internals: thread table with restart and snapshot modals', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/internals');
        await expect(page.locator('h1', { hasText: 'Workers' })).toBeVisible();
        expect(await page.locator('tbody tr').count()).toBeGreaterThan(3);

        // row actions live in a per-row kebab (ui/row-actions) now: open the row's
        // menu, then the item fills the hidden thread input and opens the modal. Retry
        // the open-then-click since the dropdown can close on its own (animations).
        const openRowActionAndClick = async itemLocator => {
            const toggle = itemLocator.locator('xpath=ancestor::tr[1]').locator('button[aria-label="Worker actions"]');
            await expect(async () => {
                if (!(await itemLocator.isVisible())) {
                    await toggle.click();
                    await expect(itemLocator).toBeVisible({ timeout: 2000 });
                }
                await itemLocator.click({ timeout: 2000 });
            }).toPass({ timeout: 15000 });
        };

        await openRowActionAndClick(page.locator('.snapshot-thread-btn').first());
        await expect(page.locator('#snapshotThread.open')).toHaveCount(1);
        expect(await page.evaluate(() => document.getElementById('snapshot-thread').value)).not.toBe('');
        await page.keyboard.press('Escape');
        await expect(page.locator('#snapshotThread.open')).toHaveCount(0);

        // the kill/restart action only renders for non-main threads
        const killBtn = page.locator('.kill-thread-btn').first();
        const killThread = await killBtn.getAttribute('data-thread');
        await openRowActionAndClick(killBtn);
        await expect(page.locator('#killThread.open')).toHaveCount(1);
        expect(await page.evaluate(() => document.getElementById('kill-thread').value)).toBe(killThread);
        await page.keyboard.press('Escape');
        await expect(page.locator('#killThread.open')).toHaveCount(0);

        // thread detail page: follow an accounts-count link when an account is
        // assigned; otherwise open an IMAP worker thread ("Email worker" row)
        // and assert the empty branch. Late in a full-suite run the IMAP
        // worker may no longer be listed (pre-existing e2e-environment
        // behaviour, unrelated to the theme) - then assert the route guard
        // instead: thread URLs for non-IMAP threads redirect to the list.
        const threadLink = page.locator('tbody a[href^="/admin/internals/thread/"]').first();
        const imapRow = page.locator('tbody tr', { hasText: 'Email worker' }).first();
        if (await threadLink.count()) {
            await threadLink.click();
            await page.waitForURL(/\/admin\/internals\/thread\//);
            await expect(page.locator('.state-info').first()).toBeVisible();
            await expect(page.locator('h1', { hasText: 'Accounts' })).toBeVisible();
            await expect(page.getByText('Total Accounts:')).toBeVisible();
        } else if (await imapRow.count()) {
            const imapThread = await imapRow.locator('.kill-thread-btn').getAttribute('data-thread');
            await page.goto(`/admin/internals/thread/${imapThread}`);
            await expect(page.getByText('No accounts assigned to this thread.')).toBeVisible();
            await expect(page.locator('h1', { hasText: 'Accounts' })).toBeVisible();
            await expect(page.getByText('Total Accounts:')).toBeVisible();
        } else {
            await page.goto(`/admin/internals/thread/${killThread}`);
            await page.waitForURL(/\/admin\/internals(\?|$)/);
        }

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('public pages: index and license render under the main layout', async ({ page, browser }) => {
        // both routes are unauthenticated; use a clean context to prove that
        const context = await browser.newContext({ storageState: undefined });
        const anonPage = await context.newPage();
        const errors = trackConsoleErrors(anonPage);

        await anonPage.goto('/');
        await expect(anonPage.locator('img[alt="EmailEngine"]')).toBeVisible();
        await expect(anonPage.locator('a.btn', { hasText: 'Manage EmailEngine' })).toBeVisible();
        await expect(anonPage.getByText(/Postal Systems/)).toBeVisible();

        await anonPage.goto('/license.html');
        await expect(anonPage.locator('img[alt="EmailEngine"]')).toBeVisible();
        expect((await anonPage.locator('body').textContent()).length).toBeGreaterThan(500);

        expect(errors, errors.join('\n')).toHaveLength(0);
        await context.close();
    });

    test('account security: status rows and 2FA/logout modals', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/account/security');
        await expect(page.locator('h1', { hasText: 'Account Security' })).toBeVisible();
        // auth is enabled on the e2e instance, so all status rows render
        expect(await page.locator('.card ul > li').count()).toBeGreaterThanOrEqual(4);

        // open and close the confirmation modals without submitting
        await page.locator('#logout-all-btn').click();
        await expectModalOpen(page, 'logoutAllModal');
        await page.keyboard.press('Escape');
        await expect(page.locator('#logoutAllModal.open')).toHaveCount(0);

        await page.locator('#enable-tfa-btn').click();
        await expect(page.locator('#enableTfaModal.open')).toHaveCount(1);
        await expect(page.locator('#enableTfaModal img[alt="TOTP QR code"]')).toBeVisible();
        await page.keyboard.press('Escape');
        await expect(page.locator('#enableTfaModal.open')).toHaveCount(0);

        // password page renders its form
        await page.goto('/admin/account/password');
        await expect(page.locator('#password')).toBeVisible();
        await expect(page.locator('#password2')).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('state badge: connection error shows in the FlyonUI tooltip', async ({ page, request }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const token = await createApiToken(page, 'e2e state-badge token');
        const auth = { Authorization: `Bearer ${token}` };
        const ACCOUNT_ID = 'e2e-bad-auth';

        // an account with intentionally wrong IMAP credentials fails auth fast
        // and deterministically, driving its badge into the error state (via
        // SSE repaint while the list is open, or the server render if the
        // failure lands first - both paths feed the same ui/state-badge)
        await request.delete(`/v1/account/${ACCOUNT_ID}`, { headers: auth }).catch(() => {});
        const res = await request.post('/v1/account', {
            headers: auth,
            data: {
                account: ACCOUNT_ID,
                name: 'E2E Bad Auth',
                email: 'e2e-bad-auth@ethereal.email',
                imap: {
                    host: 'imap.ethereal.email',
                    port: 993,
                    secure: true,
                    auth: { user: 'e2e-nonexistent@ethereal.email', pass: 'wrong-password' }
                }
            }
        });
        expect(res.ok(), `POST /v1/account -> ${res.status()} ${await res.text()}`).toBeTruthy();

        try {
            await page.goto('/admin/accounts');
            const badge = page.locator(`.state-info[data-account="${ACCOUNT_ID}"]`);
            await expect(badge).toBeVisible();

            await expect(badge).toHaveText(/Connection failed/, { timeout: 90000 });
            await expect(badge).toHaveClass(/badge-error/);

            // the error text lands in the tooltip body and the content unhides
            const wrap = page.locator(`.tooltip:has(.state-info[data-account="${ACCOUNT_ID}"])`);
            await expect(wrap).not.toHaveClass(/ee-tooltip-empty/);
            expect((await wrap.locator('.tooltip-body').textContent()).trim()).not.toBe('');

            await expectTooltipOnHover(page, badge);

            // the failing account rolls up into the dashboard "Needs attention"
            // card (the connections gauge refreshes on the metrics interval, so
            // poll across reloads) and its link opens the combined errors filter
            await expect
                .poll(
                    async () => {
                        await page.goto('/admin');
                        let value = await page.locator('.card', { hasText: 'Needs attention' }).locator('.text-xl').textContent();
                        return Number(value.trim()) || 0;
                    },
                    { timeout: 60000 }
                )
                .toBeGreaterThan(0);

            const attentionLink = page.getByRole('link', { name: 'Needs attention' });
            await expect(attentionLink).toHaveAttribute('href', '/admin/accounts?state=errors');
            await attentionLink.click();
            await page.waitForURL(/\/admin\/accounts\?state=errors/);
            await expect(page.locator(`.state-info[data-account="${ACCOUNT_ID}"]`)).toBeVisible();
            await expect(page.locator('#search-state-dropdown')).toHaveText(/Needs attention/);

            await page.goto('/admin/accounts');
            await expect(badge).toBeVisible();

            // live SSE repaint: watch the badge for DOM mutations, then force
            // a state change server-side - the /admin/changes EventSource must
            // repaint the badge with no page reload involved
            await page.evaluate(id => {
                window.__badgeMutations = 0;
                const badgeElm = document.querySelector(`.state-info[data-account="${id}"]`);
                // attributeFilter: the tooltip teardown from the hover above
                // mutates the badge's style attribute asynchronously; the SSE
                // repaint always touches class/children, never style
                new window.MutationObserver(() => window.__badgeMutations++).observe(badgeElm, {
                    childList: true,
                    characterData: true,
                    attributeFilter: ['class'],
                    subtree: true
                });
            }, ACCOUNT_ID);
            const reconnect = await request.put(`/v1/account/${ACCOUNT_ID}/reconnect`, {
                headers: auth,
                data: { reconnect: true }
            });
            expect(reconnect.ok(), `PUT reconnect -> ${reconnect.status()}`).toBeTruthy();
            await expect.poll(() => page.evaluate(() => window.__badgeMutations), { timeout: 30000 }).toBeGreaterThan(0);
        } finally {
            // wait out the async teardown - a mid-deletion account transiently
            // 404s account lookups on the internals thread pages
            await request.delete(`/v1/account/${ACCOUNT_ID}`, { headers: auth });
            await expect.poll(async () => (await request.get(`/v1/account/${ACCOUNT_ID}`, { headers: auth })).status(), { timeout: 15000 }).toBe(404);
        }

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('config pages: every settings form saves and reports through a flash alert', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // idempotent save round-trip on every config page: the forms post their
        // rendered (persisted) values back, so nothing changes server-side
        const configPages = [
            '/admin/config/webhooks',
            '/admin/config/service',
            '/admin/config/security',
            '/admin/config/email-processing',
            '/admin/config/branding',
            '/admin/config/logging',
            '/admin/config/network',
            '/admin/config/smtp',
            '/admin/config/imap-proxy',
            '/admin/config/ai'
        ];
        for (const configPath of configPages) {
            await page.goto(configPath);
            await page.getByRole('button', { name: 'Save Changes' }).click();
            const flash = page.locator('.flash-alert', { hasText: 'Configuration updated' });
            await expect(flash, `${configPath} save`).toBeVisible({ timeout: 15000 });
            // the close button removes the alert (ui.js .flash-alert-close handler);
            // wait for ui.js to have executed before relying on its binding
            await page.waitForFunction(() => typeof window.uiDismissFade === 'function');
            await flash.locator('.flash-alert-close').click();
            await expect(flash, `${configPath} flash close`).toHaveCount(0);
        }

        // a changed value actually persists across the redirect
        await page.goto('/admin/config/logging');
        const maxLines = page.locator('#settingsLogsMaxLogLines');
        const origLines = await maxLines.inputValue();
        await maxLines.fill('12345');
        await page.getByRole('button', { name: 'Save Changes' }).click();
        await expect(page.locator('.flash-alert', { hasText: 'Configuration updated' })).toBeVisible();
        await expect(maxLines).toHaveValue('12345');
        await maxLines.fill(origLines);
        await page.getByRole('button', { name: 'Save Changes' }).click();
        await expect(maxLines).toHaveValue(origLines);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('gateways: edit page prefills and updates', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/gateways/new');
        await page.fill('#gateway', 'e2e-edit-gw');
        await page.fill('#name', 'E2E Edit Gateway');
        await page.fill('#host', '127.0.0.1');
        await page.fill('#port', '2525');
        await page.locator('button[type="submit"]', { hasText: 'Create Gateway' }).click();
        await page.waitForURL(/\/admin\/gateways\/gateway\//);

        await page.goto('/admin/gateways/edit/e2e-edit-gw');
        await expect(page.locator('#name')).toHaveValue('E2E Edit Gateway');
        await expect(page.locator('#host')).toHaveValue('127.0.0.1');
        await page.fill('#name', 'E2E Edited Gateway');
        await page.getByRole('button', { name: 'Save Changes' }).click();
        await page.waitForURL(/\/admin\/gateways\/gateway\//);
        await expect(page.getByRole('heading', { name: 'E2E Edited Gateway' })).toBeVisible();

        await deleteViaModal(page, /\/admin\/gateways(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('templates: edit page prefills the ACE editors and updates', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/templates/new');
        await page.fill('#inputName', 'E2E Edit Template');
        await page.fill('#inputSubject', 'e2e edit subject');
        await page.locator('button[type="submit"]', { hasText: 'Create template' }).click();
        await page.waitForURL(/\/admin\/templates\/template\//);
        const detailUrl = new URL(page.url()).pathname;

        await page.goto(`${detailUrl}/edit`);
        await expect(page.locator('#inputName')).toHaveValue('E2E Edit Template');
        await expect(page.locator('#inputSubject')).toHaveValue('e2e edit subject');
        await expect(page.locator('#editor-html .ace_content')).toBeAttached();
        await page.fill('#inputName', 'E2E Edited Template');
        await page.locator('button[type="submit"]', { hasText: 'Update template' }).click();
        await page.waitForURL(new RegExp(`${detailUrl.replace(/[/]/g, '\\/')}(\\?|$)`));
        await expect(page.getByRole('heading', { name: 'E2E Edited Template' })).toBeVisible();

        await deleteViaModal(page, /\/admin\/templates(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('webhooks: edit page prefills the editors and updates', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/webhooks/new');
        await page.fill('#inputName', 'E2E Edit Route');
        await page.fill('#inputTargetUrl', 'https://example.com/e2e-edit-webhook');
        await page.locator('button[type="submit"]', { hasText: 'Create routing' }).click();
        await page.waitForURL(/\/admin\/webhooks\/webhook\//);
        const detailUrl = new URL(page.url()).pathname;

        await page.goto(`${detailUrl}/edit`);
        await expect(page.locator('#inputName')).toHaveValue('E2E Edit Route');
        await expect(page.locator('#inputTargetUrl')).toHaveValue('https://example.com/e2e-edit-webhook');
        await expect(page.locator('#editor-fn .ace_content')).toBeAttached();
        await page.fill('#inputName', 'E2E Edited Route');
        await page.locator('button[type="submit"]', { hasText: 'Update webhook' }).click();
        await page.waitForURL(new RegExp(`${detailUrl.replace(/[/]/g, '\\/')}(\\?|$)`));
        await expect(page.getByRole('heading', { name: 'E2E Edited Route' })).toBeVisible();

        await deleteViaModal(page, /\/admin\/webhooks(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('oauth apps: edit page prefills and updates', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/oauth/new?provider=gmail');
        await page.locator('#baseScopesImap').check();
        await page.fill('#name', 'E2E OAuth Edit App');
        await page.fill('#clientId', '1234567890-e2e-edit.apps.googleusercontent.com');
        await page.fill('#clientSecret', 'GOCSPX-e2e-edit-dummy');
        await page.locator('button[type="submit"]', { hasText: 'Register app' }).click();
        await page.waitForURL(/\/admin\/config\/oauth\/app\//);
        const appId = await page.locator('#appIdValue').inputValue();

        await page.goto(`/admin/config/oauth/edit/${appId}`);
        await expect(page.locator('#name')).toHaveValue('E2E OAuth Edit App');
        await expect(page.locator('#clientId')).toHaveValue('1234567890-e2e-edit.apps.googleusercontent.com');
        await page.fill('#name', 'E2E OAuth Edited App');
        await page.locator('button[type="submit"]', { hasText: 'Update app' }).click();
        await page.waitForURL(/\/admin\/config\/oauth\/app\//);
        await expect(page.getByRole('heading', { name: 'E2E OAuth Edited App' })).toBeVisible();

        await deleteViaModal(page, /\/admin\/config\/oauth(\?|$)/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('tokens: delete flow actually removes the token', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await createApiToken(page, 'e2e delete-me token');
        await dismissTokenReveal(page);

        const row = page.locator('tbody tr', { hasText: 'e2e delete-me token' }).first();
        await row.locator('.dropdown-toggle').click();
        await row.locator('.list-delete-btn').click();
        await expect(page.locator('#deleteToken.open')).toHaveCount(1);
        await page.locator('#deleteToken button[type="submit"]').click();
        await page.waitForURL(/\/admin\/tokens(\?|$)/);
        await expect(page.locator('.flash-alert')).toBeVisible();
        await expect(page.locator('tbody tr', { hasText: 'e2e delete-me token' })).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('tokens: list paginates once it outgrows one page', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // 25 root tokens through the same endpoint the UI uses (page size is 20)
        const created = await page.evaluate(async () => {
            const crumb = document.getElementById('crumb').value;
            const tokens = [];
            for (let i = 0; i < 25; i++) {
                const res = await fetch('/admin/tokens/new', {
                    method: 'post',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ crumb, description: `e2e page filler ${i}`, scopes: ['api'], account: '' })
                });
                const data = await res.json();
                if (data && data.token) {
                    tokens.push(data.token);
                }
            }
            return tokens;
        });
        expect(created.length).toBe(25);

        const bearer = await createApiToken(page, 'e2e pagination cleanup token');
        await dismissTokenReveal(page);
        const api = await request.newContext({
            baseURL: BASE_URL,
            extraHTTPHeaders: { Authorization: `Bearer ${bearer}` }
        });

        try {
            await page.goto('/admin/tokens');
            const pager = page.locator('.join', { has: page.locator('.btn', { hasText: '2' }) }).last();
            await expect(pager).toBeVisible();
            await pager.locator('.btn', { hasText: '2' }).click();
            await page.waitForURL(/[?&]page=2/);
            expect(await page.locator('tbody tr').count()).toBeGreaterThan(0);
        } finally {
            await Promise.all(created.map(tok => api.delete(`/v1/token/${tok}`).catch(() => {})));
            await api.dispose();
        }

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('account edit: rename round-trip and folder-path datalist', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');

        await page.goto(`${url}/edit`);
        const nameField = page.locator('#name');
        const origName = await nameField.inputValue();

        // the Sent Mail folder input carries native datalist suggestions built
        // from the account's real folder listing (uiDatalist)
        await expect(page.locator('#imap_sentMailPath')).toHaveAttribute('list', 'available-paths-list');
        expect(await page.locator('#available-paths-list option').count()).toBeGreaterThan(0);

        await nameField.fill('E2E Renamed Account');
        await page.getByRole('button', { name: 'Update account' }).click();
        await page.waitForURL(u => u.pathname === url);
        await expect(page.getByText('E2E Renamed Account').first()).toBeVisible();

        await page.goto(`${url}/edit`);
        await page.locator('#name').fill(origName);
        await page.getByRole('button', { name: 'Update account' }).click();
        await page.waitForURL(u => u.pathname === url);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('account detail: reconnect, sync, logs toggle/flush and logs download', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');
        await page.goto(url);

        const toast = text => page.locator('#toastContainer .alert', { hasText: text });

        // reconnect + sync both POST with the layout crumb and report via toast
        const [reconnectRes] = await Promise.all([
            page.waitForResponse(r => r.url().includes('/reconnect') && r.request().method() === 'POST'),
            page.locator('#request-reconnect').click()
        ]);
        expect(reconnectRes.ok()).toBeTruthy();
        await expect(toast('Account reconnection requested')).toBeVisible();

        const [syncRes] = await Promise.all([
            page.waitForResponse(r => r.url().includes('/sync') && r.request().method() === 'POST'),
            page.locator('#request-sync').click()
        ]);
        expect(syncRes.ok()).toBeTruthy();
        await expect(toast('Account sync requested')).toBeVisible();

        // logs controls are consolidated into the toolbar "Logs" dropdown (#logs-info):
        // enable logging, flush, then restore. Tie each action to its POST response
        // rather than the auto-dismissing toast, and retry the open-then-click since the
        // dropdown can close on its own between opening and the item click (animations).
        const clickLogsItem = async (id, pathRe) => {
            await expect(async () => {
                if (!(await page.locator(id).isVisible())) {
                    await page.locator('#logs-info').click();
                    await expect(page.locator(id)).toBeVisible({ timeout: 2000 });
                }
                const [res] = await Promise.all([
                    page.waitForResponse(r => r.request().method() === 'POST' && pathRe.test(new URL(r.url()).pathname), { timeout: 4000 }),
                    page.locator(id).click({ timeout: 2000 })
                ]);
                expect(res.ok(), `${id} -> ${res.status()}`).toBeTruthy();
            }).toPass({ timeout: 30000 });
        };

        await clickLogsItem('#toggle-logs', /\/logs$/);
        await expect(toast('Logging settings updated')).toBeVisible();

        await clickLogsItem('#flush-logs', /\/logs-flush$/);
        await expect(toast('Stored logs were flushed')).toBeVisible();

        // restore the original (disabled) logging state
        await clickLogsItem('#toggle-logs', /\/logs$/);

        // download last: the logs.txt GET rotates the CSRF crumb cookie, so a
        // crumb-protected POST issued afterwards from this already-rendered page
        // (whose #crumb is now stale) would 403.
        const logsRes = await page.request.get(`${url}/logs.txt`);
        expect(logsRes.ok(), `logs.txt -> ${logsRes.status()}`).toBeTruthy();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('account detail: export flow completes and serves the download', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');
        await page.goto(url);

        await page.locator('#request-export').click();
        await expectModalOpen(page, 'exportModal');
        // the date range is required (the start handler toasts and bails without it)
        await page.fill('#export-start-date', '2020-01-01');
        await page.fill('#export-end-date', '2030-12-31');
        await page.locator('#export-start-btn').click();

        // the modal switches to the status view and polls until completion
        await expect(page.locator('#export-status-view')).toBeVisible({ timeout: 15000 });
        await expect(page.locator('#export-status-badge')).toHaveText(/Completed/i, { timeout: 120000 });

        const downloadHref = await page.locator('#export-download-link').getAttribute('href');
        expect(downloadHref).toBeTruthy();
        const dl = await page.request.get(downloadHref);
        expect(dl.ok(), `export download -> ${dl.status()}`).toBeTruthy();

        // close via the corner button: FlyonUI ignores Escape while focus sits
        // on <body>, which is where the fetch-driven button flow leaves it
        await page.locator('#exportModal [aria-label="Close"]').click();
        await expect(page.locator('#exportModal.open')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('topbar search: query and state filter narrow the accounts list', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);
        const url = await firstAccountUrl(page);
        test.skip(!url, 'no account registered (standalone run)');

        await page.goto('/admin/accounts');
        await page.locator('header form input[name="query"]').fill('e2e');
        await page.locator('header form button[type="submit"]').click();
        await page.waitForURL(/[?&]query=e2e/);
        await expect(page.getByText('Results for "e2e"')).toBeVisible();

        // the state dropdown navigates with the state filter applied
        await page.locator('#search-state-dropdown').click();
        await page.locator('.dropdown-item', { hasText: 'Connected' }).first().click();
        await page.waitForURL(/[?&]state=connected/);
        await expect(page.locator('#search-state-dropdown')).toContainText('Connected');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('add-account modal: submit redirects to the signed hosted form', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        // the redirect target is built from the public serviceUrl; bounce it
        // back to the local test server (the signed blob is host-independent)
        await page.route('https://e2e.emailengine.app/**', route => {
            const u = new URL(route.request().url());
            route.fulfill({ status: 302, headers: { location: `${BASE_URL}${u.pathname}${u.search}` } });
        });

        await page.goto('/admin/accounts');
        await page.locator('[data-overlay="#addAccount"]').first().click();
        await expect(page.locator('#addAccount.open')).toHaveCount(1);
        await page.fill('#account-name', 'E2E Modal Smoke');
        await page.locator('#addAccount button[type="submit"]').click();

        await page.waitForURL(/\/accounts\/new\?data=/);
        await expect(page.locator('form[action^="/accounts/new"]').first()).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('unknown admin path renders the themed error page with a 404', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const response = await page.goto('/admin/definitely-not-a-page');
        expect(response.status()).toBe(404);
        await expect(page.getByRole('heading', { name: 'Something went wrong' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();

        // the intentional 404 itself logs a resource error; anything else is a bug
        const unexpected = errors.filter(err => !/status of 404/.test(err));
        expect(unexpected, unexpected.join('\n')).toHaveLength(0);
    });

    test('mobile viewport: the sidebar opens as a drawer', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/admin');

        const dashboardLink = page.locator('#layout-sidebar').getByRole('link', { name: 'Dashboard' });
        await expect(dashboardLink).toBeHidden();

        await page.locator('header [data-overlay="#layout-sidebar"]').click();
        await expect(dashboardLink).toBeVisible();

        // the drawer's own close button dismisses it
        await page.locator('#layout-sidebar [data-overlay="#layout-sidebar"]').click();
        await expect(dashboardLink).toBeHidden();

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
