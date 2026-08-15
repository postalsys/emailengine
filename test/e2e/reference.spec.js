/* global document, window, navigator, getComputedStyle */
'use strict';

// E2E coverage for the server-rendered API reference (/admin/reference).
//
// This page has no client-side renderer: lib/api-reference/ turns the OpenAPI document
// into finished HTML on the server, and static/js/reference.js only adds deferred
// syntax highlighting, the sidebar filter and the try-it runner. The tests below check
// both halves - that every reference URL renders real content, and that the three
// pieces of browser behavior work.
//
// Every tag page is visited, so a schema shape that breaks the renderer (an unresolved
// $ref, a type the tree builder does not handle) fails here rather than in production.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run
// alphabetically with one worker, so the instance is already bootstrapped by the time
// this file runs; the helpers are idempotent either way).
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const os = require('os');
const path = require('path');
const { test, expect } = require('@playwright/test');
const { ensureAdminSession, createApiToken, trackConsoleErrors } = require('./helpers/bootstrap');

// One real login for the whole file, reused via storageState - logging in per test
// trips the login rate limiter (same pattern as pages-admin.spec.js).
const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-reference-state.json');

// A GET with no required parameters, so the try-it test can send a real request without
// inventing an account id.
const TRY_IT_TAG = 'stats';
const TRY_IT_OPERATION = 'getV1Stats';

test.describe('API reference', () => {
    test.use({ storageState: STATE_FILE });

    test.beforeAll(async ({ browser }) => {
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        await page.context().storageState({ path: STATE_FILE });
        await page.close();
    });

    test('landing page lists every endpoint group', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference');

        await expect(page.getByRole('heading', { name: 'API Reference', exact: true })).toBeVisible();

        // Getting-started block: base URL, counts and the spec link the page documents
        await expect(page.getByText('Base URL')).toBeVisible();
        await expect(page.getByRole('link', { name: '/swagger.json' })).toBeVisible();

        // One card per tag, and the sidebar lists the same tags
        const cards = page.locator('a[href^="/admin/reference/"]');
        expect(await cards.count()).toBeGreaterThan(10);

        expect(errors).toHaveLength(0);
    });

    test('side menu points at the reference and marks it active', async ({ page }) => {
        // The main menu's "API Reference" entry targets this page, not /admin/swagger,
        // and every reference URL has to light it up - the active state is the only
        // signal that the second navigation column belongs to that menu entry.
        await page.goto('/admin/reference');

        const entry = page.locator('#layout-sidebar').getByRole('link', { name: 'API Reference' });
        await expect(entry).toHaveAttribute('href', '/admin/reference');
        await expect(entry).toHaveClass(/menu-active/);

        // ...including the per-group pages
        await page.goto('/admin/reference/message');
        await expect(page.locator('#layout-sidebar').getByRole('link', { name: 'API Reference' })).toHaveClass(/menu-active/);
    });

    test('the group navigation renders as an attached second column', async ({ page }) => {
        // It must sit flush against the main sidebar (no gap, no card) and stick under
        // the topbar, otherwise it reads as a panel floating in the page instead of a
        // second level of the same menu.
        await page.setViewportSize({ width: 1440, height: 950 });
        await page.goto('/admin/reference/message');

        const geometry = await page.evaluate(() => {
            const rect = sel => {
                const el = document.querySelector(sel);
                return el ? el.getBoundingClientRect() : null;
            };
            const sidebar = rect('#layout-sidebar');
            const nav = rect('aside[aria-label="Section navigation"]');
            const topbar = rect('header');
            return nav && sidebar && topbar ? { navLeft: nav.left, sidebarRight: sidebar.right, navTop: nav.top, topbarBottom: topbar.bottom } : null;
        });

        expect(geometry).not.toBeNull();
        // flush against the sidebar and directly below the topbar (1px for rounding)
        expect(Math.abs(geometry.navLeft - geometry.sidebarRight)).toBeLessThanOrEqual(1);
        expect(Math.abs(geometry.navTop - geometry.topbarBottom)).toBeLessThanOrEqual(1);

        // and it stays there while the operations scroll past
        await page.evaluate(() => window.scrollTo(0, 1500));
        await page.waitForTimeout(200);
        const stuckTop = await page.evaluate(() => document.querySelector('aside[aria-label="Section navigation"]').getBoundingClientRect().top);
        expect(Math.abs(stuckTop - geometry.topbarBottom)).toBeLessThanOrEqual(1);
    });

    test('the group navigation collapses to a disclosure on a phone', async ({ page }) => {
        // Below lg there is no room for the column, and the strip it used to become showed
        // a fifth of the list inside its own scrollbar. The mechanism is the layout's
        // (views/layout/app.hbs + static/js/app.js); the reference is its only caller.
        const errors = trackConsoleErrors(page);

        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/admin/reference/message');

        const toggle = page.locator('#secondary-nav-toggle');
        const panel = page.locator('#secondary-nav-panel');
        const column = page.locator('aside[aria-label="Section navigation"]');

        await expect(toggle).toBeVisible();
        await expect(panel).toBeHidden();
        await expect(toggle).toContainText('Endpoints');
        // one row, so the page below it starts on the first screen
        expect((await column.boundingBox()).height).toBeLessThan(100);

        await toggle.click();
        await expect(panel).toBeVisible();
        await expect(toggle).toHaveAttribute('aria-expanded', 'true');

        // Opened it takes at most the screen, and scrolls itself past that. The filter is the
        // case that proves it: its 82 hits are several thousand pixels of rows, and without a
        // cap they push the page heading and every operation below the fold.
        const panelHeight = async () => (await panel.boundingBox()).height;
        expect(await panelHeight()).toBeLessThanOrEqual(844);

        await page.fill('#ref-filter', 'a');
        await expect(page.locator('#ref-filter-results')).toBeVisible();
        expect(await panelHeight()).toBeLessThanOrEqual(844);
        await page.fill('#ref-filter', '');

        // Escape puts it away from the keyboard, wherever the reader has scrolled to
        await page.keyboard.press('Escape');
        await expect(panel).toBeHidden();
        await toggle.click();
        await expect(panel).toBeVisible();

        // Tapping a group opens its endpoints in place. As a link it would load that group's
        // page and take the menu with it, which is the opposite of looking inside a group.
        const groupRow = slug => panel.locator(`#ref-tag-list a[href="/admin/reference/${slug}"]`);

        await groupRow('account').click();
        await expect(page.locator('#ref-ops-account')).toBeVisible();
        await expect(groupRow('account')).toHaveAttribute('aria-expanded', 'true');
        await expect(page).toHaveURL(/\/admin\/reference\/message$/);

        // one group at a time, so the menu cannot grow past the control that closes it - the
        // group the page is on gives way like any other
        await expect(page.locator('#ref-ops-message')).toBeHidden();
        await groupRow('mailbox').click();
        await expect(page.locator('#ref-ops-mailbox')).toBeVisible();
        await expect(page.locator('#ref-ops-account')).toBeHidden();

        // tapping the open one puts it away
        await groupRow('mailbox').click();
        await expect(page.locator('#ref-ops-mailbox')).toBeHidden();

        // an in-page jump closes the menu, so it is not left covering what was jumped to
        await groupRow('message').click();
        await panel.locator('.ee-ref-op-nav a').first().click();
        await expect(panel).toBeHidden();

        // the filter hotkey has to open the panel on its way to the field - focusing an input
        // inside a collapsed panel does nothing, and this is the width where an 82-endpoint
        // list needs the filter most (a narrow desktop window lands here too, with a keyboard)
        await page.keyboard.press('/');
        await expect(panel).toBeVisible();
        await expect(page.locator('#ref-filter')).toBeFocused();

        // Nothing a reader collapsed on a phone may strand the wide-screen column: the group
        // rows are plain links there, so a hidden active list would have no way back. Leave the
        // current group collapsed and another one open, then widen - the column has to come up
        // showing the group the page is on, and only that one.
        await groupRow('message').click();
        await expect(page.locator('#ref-ops-message')).toBeHidden();
        await groupRow('account').click();
        await expect(page.locator('#ref-ops-account')).toBeVisible();

        await page.setViewportSize({ width: 1440, height: 900 });
        await expect(toggle).toBeHidden();
        await expect(panel).toBeVisible();
        await expect(page.locator('#ref-ops-message')).toBeVisible();
        await expect(page.locator('#ref-ops-account')).toBeHidden();

        // ...and the rows announce the state the column is actually in: at this width the
        // group the page is on is the expanded one, whatever was tapped on a narrow screen
        await expect(groupRow('message')).toHaveAttribute('aria-expanded', 'true');
        await expect(groupRow('account')).toHaveAttribute('aria-expanded', 'false');

        // where the column is always on screen a group row is a plain link again - one click
        // to the group instead of two, and nothing to put away afterwards
        await groupRow('account').click();
        await expect(page).toHaveURL(/\/admin\/reference\/account$/);

        expect(errors).toHaveLength(0);
    });

    test('every endpoint group page renders its operations', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference');

        // Drive the walk from the rendered nav rather than a hardcoded list, so a tag
        // added to the API is covered automatically. The group rows are the ones that own an
        // operation list (aria-controls); the rows inside those lists link into a group's page
        // rather than to it.
        const slugs = await page.evaluate(() =>
            Array.from(document.querySelectorAll('#ref-tag-list a[aria-controls]')).map(link => link.getAttribute('href').split('/').pop())
        );

        expect(slugs.length).toBeGreaterThan(10);

        for (const slug of slugs) {
            const response = await page.goto(`/admin/reference/${slug}`);
            expect(response.status(), `GET /admin/reference/${slug}`).toBe(200);

            // Each page must render at least one operation with a method badge, a path
            // and a response tab strip - i.e. the model actually produced content
            const operations = page.locator('.ee-ref-op');
            expect(await operations.count(), `operations on /admin/reference/${slug}`).toBeGreaterThan(0);

            const first = operations.first();
            await expect(first.locator('.badge').first()).toBeVisible();
            await expect(first.locator('[role="tablist"]').first()).toBeVisible();
        }

        expect(errors).toHaveLength(0);
    });

    test('operation markup carries no duplicate element ids', async ({ page }) => {
        // A tag page renders the same partials once per operation, and the ui/* partials
        // fall back to whatever `id` resolves to in the surrounding context - so a missing
        // id="" at a call site silently emits the operation id several times over. Deep
        // links and every getElementById lookup break quietly when that happens.
        await page.goto('/admin/reference/message');

        const duplicates = await page.evaluate(() => {
            const counts = new Map();
            for (const el of document.querySelectorAll('[id]')) {
                counts.set(el.id, (counts.get(el.id) || 0) + 1);
            }
            return Array.from(counts.entries())
                .filter(([, count]) => count > 1)
                .map(([id, count]) => `${id} x${count}`);
        });

        expect(duplicates).toEqual([]);
    });

    test('unknown endpoint group returns 404', async ({ page }) => {
        const response = await page.goto('/admin/reference/not-a-real-group');
        expect(response.status()).toBe(404);
    });

    test('operation renders parameters, schema tree and examples', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/message');

        const operation = page.locator('#getV1AccountAccountMessageMessage');
        await expect(operation).toBeVisible();

        // Signature
        await expect(operation.getByText('/v1/account/{account}/message/{message}')).toBeVisible();
        await expect(operation.locator('.badge').first()).toHaveText('GET');

        // Path parameters with the joi constraints swagger-ui never displayed
        await expect(operation.getByRole('heading', { name: 'Path parameters' })).toBeVisible();
        await expect(operation.locator('.ee-ref-prop', { hasText: 'account' }).first()).toContainText('max 256 chars');

        // Response schema tree: nested properties render through the recursive partial
        const properties = operation.locator('.ee-ref-props .ee-ref-prop');
        expect(await properties.count()).toBeGreaterThan(10);

        // The example payload is what orients a reader, so it is open on arrival and sits
        // above the property tree rather than below it
        const example = operation.locator('details', { hasText: 'Example response' }).first();
        await expect(example).toBeVisible();
        await expect(example.locator('pre')).toBeVisible();

        const tree = operation.locator('#getV1AccountAccountMessageMessage-resp-200-schema');
        await expect(tree).toBeVisible();
        const exampleBox = await example.boundingBox();
        const treeBox = await tree.boundingBox();
        expect(exampleBox.y).toBeLessThan(treeBox.y);

        await example.locator('summary').click();
        await expect(example.locator('pre')).toBeHidden();

        expect(errors).toHaveLength(0);
    });

    test('a large schema can be filtered and expanded in place', async ({ page }) => {
        // The sidebar filter deliberately does not index response property names, so this is
        // the only way to reach a single field on a page rendering hundreds of rows.
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/account');

        const scope = page.locator('#getV1AccountAccount-resp-200-schema');
        const tools = page.locator('[data-schema-scope="getV1AccountAccount-resp-200-schema"]');

        await expect(tools).toBeVisible();

        // The 128-property response arrives collapsed to its top level rather than in full
        const shown = scope.locator('.ee-ref-prop:visible');
        const initial = await shown.count();
        expect(initial).toBeGreaterThan(10);
        expect(initial).toBeLessThan(60);

        // Filtering hides everything but the hit and the groups it is nested in, opening
        // whatever it was buried under
        await tools.locator('input').fill('expires');
        await expect(tools.locator('[data-schema-count]')).toContainText('match');
        const filtered = await shown.count();
        expect(filtered).toBeGreaterThan(0);
        expect(filtered).toBeLessThan(initial);

        // Clearing is a real undo, back to the server-rendered state
        await tools.locator('input').fill('');
        await expect(shown).toHaveCount(initial);

        // Expand all reaches the rows the budget left collapsed
        await tools.getByRole('button', { name: 'Expand all' }).click();
        expect(await shown.count()).toBeGreaterThan(initial);

        await tools.getByRole('button', { name: 'Collapse all' }).click();
        expect(await shown.count()).toBeLessThanOrEqual(initial);

        expect(errors).toHaveLength(0);
    });

    test('a flag parameter list renders as chips rather than a row each', async ({ page }) => {
        // GET /v1/settings takes 87 undocumented booleans that answer one question between
        // them; a row each was roughly 260 lines of page carrying no more information.
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/settings');

        const operation = page.locator('#getV1Settings');
        await expect(operation.getByText('Set any of these to')).toBeVisible();
        await expect(operation.getByRole('heading', { name: 'Query parameters' })).toBeVisible();

        // The names are still on the page, just not as 87 property rows
        const chips = operation.locator('.ee-chip', { hasText: 'webhooksEnabled' });
        await expect(chips.first()).toBeVisible();

        expect(errors).toHaveLength(0);
    });

    test('response and code sample tabs switch panels', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/message');

        const operation = page.locator('#getV1AccountAccountMessageMessage');

        // Responses: 200 is selected on load, clicking 404 swaps the panel
        await expect(operation.locator('#getV1AccountAccountMessageMessage-resp-200')).toBeVisible();
        await expect(operation.locator('#getV1AccountAccountMessageMessage-resp-404')).toBeHidden();
        await operation.locator('#getV1AccountAccountMessageMessage-resp-404-tab').click();
        await expect(operation.locator('#getV1AccountAccountMessageMessage-resp-404')).toBeVisible();
        await expect(operation.locator('#getV1AccountAccountMessageMessage-resp-200')).toBeHidden();

        // Code samples: curl is shown first, Python is reachable and gets highlighted
        // once visible (highlighting is deferred until a block enters the viewport)
        const curl = operation.locator('#getV1AccountAccountMessageMessage-sample-curl-code');
        await expect(curl).toContainText('curl -X GET');
        await expect(curl).toContainText('Authorization: Bearer $EMAILENGINE_TOKEN');

        await operation.locator('#getV1AccountAccountMessageMessage-sample-python-tab').click();
        const python = operation.locator('#getV1AccountAccountMessageMessage-sample-python-code');
        await expect(python).toContainText('import requests');
        await expect(python.locator('.hljs-keyword').first()).toBeVisible();

        expect(errors).toHaveLength(0);
    });

    test('sidebar filter narrows the endpoint list and restores it', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference');

        const tagList = page.locator('#ref-tag-list');
        const hits = page.locator('#ref-filter-results .ee-ref-hit:not(.hidden)');

        await expect(tagList).toBeVisible();

        await page.fill('#ref-filter', 'blocklist');
        await expect(tagList).toBeHidden();
        expect(await hits.count()).toBeGreaterThan(0);
        await expect(page.locator('#ref-filter-empty')).toBeHidden();

        // All terms must match, so a nonsense query empties the list
        await page.fill('#ref-filter', 'definitelynotanendpoint');
        await expect(hits).toHaveCount(0);
        await expect(page.locator('#ref-filter-empty')).toBeVisible();

        // Clearing restores the tag list
        await page.fill('#ref-filter', '');
        await expect(tagList).toBeVisible();
        await expect(page.locator('#ref-filter-results')).toBeHidden();

        expect(errors).toHaveLength(0);
    });

    test('deep link scrolls to the operation', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/message#putV1AccountAccountMessageMessage');

        const offset = await page.evaluate(() => {
            const el = document.getElementById('putV1AccountAccountMessageMessage');
            return el ? el.getBoundingClientRect().top : null;
        });

        expect(offset).not.toBeNull();
        // the scroller's own top inset parks the section just below the sticky topbar
        expect(offset).toBeLessThan(300);
        expect(offset).toBeGreaterThan(-50);

        expect(errors).toHaveLength(0);
    });

    test('the filter matches what an operation accepts, not just its path', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference');

        const hits = page.locator('#ref-filter-results .ee-ref-hit:not(.hidden)');

        // "mailMerge" appears in no path or summary - only as a request body property, which
        // is the whole point of indexing field names
        await page.fill('#ref-filter', 'mailmerge');
        await expect(hits).toHaveCount(1);
        await expect(hits.first()).toContainText('/v1/account/{account}/submit');

        // the match count is announced rather than only implied by the list length
        await expect(page.locator('#ref-filter-hint')).toContainText('1 endpoint');

        expect(errors).toHaveLength(0);
    });

    test('the filter can be driven from the keyboard alone', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference');

        // "/" focuses the field from anywhere on the page
        await page.locator('body').click();
        await page.keyboard.press('/');
        await expect(page.locator('#ref-filter')).toBeFocused();

        // ...and the slash itself is not typed into it
        await expect(page.locator('#ref-filter')).toHaveValue('');

        await page.keyboard.type('blocklist');
        await expect(page.locator('#ref-tag-list')).toBeHidden();

        // Down enters the result list, and Up from the first result returns to the field
        await page.keyboard.press('ArrowDown');
        const first = page.locator('#ref-filter-results .ee-ref-hit:not(.hidden) a').first();
        await expect(first).toBeFocused();
        await page.keyboard.press('ArrowUp');
        await expect(page.locator('#ref-filter')).toBeFocused();

        // Escape clears a filter rather than leaving the list narrowed
        await page.keyboard.press('Escape');
        await expect(page.locator('#ref-tag-list')).toBeVisible();
        await expect(page.locator('#ref-filter')).toHaveValue('');

        // Enter opens the top hit without touching the arrow keys. Navigating is the last
        // step on purpose: the next page's script binds its own key handling on load, and
        // racing that would make this test flaky rather than meaningful.
        await page.keyboard.type('blocklist');
        await page.keyboard.press('Enter');
        await expect(page).toHaveURL(/\/admin\/reference\/blocklists#/);

        expect(errors).toHaveLength(0);
    });

    test('the sidebar marks the operation being read as you scroll', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/account');

        const marked = page.locator('.ee-ref-op-nav a[aria-current]');

        // Something is marked from the start, without having to scroll first. The marker is
        // repainted on an animation frame, so every assertion here has to be a retrying one.
        await expect(marked).toHaveCount(1);
        await expect(marked).toHaveText('Get account info');

        // The marker has to actually LOOK marked. Asserting only the attribute hid a real bug:
        // the styling first lived in a components-layer rule, which loses to the
        // text-base-content/70 utility on the same element, so the colour silently never applied.
        const [markedColor, plainColor] = await Promise.all([
            marked.evaluate(el => getComputedStyle(el).color),
            page
                .locator('.ee-ref-op-nav a:not([aria-current])')
                .first()
                .evaluate(el => getComputedStyle(el).color)
        ]);
        expect(markedColor).not.toBe(plainColor);

        // Scroll to a specific operation and the sidebar should follow it
        const target = 'getV1AccountAccountOauthtoken';
        await page.locator(`#${target}`).scrollIntoViewIfNeeded();
        await page.mouse.wheel(0, 1);

        await expect(page.locator(`.ee-ref-op-nav a[href="#${target}"]`)).toHaveAttribute('aria-current', 'location');

        // ...and only ever one entry is marked, so the previous one was cleared
        await expect(marked).toHaveCount(1);
        await expect(marked).toHaveText('Get OAuth2 access token');

        // Scrolling back up returns the marker to the first operation
        await page.evaluate(() => window.scrollTo(0, 0));
        await expect(marked).toHaveCount(1);
        await expect(marked).toHaveText('Get account info');

        expect(errors).toHaveLength(0);
    });

    test('a property deep link opens the groups it is buried in', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        // Three levels down, inside a collapsed disclosure - the browser cannot scroll to it
        // on its own because it has no layout box until the group is opened
        const anchor = 'postV1Account.body.imap.tls.rejectUnauthorized';
        await page.goto(`/admin/reference/account#${anchor}`);

        const property = page.locator(`[id="${anchor}"]`);
        await expect(property).toBeVisible();
        await expect(property).toContainText('rejectUnauthorized');

        const offset = await property.evaluate(el => el.getBoundingClientRect().top);
        expect(offset).toBeLessThan(300);
        expect(offset).toBeGreaterThan(-50);

        // Clicking the link on another row moves the highlight without a page load
        const sibling = page.locator('[id="postV1Account.body.imap.tls.minVersion"]');
        await sibling.locator('.ee-ref-prop-anchor').click();
        await expect(page).toHaveURL(/#postV1Account\.body\.imap\.tls\.minVersion$/);

        expect(errors).toHaveLength(0);
    });

    test('the chosen code sample language sticks across operations and reloads', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/blocklists');

        const operations = page.locator('.ee-ref-op');
        const firstPython = operations.first().locator('[role="tab"]', { hasText: 'Python' });
        await firstPython.click();
        await expect(firstPython).toHaveAttribute('aria-selected', 'true');

        // Every other operation on the page follows on the next load, so a page of endpoints
        // is not read one language at a time
        await page.reload();
        const tabs = page.locator('[data-sample-tabs] [role="tab"][aria-selected="true"]');
        const labels = await tabs.allTextContents();
        expect(labels.length).toBeGreaterThan(1);
        expect(labels.every(label => label.trim() === 'Python')).toBe(true);

        // ...including on a different group page
        await page.goto('/admin/reference/stats');
        await expect(page.locator(`#${TRY_IT_OPERATION}-sample-python-tab`)).toHaveAttribute('aria-selected', 'true');

        expect(errors).toHaveLength(0);
    });

    test('copy as curl serializes the filled-in try-it form', async ({ page, context }) => {
        const errors = trackConsoleErrors(page);

        await context.grantPermissions(['clipboard-read', 'clipboard-write']);

        await page.goto('/admin/reference/message');

        const id = 'getV1AccountAccountMessages';
        const form = page.locator(`#${id} .ee-ref-try`);
        await page.locator(`#try-${id} summary`).click();

        // A value the generated samples above the operation cannot know about
        await form.locator('[data-in="path"][data-param="account"]').fill('e2e-account');
        await form.locator('[data-in="query"][data-param="path"]').fill('INBOX');

        await form.locator('.ee-ref-try-curl').click();

        const copied = await page.evaluate(() => navigator.clipboard.readText());

        expect(copied).toContain('curl -X GET');
        expect(copied).toContain('/v1/account/e2e-account/messages');
        expect(copied).toContain('path=INBOX');
        // the placeholder, never the token held for this tab
        expect(copied).toContain('Authorization: Bearer $EMAILENGINE_TOKEN');

        expect(errors).toHaveLength(0);
    });

    test('a pasted token is set once and reused across group pages', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const token = await createApiToken(page, 'e2e reference reuse');

        // The control exists only on the dedicated access-token page
        await page.goto('/admin/reference/token');
        await page.fill('#ref-access-token', token);
        await page.click('#ref-token-set');
        await expect(page.locator('#ref-token-state')).toHaveText('Active');

        // ...and the status survives navigation to a group page, which carries no input
        await page.goto(`/admin/reference/${TRY_IT_TAG}`);
        await expect(page.locator('#ref-access-token')).toHaveCount(0);
        await expect(page.locator('#ref-token-state')).toHaveText('Active');

        // ...and is actually used by a request from that page
        const form = page.locator(`#${TRY_IT_OPERATION} .ee-ref-try`);
        await page.locator(`#try-${TRY_IT_OPERATION} summary`).click();
        await form.locator('button[type="submit"]').click();
        await expect(form.locator('.ee-ref-try-code')).toContainText('200', { timeout: 20000 });

        // clearing it takes effect everywhere too
        await page.goto('/admin/reference/token');
        await page.click('#ref-token-clear');
        await page.goto(`/admin/reference/${TRY_IT_TAG}`);
        await expect(page.locator('#ref-token-state')).toHaveText('Not set');

        expect(errors).toHaveLength(0);
    });

    test('minting a temporary token activates it and it expires', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/token');
        await page.click('#ref-token-mint');

        // The status reports a lifetime, not a bare "Active" - this is the expiring kind
        await expect(page.locator('#ref-token-state')).toContainText('min left', { timeout: 20000 });
        await expect(page.locator('#ref-token-feedback')).toContainText('Temporary token minted');

        const stored = await page.evaluate(() => JSON.parse(window.sessionStorage.getItem('eeRefToken')));
        expect(stored.token).toMatch(/^[0-9a-f]{64}$/);
        // one hour, allowing a little slack for the round trip
        expect(stored.expires - Date.now()).toBeGreaterThan(59 * 60 * 1000);
        expect(stored.expires - Date.now()).toBeLessThanOrEqual(60 * 60 * 1000);

        // It is a real api-scoped token: a live request with it succeeds
        await page.goto(`/admin/reference/${TRY_IT_TAG}`);
        const form = page.locator(`#${TRY_IT_OPERATION} .ee-ref-try`);
        await page.locator(`#try-${TRY_IT_OPERATION} summary`).click();
        await form.locator('button[type="submit"]').click();
        await expect(form.locator('.ee-ref-try-code')).toContainText('200', { timeout: 20000 });

        // ...and the client drops it once past its expiry rather than sending a dead token
        await page.evaluate(() => {
            const entry = JSON.parse(window.sessionStorage.getItem('eeRefToken'));
            entry.expires = Date.now() - 1000;
            window.sessionStorage.setItem('eeRefToken', JSON.stringify(entry));
        });
        await page.reload();
        await expect(page.locator('#ref-token-state')).toHaveText('Not set');

        expect(errors).toHaveLength(0);
    });

    test('the minted-token countdown runs down on the open page', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        // Fake timers, so the token's hour is spent in milliseconds. Installed before the
        // navigation: the countdown schedules its first repaint as the page loads.
        await page.clock.install();

        await page.goto('/admin/reference/token');
        await page.click('#ref-token-mint');

        const state = page.locator('#ref-token-state');
        const badge = page.locator('#ref-token-expiry');
        await expect(state).toContainText('min left', { timeout: 20000 });
        await expect(badge).toContainText('min left');

        // Whatever the mint round trip left on the clock, ten minutes take exactly ten off
        // the label - the countdown is not the value that was painted when the page opened.
        const minutes = Number((await state.textContent()).match(/\d+/)[0]);
        await page.clock.fastForward('10:00');
        await expect(state).toHaveText(`${minutes - 10} min left`);
        await expect(badge).toHaveText(`${minutes - 10} min left`);

        // ...and the same open page notices the expiry itself, without being reloaded
        await page.clock.fastForward('01:00:00');
        await expect(state).toHaveText('Not set');
        await expect(badge).toBeHidden();
        await expect(page.locator('#ref-token-clear-wrap')).toBeHidden();
        expect(await page.evaluate(() => window.sessionStorage.getItem('eeRefToken'))).toBeNull();

        expect(errors).toHaveLength(0);
    });

    test('the sidebar links back to the reference overview', async ({ page }) => {
        await page.goto('/admin/reference/message');

        const overview = page.locator('aside[aria-label="Section navigation"]').getByRole('link', { name: 'Overview' });
        await expect(overview).toHaveAttribute('href', '/admin/reference');

        await overview.click();
        await expect(page).toHaveURL(/\/admin\/reference$/);
        await expect(page.getByRole('heading', { name: 'API Reference', exact: true })).toBeVisible();
    });

    test('the sidebar token status always links to the token page', async ({ page }) => {
        // Whatever the state, this has to reach the control - the try-it panels on every
        // group page depend on it, and the control lives on its own page.
        for (const url of ['/admin/reference/message', '/admin/reference']) {
            await page.goto(url);
            const status = page.locator('#ref-token-state').locator('xpath=ancestor::a[1]');
            await expect(status).toHaveAttribute('href', '/admin/reference/token');
        }

        // it still points there once a token is held, not just while unset
        await page.goto('/admin/reference/token');
        await page.click('#ref-token-mint');
        await expect(page.locator('#ref-token-state')).toContainText('min left', { timeout: 20000 });

        await page.goto('/admin/reference/message');
        const status = page.locator('#ref-token-state').locator('xpath=ancestor::a[1]');
        await expect(status).toHaveAttribute('href', '/admin/reference/token');
        await status.click();
        await expect(page).toHaveURL(/\/admin\/reference\/token$/);
        await expect(page.getByRole('heading', { name: 'Access token' })).toBeVisible();
    });

    test('the missing-token banner shows on every reference page, sticks below the topbar and mints in place', async ({ page }) => {
        const banner = page.locator('#ref-token-alert');

        // shown wherever try-it panels could be used without a token
        for (const url of ['/admin/reference', '/admin/reference/message']) {
            await page.goto(url);
            await expect(banner).toBeVisible();
            await expect(banner).toContainText('No access token is set');
        }

        // The try-it panels it warns about are hundreds of pixels down the page, so the
        // banner stays put while they scroll under it rather than leaving with the header.
        const lastOperation = page.locator('.ee-ref-op').last();
        await lastOperation.scrollIntoViewIfNeeded();
        await expect(banner).toBeInViewport();

        // Staying put must not cost access to anything: a deep link still has to land clear of
        // the band, which is what the measured --ee-ref-alert-h offset buys. A middle
        // operation, not the last one - at the end of the document the browser runs out of
        // scroll and parks the section wherever it lands, which would pass on its own.
        const operations = page.locator('.ee-ref-op');
        const id = await operations.nth(Math.floor((await operations.count()) / 2)).getAttribute('id');
        await page.goto(`/admin/reference/message#${id}`);
        await expect(banner).toBeInViewport();

        const landing = await page.evaluate(elId => {
            const operation = document.getElementById(elId);
            return {
                bannerBottom: document.getElementById('ref-token-alert').getBoundingClientRect().bottom,
                operationTop: operation.getBoundingClientRect().top,
                inset: parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop)
            };
        }, id);

        // clear of the band, and only just - the gap is the section's own scroll-margin, so a
        // height that was published wrong (or not at all) moves this out of range
        expect(landing.operationTop - landing.bannerBottom).toBeGreaterThanOrEqual(0);
        expect(landing.operationTop - landing.bannerBottom).toBeLessThanOrEqual(64);

        // the banner's own mint button works without leaving the page
        await page.locator('#ref-token-alert .ref-token-mint').click();
        await expect(banner).toBeHidden({ timeout: 20000 });
        await expect(page.locator('#ref-token-state')).toContainText('min left');

        // ...and the inset it was holding open goes with it, back to plain page flow
        const cleared = await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop));
        expect(cleared).toBeLessThan(landing.inset);

        // ...and it stays gone on the next page now that a token is held
        await page.goto('/admin/reference/submit');
        await expect(banner).toBeHidden();

        // the access-token page never shows it - the control is already there
        await page.goto('/admin/reference/token');
        await expect(page.locator('#ref-token-alert')).toHaveCount(0);
    });

    test('clear is offered only while a token is held', async ({ page }) => {
        await page.goto('/admin/reference/token');
        await expect(page.locator('#ref-token-clear-wrap')).toBeHidden();

        await page.click('#ref-token-mint');
        await expect(page.locator('#ref-token-clear-wrap')).toBeVisible({ timeout: 20000 });

        await page.click('#ref-token-clear');
        await expect(page.locator('#ref-token-clear-wrap')).toBeHidden();
        await expect(page.locator('#ref-token-state')).toHaveText('Not set');
    });

    test('try it sends a real request and renders the response', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const token = await createApiToken(page, 'e2e reference try-it');

        await page.goto('/admin/reference/token');
        await page.fill('#ref-access-token', token);
        await page.click('#ref-token-set');

        await page.goto(`/admin/reference/${TRY_IT_TAG}`);

        const operation = page.locator(`#${TRY_IT_OPERATION}`);
        await operation.locator(`#try-${TRY_IT_OPERATION} summary`).click();

        const form = operation.locator('.ee-ref-try');
        await form.locator('button[type="submit"]').click();

        // A 2xx badge and a JSON body prove the request was built, sent and rendered
        const status = form.locator('.ee-ref-try-code');
        await expect(status).toContainText('200', { timeout: 20000 });
        await expect(form.locator('.ee-ref-try-body')).toContainText('"version"');

        expect(errors).toHaveLength(0);
    });

    test('try it reports an invalid request body without sending it', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/reference/blocklists');

        // The one operation in this group that carries a request body
        const operation = page.locator('#postV1BlocklistListid');
        await operation.locator('#try-postV1BlocklistListid summary').click();

        const form = operation.locator('.ee-ref-try');

        // Typed through the editor the panel upgrades to, which syncs into the textarea the
        // request builder reads. The editor's own worker flags this too, but submit-time
        // validation is what has to stop the request.
        await expect(form.locator('.code-editor')).toBeVisible();
        await page.evaluate(() => window.ace.edit(document.querySelector('#try-postV1BlocklistListid .code-editor')).setValue('{ not json', 1));

        await form.locator('button[type="submit"]').click();

        await expect(form.locator('.ee-ref-try-status')).toContainText('not valid JSON');
        await expect(form.locator('.ee-ref-try-result')).toBeHidden();

        expect(errors).toHaveLength(0);
    });

    test('the try it warning appears only where running the request has a consequence', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        // A read says nothing. The blanket warning this replaced fired on all 82 operations,
        // 42 of which only read, which is what made it invisible on the ones that matter.
        await page.goto('/admin/reference/stats');
        await page.locator('#try-getV1Stats summary').first().click();
        await expect(page.locator('#try-getV1Stats .ee-ref-try')).toBeVisible();
        await expect(page.locator('#try-getV1Stats .alert-warning')).toHaveCount(0);

        // Removing an account warns, and names the consequence rather than the HTTP method
        await page.goto('/admin/reference/account');
        await page.locator('#try-deleteV1AccountAccount summary').first().click();
        await expect(page.locator('#try-deleteV1AccountAccount .alert-warning')).toContainText('cannot be undone');

        // An ordinary write gets one muted line, not a box
        await page.locator('#try-putV1AccountAccount summary').first().click();
        const update = page.locator('#try-putV1AccountAccount');
        await expect(update.locator('.alert-warning')).toHaveCount(0);
        await expect(update.getByText('Runs against live data on this instance.')).toBeVisible();

        // Sending is the other irreversible one
        await page.goto('/admin/reference/submit');
        await page.locator('#try-postV1AccountAccountSubmit summary').first().click();
        await expect(page.locator('#try-postV1AccountAccountSubmit .alert-warning')).toContainText('sends real email');

        expect(errors).toHaveLength(0);
    });

    test('an irreversible request is confirmed before it runs', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        // The fields arrive prefilled from the schema example, so Send here is otherwise one
        // click away from a real deletion.
        const sent = [];
        page.on('request', request => {
            if (request.method() === 'DELETE' && request.url().includes('/v1/account/')) {
                sent.push(request.url());
            }
        });

        await page.goto('/admin/reference/account');
        await page.locator('#try-deleteV1AccountAccount summary').first().click();

        const modal = page.locator('#ee-ref-confirm-deleteV1AccountAccount');
        await expect(modal).toBeHidden();

        // `opened` rather than merely visible: HSOverlay removes `hidden` first and marks the
        // dialog opened from a later timer, and its buttons are not wired to close it until
        // then. Waiting for it is what a reader does by existing.
        const settled = expect(modal).toHaveClass(/opened/);

        await page.locator('#try-deleteV1AccountAccount button[type="submit"]').click();
        await settled;
        expect(sent).toHaveLength(0);

        // The resolved request, not a generic "are you sure" - the account id is the part
        // worth reading before agreeing
        await expect(modal.locator('.ee-ref-confirm-request')).toHaveText('DELETE /v1/account/user123');

        await modal.getByRole('button', { name: 'Cancel' }).click();
        await expect(modal).toBeHidden();
        expect(sent).toHaveLength(0);

        // Confirming runs it, once
        await page.locator('#try-deleteV1AccountAccount button[type="submit"]').click();
        await expect(modal).toHaveClass(/opened/);
        await modal.getByRole('button', { name: 'Run it' }).click();
        await expect(modal).toBeHidden();
        await expect(page.locator('#try-deleteV1AccountAccount .ee-ref-try-result')).toBeVisible();
        expect(sent).toHaveLength(1);

        // A bulk operation decides how much it deletes in its body, so the dialog has to show
        // that too - the path alone would be confirming the wrong half
        await page.goto('/admin/reference/multi-message-actions');
        await page.locator('#try-putV1AccountAccountMessagesDelete summary').first().click();
        await page.locator('#try-putV1AccountAccountMessagesDelete button[type="submit"]').click();

        const bulk = page.locator('#ee-ref-confirm-putV1AccountAccountMessagesDelete');
        await expect(bulk).toHaveClass(/opened/);
        await expect(bulk.locator('.ee-ref-confirm-request')).toHaveText('PUT /v1/account/user123/messages/delete');
        await expect(bulk.locator('.ee-ref-confirm-body')).toContainText('"search"');

        // Send is disabled while the dialog is up, so a second click cannot queue a second
        // confirmation that one "Run it" would then answer twice
        await expect(page.locator('#try-putV1AccountAccountMessagesDelete button[type="submit"]')).toBeDisabled();
        await bulk.getByRole('button', { name: 'Cancel' }).click();
        await expect(bulk).toBeHidden();
        await expect(page.locator('#try-putV1AccountAccountMessagesDelete button[type="submit"]')).toBeEnabled();

        // Submitting a stored draft confirms too. Its body is entirely optional overrides -
        // the draft carries its own recipients - so Send there mails people who appear
        // nowhere in the panel, which is the case with the least in the request to read.
        await page.goto('/admin/reference/submit');
        await page.locator('#try-postV1AccountAccountMessageMessageSubmit summary').first().click();
        await page.locator('#try-postV1AccountAccountMessageMessageSubmit button[type="submit"]').click();

        const draft = page.locator('#ee-ref-confirm-postV1AccountAccountMessageMessageSubmit');
        await expect(draft).toHaveClass(/opened/);
        await expect(draft.locator('.ee-ref-confirm-request')).toContainText('/message/');
        await draft.getByRole('button', { name: 'Cancel' }).click();
        await expect(draft).toBeHidden();

        // Nothing that only reads carries a dialog
        await page.goto('/admin/reference/stats');
        await expect(page.locator('[id^="ee-ref-confirm-"]')).toHaveCount(0);

        // 401s are expected here - this spec holds no token - so only unexpected noise fails
        expect(errors.filter(text => !/401|Unauthorized/.test(text))).toHaveLength(0);
    });

    test('the request body upgrades to a JSON editor, and only once it is asked for', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const aceRequests = [];
        page.on('request', request => {
            if (request.url().includes('/static/js/ace/')) {
                aceRequests.push(request.url());
            }
        });

        await page.goto('/admin/reference/account');
        await expect(page.locator('#try-postV1Account')).toBeVisible();

        // 127 KB gzipped of editor that a reader who never opens a Try it panel does not pay for
        expect(aceRequests).toHaveLength(0);

        await page.locator('#try-postV1Account summary').first().click();

        const editor = page.locator('#try-postV1Account .code-editor');
        await expect(editor).toBeVisible();
        expect(aceRequests.some(url => url.endsWith('/ace.js'))).toBe(true);

        // The textarea stays in the DOM holding the value, so prepareRequest, "Copy as curl"
        // and the no-JS path are all unaffected by the upgrade
        const textarea = page.locator('#try-postV1Account [data-body]');
        await expect(textarea).toBeHidden();

        await page.evaluate(() => window.ace.edit(document.querySelector('#try-postV1Account .code-editor')).setValue('{"account":"edited-in-ace"}', 1));
        expect(await textarea.inputValue()).toBe('{"account":"edited-in-ace"}');

        // Completion is this operation's own fields. Stock language_tools completion is
        // word-based, which inside a JSON body only ever suggests what is already typed, so
        // the custom completer has to be the ONLY one registered.
        const completions = await page.evaluate(async () => {
            const editorInstance = window.ace.edit(document.querySelector('#try-postV1Account .code-editor'));
            if ((editorInstance.completers || []).length !== 1) {
                return null;
            }
            return new Promise(resolve =>
                editorInstance.completers[0].getCompletions(editorInstance, editorInstance.session, { row: 0, column: 0 }, '', (err, list) =>
                    resolve((list || []).map(item => item.value))
                )
            );
        });

        expect(completions).not.toBeNull();
        expect(completions).toContain('account');
        // nested, to prove the whole rendered tree is harvested and not just the top level
        expect(completions).toContain('imapIndexer');

        expect(errors).toHaveLength(0);
    });
});
