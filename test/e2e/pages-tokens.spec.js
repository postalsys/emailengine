'use strict';

// Per-page tests for the access-token pages, covering the permission editor added with scoped
// tokens: the axes stay hidden until the restriction is switched on, the presets move the
// checkboxes, and a token minted through the form comes back labelled on the listing.
//
// The last one is the reason this file exists rather than a unit test. The narrowing travels form ->
// admin route -> tokens.provision() -> Redis -> tokens.list() -> the listing template, and nothing
// short of driving the browser shows that the whole chain agrees.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker). The `pages-` prefix matters: a spec sorting before happy-path.spec.js breaks its
// fresh-instance assertions, and only in CI.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const os = require('os');
const path = require('path');
const { test, expect } = require('@playwright/test');
const { ensureAdminSession, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');

const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-tokens-state.json');

// Unique per run so a re-run against the same Redis does not match a previous token's row
const TOKEN_DESCRIPTION = `e2e restricted ${Date.now()}`;

test.describe('access token pages', () => {
    test.use({ storageState: STATE_FILE });

    test.beforeAll(async ({ browser }) => {
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        await page.context().storageState({ path: STATE_FILE });
        await page.close();
    });

    test('the permission editor stays out of the way until it is switched on', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        const section = page.locator('#permissionSection');
        const toggle = page.locator('#permissionsEnabled');

        // Hidden rather than disabled: an axis a reader can see but not use invites the reading that
        // it already applies
        await expect(section).toBeHidden();
        await expect(toggle).not.toBeChecked();

        await toggle.check();
        await expect(section).toBeVisible();

        // Enabling starts from everything selected, so the first state is "no narrowing yet" and each
        // untick is a deliberate subtraction. Starting empty would post two empty allowlists, which
        // grant nothing.
        await expect(page.locator('.permission-action:checked')).toHaveCount(4);
        await expect(page.locator('.permission-group:checked')).toHaveCount(13);

        await toggle.uncheck();
        await expect(section).toBeHidden();

        expect(errors).toEqual([]);
    });

    test('the admin group is shown as refused rather than left out', async ({ page }) => {
        await page.goto(`${BASE_URL}/admin/tokens/new`);
        await page.locator('#permissionsEnabled').check();

        // Omitting it entirely reads as an oversight; the reason is the point
        await expect(page.getByText('can never be granted to a restricted token')).toBeVisible();
        await expect(page.locator('#permissionGroup_admin')).toHaveCount(0);
    });

    test('a preset selects exactly what it names', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);
        await page.locator('#permissionsEnabled').check();

        await page.getByRole('button', { name: 'Read only' }).click();

        await expect(page.locator('#permissionAction_read')).toBeChecked();
        // The whole point of separating destructive from write
        await expect(page.locator('#permissionAction_write')).not.toBeChecked();
        await expect(page.locator('#permissionAction_destructive')).not.toBeChecked();
        await expect(page.locator('#permissionAction_send')).not.toBeChecked();

        await page.getByRole('button', { name: 'Send only' }).click();
        await expect(page.locator('#permissionAction_send')).toBeChecked();
        await expect(page.locator('#permissionGroup_submit')).toBeChecked();
        await expect(page.locator('#permissionGroup_message')).not.toBeChecked();

        expect(errors).toEqual([]);
    });

    test('a token minted with a restriction is labelled on the listing', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#description').fill(TOKEN_DESCRIPTION);
        await page.locator('#permissionsEnabled').check();

        // Narrow to reading messages and folders, which is the shape the feature exists for
        await page.getByRole('button', { name: 'Read only' }).click();
        for (const group of ['account', 'outbox', 'diagnostics']) {
            await page.locator(`#permissionGroup_${group}`).uncheck();
        }

        await page.getByRole('button', { name: 'Generate a token' }).click();

        // The value is shown once and never again, so the modal is the only place it appears
        const tokenValue = page.locator('#showTokenValue');
        await expect(tokenValue).toHaveValue(/^[0-9a-f]{64}$/, { timeout: 15000 });

        await page.getByRole('button', { name: 'Done' }).click();

        // Closing the reveal modal navigates back to the listing
        await page.waitForURL(/\/admin\/tokens/);

        // Searched rather than scanned: tokens.list() sorts by the token hash, so a newly minted one
        // lands in an arbitrary position and falls off page one once the shared instance has enough
        // tokens from the other specs.
        await page.goto(`${BASE_URL}/admin/tokens?query=${encodeURIComponent(TOKEN_DESCRIPTION)}`);

        const row = page.locator('tr', { hasText: TOKEN_DESCRIPTION });
        await expect(row).toBeVisible();
        await expect(row).toContainText('Restricted');
        await expect(row).toContainText('Can: Read');
        await expect(row).toContainText('Messages');
        await expect(row).toContainText('Folders');

        expect(errors).toEqual([]);
    });

    test('unticking every box is refused rather than minting a token that can do nothing', async ({ page }) => {
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#description').fill(`e2e empty axes ${Date.now()}`);
        await page.locator('#permissionsEnabled').check();

        for (const action of ['read', 'write', 'send', 'destructive']) {
            await page.locator(`#permissionAction_${action}`).uncheck();
        }

        await page.getByRole('button', { name: 'Generate a token' }).click();

        // An empty allowlist allows nothing, so the token would authenticate and then refuse every
        // request it made - a puzzle for whoever was handed it
        await expect(page.locator('#showTokenError')).toBeVisible({ timeout: 15000 });
        await expect(page.locator('#showTokenError')).toContainText('at least one action');
    });
});
