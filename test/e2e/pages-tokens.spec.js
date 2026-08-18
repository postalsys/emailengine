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
        await expect(page.getByText('never available to a restricted token')).toBeVisible();
        await expect(page.locator('#permissionGroup_admin')).toHaveCount(0);
    });

    test('says in words what the two axes add up to', async ({ page }) => {
        // The axes multiply: four actions by thirteen sections. Without this a reader has to do that
        // cross-product in their head to find out what they just built.
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);
        await page.locator('#permissionsEnabled').check();

        await page.getByRole('button', { name: 'Read only' }).click();

        const outcome = page.locator('#permissionOutcome');
        await expect(outcome).toContainText('This token can read in');
        await expect(outcome).toContainText('Messages');

        // The half that reassures: what it will NOT be able to do
        await expect(outcome).toContainText('It cannot');
        await expect(outcome).toContainText('delete');

        // Selecting nothing is called out rather than silently producing a dead credential
        for (const action of ['read', 'write', 'send', 'destructive']) {
            await page.locator(`#permissionAction_${action}`).uncheck();
        }
        await expect(outcome).toContainText('would not be able to do anything');

        expect(errors).toEqual([]);
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

        // The value is 64 characters and this modal is the only place it is ever shown. It used to
        // truncate at about 32: ui/copy-field's join wrapper is inline-flex, so the `grow` on the
        // input had nothing to grow inside, and the default modal was narrower than the token.
        // Asserted by measurement rather than by eye, because a later width or font change would
        // silently reintroduce it.
        const overflow = await tokenValue.evaluate(el => el.scrollWidth - el.clientWidth);
        expect(overflow, 'the access token does not fit its field and is being cut off').toBeLessThanOrEqual(0);

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
        await expect(row).toContainText('Can read in');
        await expect(row).toContainText('Messages');
        await expect(row).toContainText('Folders');

        expect(errors).toEqual([]);
    });

    test('warns when a restriction contradicts one of the token own scopes', async ({ page }) => {
        // The scopes and the permissions are checked separately, so it is entirely legal to hold the
        // smtp scope and a restriction that forbids sending - the token simply cannot use that
        // surface. Legal, but never what someone meant to build.
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesAPI').check();
        await page.locator('#scopesSMTP').check();
        await page.locator('#permissionsEnabled').check();

        const warning = page.locator('#permissionScopeWarning');
        // Everything is selected on enable, so the smtp surface is satisfied and nothing is wrong yet
        await expect(warning).toBeHidden();

        await page.getByRole('button', { name: 'Read only' }).click();
        await expect(warning).toBeVisible();
        await expect(warning).toContainText('send over SMTP');

        // Granting what the surface asks for clears it again
        await page.locator('#permissionAction_send').check();
        await page.locator('#permissionGroup_submit').check();
        await expect(warning).toBeHidden();
    });

    test('the editor lives under the API scope and follows it', async ({ page }) => {
        // Nested rather than stacked in a card of its own: as siblings, nothing said the permissions
        // were a subset of one scope, and the relationship had to be asserted in prose. Permissions
        // resolve per endpoint on the REST API, so without that scope every setting would either
        // change nothing or leave the token unable to do its one job - and scopes are fixed once the
        // token exists, so no later state rescues it.
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        const row = page.locator('#permissionRow');

        // It is a row of the scope list, not a separate section
        await expect(page.locator('ul', { has: page.locator('#scopesAPI') }).locator('#permissionRow')).toHaveCount(1);

        // "All scopes" carries API with it
        await expect(row).toBeVisible();

        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesSMTP').check();
        await expect(row).toBeHidden();

        // Adding API access brings it back
        await page.locator('#scopesAPI').check();
        await expect(row).toBeVisible();
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
        // request it made - a puzzle for whoever was handed it. Refused by tokenPermissionsSchema
        // rather than by this route, so POST /v1/tokens gives the same answer.
        await expect(page.locator('#showTokenError')).toBeVisible({ timeout: 15000 });
        await expect(page.locator('#showTokenError')).toContainText('Select at least one action');

        // And the outcome panel says so before the request is even made
        await expect(page.locator('#permissionOutcome')).toContainText('would not be able to do anything');
    });
});
