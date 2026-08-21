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
const { ensureAdminSession, createApiToken, dismissTokenReveal, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');

const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-tokens-state.json');

// Unique per run so a re-run against the same Redis does not match a previous token's row
const TOKEN_DESCRIPTION = `e2e restricted ${Date.now()}`;
const BOUND_TOKEN_DESCRIPTION = `e2e bound ${Date.now()}`;

// The account the binding test points at. Registered over the REST API rather than through the
// account wizard: what is under test is the token form, and the wizard needs a working mail server.
const BOUND_ACCOUNT_ID = 'e2e-token-binding';

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

        // Closing the reveal modal navigates back to the listing. Through the shared helper, which
        // settles the opening transition before clicking and waits the navigation out - this spec
        // used to do it by hand and got both halves wrong.
        await dismissTokenReveal(page);

        // Searched rather than scanned: tokens.list() sorts by the token hash, so a newly minted one
        // lands in an arbitrary position and falls off page one once the shared instance has enough
        // tokens from the other specs.
        await page.goto(`${BASE_URL}/admin/tokens?query=${encodeURIComponent(TOKEN_DESCRIPTION)}`);

        const row = page.locator('tr', { hasText: TOKEN_DESCRIPTION });
        await expect(row).toBeVisible();
        await expect(row).toContainText('Restricted');
        // An unbound token is usable for every account, which the binding column has to say out loud
        // now that it also reports the tokens that are pinned to one
        await expect(row).toContainText('All accounts');
        await expect(row).toContainText('Can read in');
        await expect(row).toContainText('Messages');
        await expect(row).toContainText('Folders');

        expect(errors).toEqual([]);
    });

    test('a token can be bound to an account typed into the form', async ({ page, request }) => {
        // The binding used to be reachable only by opening the form from an account page, which put
        // the account in the URL and out of sight. It is what the token IS - the credential is
        // refused for every other account - so it has to be visible and editable on the form itself.
        const errors = trackConsoleErrors(page);

        const apiToken = await createApiToken(page, `e2e binding setup ${Date.now()}`);
        await dismissTokenReveal(page);
        const auth = { Authorization: `Bearer ${apiToken}` };

        // No imap/smtp block: the token form resolves the account record and never touches the mail
        // server, and a half-configured account would have the IMAP worker dialling out for the
        // length of the test for nothing
        await request.delete(`/v1/account/${BOUND_ACCOUNT_ID}`, { headers: auth }).catch(() => {});
        const created = await request.post('/v1/account', {
            headers: auth,
            data: {
                account: BOUND_ACCOUNT_ID,
                name: 'E2E Token Binding',
                email: 'e2e-token-binding@ethereal.email'
            }
        });
        expect(created.ok(), `POST /v1/account -> ${created.status()} ${await created.text()}`).toBeTruthy();

        try {
            await page.goto(`${BASE_URL}/admin/tokens/new`);

            // Optional: an empty field is what an unbound, instance-wide token looks like
            await expect(page.locator('#account')).toHaveValue('');

            await page.locator('#description').fill(BOUND_TOKEN_DESCRIPTION);
            await page.locator('#account').fill(BOUND_ACCOUNT_ID);
            await page.getByRole('button', { name: 'Generate a token' }).click();

            await expect(page.locator('#showTokenValue')).toHaveValue(/^[0-9a-f]{64}$/, { timeout: 15000 });
            const boundToken = await page.locator('#showTokenValue').inputValue();
            await dismissTokenReveal(page);

            // A bound token is not in the unbound listing at all, so the reveal modal hands the
            // reader over to the listing for the account it was just bound to
            await expect(page).toHaveURL(new RegExp(`/admin/tokens\\?account=${BOUND_ACCOUNT_ID}$`));
            await expect(page.locator('tr', { hasText: BOUND_TOKEN_DESCRIPTION })).toBeVisible();

            // And it is on the Access Tokens page itself, which reads every token rather than only
            // the unbound index - otherwise the page that manages credentials would be the one place
            // this one could not be found. Searched rather than scanned: the listing sorts by token
            // hash, so a new row lands in an arbitrary position.
            await page.goto(`${BASE_URL}/admin/tokens?query=${encodeURIComponent(BOUND_TOKEN_DESCRIPTION)}`);
            const listed = page.locator('tr', { hasText: BOUND_TOKEN_DESCRIPTION });
            await expect(listed).toBeVisible();
            await expect(listed).toContainText(BOUND_ACCOUNT_ID);

            // The binding is real over the API, not just a label on a listing
            const boundAuth = { Authorization: `Bearer ${boundToken}` };
            expect((await request.get(`/v1/account/${BOUND_ACCOUNT_ID}`, { headers: boundAuth })).status()).toBe(200);

            // And deleting the account revokes it. The record used to survive in the global token
            // hash, where it went on authenticating with nothing anywhere listing it.
            await request.delete(`/v1/account/${BOUND_ACCOUNT_ID}`, { headers: auth });
            expect(
                (await request.get(`/v1/account/${BOUND_ACCOUNT_ID}`, { headers: boundAuth })).status(),
                'a token bound to a deleted account must no longer authenticate'
            ).toBe(401);

            expect(errors).toEqual([]);
        } finally {
            await request.delete(`/v1/account/${BOUND_ACCOUNT_ID}`, { headers: auth }).catch(() => {});
        }
    });

    test('an account ID that does not exist is refused, and says so', async ({ page }) => {
        // Free text, so a typo is the failure to design for. It has to name the value that was not
        // found rather than report a bare "Not Found", which says nothing about which field to fix.
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#description').fill(`e2e unknown account ${Date.now()}`);
        await page.locator('#account').fill('e2e-no-such-account');
        await page.getByRole('button', { name: 'Generate a token' }).click();

        const error = page.locator('#showTokenError');
        await expect(error).toBeVisible({ timeout: 15000 });
        await expect(error).toContainText('e2e-no-such-account');
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

    test('the access editor is its own section and names the scopes it affects', async ({ page }) => {
        // It used to be a row nested under the API checkbox, which put it under an unticked box
        // whenever MCP alone was selected - titled for a surface that token would not even have.
        // What ties it to the scopes now is the sentence naming them, so that is what is asserted.
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        const card = page.locator('#accessCard');
        const appliesTo = page.locator('#accessAppliesTo');

        // Not inside the scope list any more
        await expect(page.locator('ul', { has: page.locator('#scopesAPI') }).locator('#accessCard')).toHaveCount(0);

        // "All scopes" carries both per-request surfaces with it
        await expect(card).toBeVisible();
        await expect(appliesTo).toContainText('REST API requests and MCP tool calls');

        // The login-time scopes are checked once against everything their surface can do, so a
        // narrowing either changes nothing or breaks them - there is nothing to edit
        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesSMTP').check();
        await expect(card).toBeHidden();

        await page.locator('#scopesAPI').check();
        await expect(card).toBeVisible();
        await expect(appliesTo).toHaveText('Applies to REST API requests.');
    });

    test('an MCP-only token is provisioned by access level, not by the API matrix', async ({ page }) => {
        // Ticking MCP used to open a block titled "Limit what the API token can do", nested under an
        // API checkbox that was not even ticked. An mcp-scoped token cannot call /v1 at all, so the
        // editor offers the same named levels the OAuth consent prompt and the MCP config page do.
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesMcp').check();

        await expect(page.locator('#accessAppliesTo')).toHaveText('Applies to MCP tool calls.');
        await expect(page.locator('#mcpLevelBlock')).toBeVisible();
        // No "restrict?" toggle in this mode: an agent credential starts read-only rather than
        // unrestricted, which is the wrong way round for something a model drives
        await expect(page.locator('#apiLimitBlock')).toBeHidden();
        await expect(page.locator('#mcpAccess_read')).toBeChecked();

        // The matrix is the detail view behind the levels, not the way in
        await expect(page.locator('#permissionSection')).toBeHidden();

        // Read-only leaves the reading tools and nothing else, which is the number the two axes
        // cannot tell anyone by themselves
        const outcome = page.locator('#permissionOutcome');
        await expect(outcome).toBeVisible();
        await expect(outcome).toContainText('MCP tools available');
        const readOnlyCount = await outcome.textContent();

        await page.locator('#mcpAccess_full').check();
        // Full access mints no permissions record at all, so every tool survives
        await expect(outcome).toContainText(/(\d+) of \1 MCP tools available/);
        expect(await outcome.textContent()).not.toBe(readOnlyCount);

        expect(errors).toEqual([]);
    });

    test('the custom level lists only the sections MCP can reach', async ({ page }) => {
        // Ticking "Webhook routes" on a token that can only call MCP tools grants nothing. A control
        // with no effect reads as a permission, so those rows are taken out rather than left inert.
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens/new`);

        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesMcp').check();
        await page.locator('#mcpAccess_custom').check();

        await expect(page.locator('#permissionSection')).toBeVisible();
        // The API presets are shapes for the REST API; the named levels above are this mode's presets
        await expect(page.locator('#permissionPresetRow')).toBeHidden();
        await expect(page.locator('#permissionMcpScopeNote')).toBeVisible();

        // Six of the thirteen sections carry an MCP tool
        await expect(page.locator('#permissionGroup_message')).toBeVisible();
        await expect(page.locator('#permissionGroup_webhook')).toBeHidden();
        await expect(page.locator('#permissionGroup_gateway')).toBeHidden();
        // A cluster whose every section is out of reach is a heading over nothing
        await expect(page.locator('[data-cluster="Monitoring"]')).toBeHidden();

        // Custom starts from the level it was opened out of, which is what its hint promises
        await expect(page.locator('#permissionAction_read')).toBeChecked();
        await expect(page.locator('#permissionAction_destructive')).not.toBeChecked();

        // Narrowing it down to a single tool family is visible before the client ever connects
        for (const group of ['account', 'mailbox', 'outbox', 'template']) {
            await page.locator(`#permissionGroup_${group}`).uncheck();
        }
        await expect(page.locator('#permissionOutcome')).toContainText('MCP tools available');

        expect(errors).toEqual([]);
    });

    test('an MCP token minted at a named level carries that level permissions', async ({ page }) => {
        // The level has to mean the same thing here as it does on the consent prompt, so what is
        // asserted is the record that reaches Redis and comes back on the listing - not the radio.
        const description = `e2e mcp level ${Date.now()}`;

        await page.goto(`${BASE_URL}/admin/tokens/new`);
        await page.locator('#description').fill(description);
        await page.locator('#scopesAll').uncheck();
        await page.locator('#scopesMcp').check();
        await page.locator('#mcpAccess_mail').check();

        await page.getByRole('button', { name: 'Generate a token' }).click();
        await expect(page.locator('#showTokenValue')).toHaveValue(/^[0-9a-f]{64}$/, { timeout: 15000 });
        await dismissTokenReveal(page);

        await page.goto(`${BASE_URL}/admin/tokens?query=${encodeURIComponent(description)}`);
        const row = page.locator('tr', { hasText: description });
        await expect(row).toBeVisible();
        await expect(row).toContainText('mcp');
        // The mail agent level is the non-destructive subset of the MCP surface: it can send, and it
        // cannot reach the delete tool. Asserted as the whole sentence rather than a fragment, since
        // the sentence lists exactly the actions the record allows - "delete" being absent from it is
        // the assertion (a `not.toContainText` would match the row's own Delete button instead).
        await expect(row).toContainText('Can read, create and modify, send email in Accounts, Folders, Messages, Sending, Sending queue, Templates');
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
