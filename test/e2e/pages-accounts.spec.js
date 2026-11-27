'use strict';

// The accounts list's filter pills and bulk actions. The filters travel pill -> query string ->
// Account#listAccounts() -> the Lua listing, and a bulk action travels the floating bar -> the
// dialog -> one POST /admin/accounts/{account}/bulk per account -> the outcome list, so only a
// browser shows the chain agreeing.
//
// The accounts are registered over the REST API under a domain of their own, so the domain filter
// isolates them from whatever else the shared instance holds. Shares the Playwright webServer and
// Redis db 14 with the other specs (files run alphabetically with one worker); the `pages-` prefix
// keeps it after happy-path.spec.js.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect } = require('./helpers/test');
const {
    useAdminSession,
    ensureAdminSession,
    createApiToken,
    dismissTokenReveal,
    trackConsoleErrors,
    expectModalOpen,
    BASE_URL
} = require('./helpers/bootstrap');

const RUN = Date.now().toString(36);
const DOMAIN = `bulk-${RUN}.example.com`;

const SMTP = { host: '127.0.0.1', port: 9, secure: false, auth: { user: 'u', pass: 'p' } };

// An IMAP account the worker cannot reach: port 9 refuses at once, so the account sits in a
// connection error without the worker dialling out anywhere
const ACCOUNTS = [
    {
        account: `e2e-bulk-imap-${RUN}`,
        name: 'Bulk IMAP',
        email: `imap@${DOMAIN}`,
        imap: { host: '127.0.0.1', port: 9, secure: false, auth: { user: 'u', pass: 'p' } },
        smtp: SMTP
    },
    { account: `e2e-bulk-smtp-${RUN}`, name: 'Bulk SMTP', email: `smtp@${DOMAIN}`, smtp: SMTP },
    { account: `e2e-bulk-sub-${RUN}`, name: 'Bulk Subdomain', email: `sub@eu.${DOMAIN}`, smtp: SMTP },
    // must never match: the domain is only a suffix of its own
    { account: `e2e-bulk-other-${RUN}`, name: 'Bulk Other', email: `other@not${DOMAIN}`, smtp: SMTP }
];

test.describe('accounts list filters and bulk actions', () => {
    useAdminSession(test, 'accounts');

    let auth;

    test.beforeAll(async ({ browser, request }) => {
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        const token = await createApiToken(page, `e2e accounts ${RUN}`);
        await dismissTokenReveal(page);
        await page.close();

        auth = { Authorization: `Bearer ${token}` };
        for (const data of ACCOUNTS) {
            const created = await request.post('/v1/account', { headers: auth, data });
            expect(created.ok(), `POST /v1/account -> ${created.status()} ${await created.text()}`).toBeTruthy();
        }
    });

    test.afterAll(async ({ request }) => {
        for (const { account } of ACCOUNTS) {
            await request.delete(`/v1/account/${account}`, { headers: auth }).catch(() => {});
        }
    });

    const rows = page => page.locator('tbody tr');

    test('the domain pill lists the domain and its subdomains only', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/accounts`);

        await page.locator('#filter-domain').click();
        await page.locator('#filter-domain-input').fill(DOMAIN);
        await page.locator('#filter-domain-input').press('Enter');

        await expect(page).toHaveURL(new RegExp(`domain=${DOMAIN.replace(/\./g, '\\.')}`));
        await expect(rows(page)).toHaveCount(3);
        await expect(page.getByText(`other@not${DOMAIN}`)).toHaveCount(0);
        await expect(page.getByRole('button', { name: `Domain: ${DOMAIN}, change filter` })).toBeVisible();
        // the header counts the matches out of the whole
        await expect(page.locator('h1 .badge')).toHaveText(/^3 of \d+$/);

        expect(errors).toEqual([]);
    });

    test('a pill applies when its menu closes, and Escape throws the change away', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        const start = `${BASE_URL}/admin/accounts?domain=${DOMAIN}`;
        await page.goto(start);

        // Escape: nothing applied, and the box is unticked again for the next opening
        await page.locator('#filter-type').click();
        const smtpOnly = page.locator('input[name="type"][value="sending"]');
        await smtpOnly.check();
        await page.keyboard.press('Escape');
        await expect(page).toHaveURL(start);
        await expect(smtpOnly).not.toBeChecked();

        // A click elsewhere closes the menu and applies what was ticked
        await page.locator('#filter-type').click();
        await smtpOnly.check();
        await page.locator('h1').click();
        await expect(page).toHaveURL(/type=sending/);
        await expect(rows(page)).toHaveCount(2);

        // The pill's x drops only that filter
        await page.getByRole('link', { name: 'Remove the Type filter' }).click();
        await expect(page).toHaveURL(start);
        await expect(rows(page)).toHaveCount(3);

        expect(errors).toEqual([]);
    });

    test('pause skips what it does not apply to, and delete needs the word typed', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        const modal = page.locator('#bulkModal');
        await page.goto(`${BASE_URL}/admin/accounts?domain=${DOMAIN}`);

        const bar = page.locator('#bulkBar');
        await expect(bar).toBeHidden();
        await page.locator('#bulkSelectAll').check();
        await expect(bar).toBeVisible();
        await expect(page.locator('#bulkCount')).toHaveText('3');

        // Pause: a light confirmation naming the accounts, then the outcome
        await bar.locator('[data-bulk-action="pause"]').click();
        await expectModalOpen(modal);
        await expect(page.locator('#bulkList li')).toHaveCount(3);
        await page.locator('#bulkStart').click();
        await expect(page.locator('#bulkResultStep')).toBeVisible();
        await expect(page.locator('#bulkResults')).toContainText('Paused 1 account');
        await expect(page.locator('#bulkResults')).toContainText('Skipped 2 accounts: Sends only, nothing to sync');
        await page.locator('#bulkDone').click();
        await page.waitForLoadState('load');

        // Delete: the button stays off until "delete" is typed
        await page.locator('#bulkSelectAll').check();
        await bar.locator('[data-bulk-action="delete"]').click();
        await expectModalOpen(modal);
        const start = page.locator('#bulkStart');
        await expect(start).toBeDisabled();
        await page.locator('#bulkTypeConfirm').fill('delet');
        await expect(start).toBeDisabled();
        await page.locator('#bulkTypeConfirm').fill('delete');
        await expect(start).toBeEnabled();
        await start.click();
        await expect(page.locator('#bulkResults')).toContainText('Deleted 3 accounts');
        await page.locator('#bulkDone').click();
        await page.waitForLoadState('load');

        await expect(page.getByText('No accounts match the current filter.')).toBeVisible();

        expect(errors).toEqual([]);
    });
});
