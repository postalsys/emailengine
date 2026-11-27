'use strict';

// Filter pills on the lists besides accounts, and bulk delete on the access tokens list. The pills
// travel pill -> query string -> each list's own listing (webhookStatus(), gatewayState(), the
// token scope and binding filters), and the bulk delete travels the floating bar -> the dialog ->
// one POST /admin/tokens/{token}/bulk per token, so only a browser shows the chain agreeing.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker); the `pages-` prefix keeps it after happy-path.spec.js.
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

test.describe('list filter pills and token bulk delete', () => {
    useAdminSession(test, 'lists');

    let auth;

    test.beforeAll(async ({ browser }) => {
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        // Two tokens to delete in bulk, told apart by the run, and one to drive the REST API with
        for (const label of ['first', 'second']) {
            await createApiToken(page, `e2e bulk ${label} ${RUN}`);
            await dismissTokenReveal(page);
        }
        auth = { Authorization: `Bearer ${await createApiToken(page, `e2e lists api ${RUN}`)}` };
        await dismissTokenReveal(page);
        await page.close();
    });

    test('the status pill narrows the gateways list', async ({ page, request }) => {
        const errors = trackConsoleErrors(page);
        const gateway = `e2e-gw-${RUN}`;
        const created = await request.post('/v1/gateway', {
            headers: auth,
            data: { gateway, name: `E2E gateway ${RUN}`, host: '127.0.0.1', port: 9, secure: false }
        });
        expect(created.ok(), `POST /v1/gateway -> ${created.status()} ${await created.text()}`).toBeTruthy();

        try {
            await page.goto(`${BASE_URL}/admin/gateways?query=${RUN}`);
            await expect(page.getByText(`E2E gateway ${RUN}`)).toBeVisible();

            // never used, so an Error filter hides it and a Not used filter shows it
            await page.goto(`${BASE_URL}/admin/gateways?query=${RUN}&state=error`);
            await expect(page.getByText('No gateways match the current filter.')).toHaveCount(0);
            await expect(page.getByText(`E2E gateway ${RUN}`)).toHaveCount(0);

            await page.goto(`${BASE_URL}/admin/gateways?query=${RUN}`);
            await page.locator('#filter-state').click();
            await page.locator('input[name="state"][value="unused"]').check();
            await page.locator('h1').click();
            await expect(page).toHaveURL(/state=unused/);
            await expect(page).toHaveURL(new RegExp(`query=${RUN}`));
            await expect(page.getByText(`E2E gateway ${RUN}`)).toBeVisible();
        } finally {
            await request.delete(`/v1/gateway/${gateway}`, { headers: auth }).catch(() => {});
        }

        expect(errors).toEqual([]);
    });

    test('selected tokens are deleted in bulk after typing the word', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        const list = `${BASE_URL}/admin/tokens?query=${encodeURIComponent(`e2e bulk`)}`;
        await page.goto(list);

        const rows = page.locator('tbody tr', { hasText: RUN });
        await expect(rows).toHaveCount(2);
        for (const box of await rows.locator('.ee-bulk-select').all()) {
            await box.check();
        }
        await expect(page.locator('#bulkCount')).toHaveText('2');

        await page.locator('#bulkBar [data-bulk-action="delete"]').click();
        await expectModalOpen(page.locator('#bulkModal'));
        await expect(page.locator('#bulkList li')).toHaveCount(2);
        await expect(page.locator('#bulkStart')).toBeDisabled();
        await page.locator('#bulkTypeConfirm').fill('delete');
        await page.locator('#bulkStart').click();
        await expect(page.locator('#bulkResults')).toContainText('Deleted 2 tokens');
        await page.locator('#bulkDone').click();
        await page.waitForLoadState('load');

        await expect(page.locator('tbody tr', { hasText: RUN })).toHaveCount(0);
        expect(errors).toEqual([]);
    });

    test('the scope pill narrows the tokens list and keeps the search', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/tokens?query=${encodeURIComponent(`e2e lists api ${RUN}`)}`);
        await expect(page.locator('tbody tr')).toHaveCount(1);

        await page.locator('#filter-scope').click();
        await page.locator('input[name="scope"][value="metrics"]').check();
        await page.locator('h1').click();
        await expect(page).toHaveURL(/scope=metrics/);
        await expect(page.locator('tbody tr')).toHaveCount(0);
        await expect(page.getByText(/No results for/)).toBeVisible();

        // the x on the pill drops the scope and keeps the search
        await page.getByRole('link', { name: 'Remove the Scope filter' }).click();
        await expect(page.locator('tbody tr')).toHaveCount(1);
        expect(errors).toEqual([]);
    });
});
