'use strict';

// Verification spec for the queue browser we mount at /admin/bull-board. bull-board is a
// third-party Hapi PLUGIN serving its own bundled UI, so neither the route-table test nor the
// UI smoke test covers it (see the header comment in test/api-routes-table-test.js). This spec
// exists so a bull-board major bump - 9.0.0 redesigned the UI around design tokens - cannot land
// without something asserting the page still renders inside our admin session.
//
// Shares the Playwright webServer and Redis db 14 with the other specs. The filename has to sort
// after happy-path.spec.js: files run alphabetically with one worker, and happy-path asserts
// fresh-instance behaviour (it sets the FIRST admin password, so its form has no current-password
// field). Anything that bootstraps the instance ahead of it breaks that test.

const os = require('os');
const path = require('path');
const { test, expect } = require('@playwright/test');
const { ensureAdminSession, trackConsoleErrors } = require('./helpers/bootstrap');

const STATE_FILE = path.join(os.tmpdir(), 'ee-e2e-bullboard-state.json');

test.describe('Queue browser (bull-board)', () => {
    test.beforeAll(async ({ browser }) => {
        // plain context (storageState explicitly unset - the file does not exist yet)
        // performs the single real login
        const page = await browser.newPage({ storageState: undefined });
        await ensureAdminSession(page);
        await page.context().storageState({ path: STATE_FILE });
        await page.close();
    });

    test.use({ storageState: STATE_FILE });

    test('renders the board with all three EmailEngine queues', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const response = await page.goto('/admin/bull-board');
        expect(response.status()).toBe(200);

        // The UI is a client-side app: wait for it to paint rather than for the HTML shell.
        await expect(page.locator('#root')).toBeVisible({ timeout: 15000 });

        // The three queues registered in lib/api-routes/bull-board-routes.js. Their display names
        // carry the prefixes set there, which is what proves our adapter config reached the UI.
        for (const name of ['Webhooks Queue', 'Submission Queue', 'Document Queue']) {
            await expect(page.getByText(name, { exact: false }).first()).toBeVisible({ timeout: 15000 });
        }

        expect(errors).toHaveLength(0);
    });

    test('serves the queues API the board fetches', async ({ page }) => {
        // Assert the request the board itself issues rather than a hand-built one: the admin
        // surface content-negotiates, so the same URL fetched from a bare API context comes back
        // as EmailEngine's HTML. Waiting on the board's own call keeps this testing bull-board.
        const [res] = await Promise.all([page.waitForResponse(r => /\/admin\/bull-board\/api\/queues/.test(r.url())), page.goto('/admin/bull-board')]);

        expect(res.status()).toBe(200);
        expect(res.headers()['content-type']).toContain('application/json');

        const body = await res.json();
        // The names carry the `prefix` set per adapter in lib/api-routes/bull-board-routes.js, so
        // this also pins that our adapter options still reach the API across a bull-board major.
        const names = (body.queues || []).map(q => q.name);
        for (const name of ['Webhooks Queue - notify', 'Submission Queue - submit', 'Document Queue - documents']) {
            expect(names).toContain(name);
        }
    });
});
