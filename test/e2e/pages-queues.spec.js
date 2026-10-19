'use strict';

// Per-page tests for the queue browser (/admin/queues), the in-house replacement for the
// bull-board page: the overview and the three queue pages render for an admin, the counts
// endpoint the pages poll answers JSON, the retired bull-board URLs redirect, and a scheduled
// message walks through the actions a row offers - open, send now, remove - against a real
// queue entry created through the API.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker). The `pages-` prefix matters: a spec sorting before happy-path.spec.js breaks
// its fresh-instance assertions, and only in CI. The action tests need an account to queue a
// message for; they register one over the REST API rather than through the wizard, since what is
// under test is the queue page.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect } = require('@playwright/test');
const { useAdminSession, createApiToken, dismissTokenReveal, trackConsoleErrors, openRowMenu, BASE_URL } = require('./helpers/bootstrap');

const ACCOUNT_ID = 'e2e-queue-browser';

// Far enough ahead that nothing sends it before the test looks at it
const SEND_AT = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();

test.describe('queue browser pages', () => {
    useAdminSession(test, 'queues');

    test('the overview lists every queue with its counts and links into them', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const response = await page.goto(`${BASE_URL}/admin/queues`);
        expect(response.status()).toBe(200);

        for (const name of ['notify', 'submit', 'export']) {
            const card = page.locator(`[data-queue-card="${name}"]`);
            await expect(card).toBeVisible();
            // five state tiles, each a link to that state's tab
            await expect(card.locator('[data-queue-count]')).toHaveCount(5);
            await expect(card.locator(`a[href="/admin/queues/${name}?state=failed"]`)).toBeVisible();
        }

        // the side menu entry is active here
        await expect(page.locator('aside a[href="/admin/queues"]').first()).toBeVisible();

        expect(errors).toHaveLength(0);
    });

    test('the counts endpoint the pages poll answers JSON for every queue', async ({ page }) => {
        // Fetched from inside the page, the way static/js/queues.js polls it: that is the call
        // that has to work under the admin session and the page's connect-src policy
        await page.goto(`${BASE_URL}/admin/queues`);
        const body = await page.evaluate(async () => {
            const res = await fetch('/admin/queues/counts', { headers: { accept: 'application/json' }, credentials: 'same-origin' });
            if (!res.ok || !(res.headers.get('content-type') || '').includes('application/json')) {
                throw new Error(`${res.status} ${res.headers.get('content-type')}`);
            }
            return res.json();
        });

        for (const name of ['notify', 'submit', 'export']) {
            expect(body.queues[name]).toBeTruthy();
            expect(typeof body.queues[name].isPaused).toBe('boolean');
            for (const state of ['waiting', 'active', 'delayed', 'failed', 'completed']) {
                expect(typeof body.queues[name].counts[state]).toBe('number');
            }
        }
    });

    test('every queue page renders each state tab without errors', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        for (const name of ['notify', 'submit', 'export']) {
            for (const state of ['waiting', 'active', 'delayed', 'failed', 'completed']) {
                const response = await page.goto(`${BASE_URL}/admin/queues/${name}?state=${state}`);
                expect(response.status(), `${name}/${state}`).toBe(200);
                await expect(page.locator('nav[aria-label="Entries by state"] a.tab-active')).toContainText(new RegExp(state, 'i'));
            }
        }

        // an unknown queue or state falls back to the overview rather than erroring
        await page.goto(`${BASE_URL}/admin/queues/nope`);
        await expect(page).toHaveURL(/\/admin\/queues$/);
        await page.goto(`${BASE_URL}/admin/queues/submit?state=nope`);
        await expect(page).toHaveURL(/\/admin\/queues$/);

        expect(errors).toHaveLength(0);
    });

    test('the retired bull-board URLs redirect to the matching queue page', async ({ page }) => {
        await page.goto(`${BASE_URL}/admin/bull-board`);
        await expect(page).toHaveURL(/\/admin\/queues$/);

        await page.goto(`${BASE_URL}/admin/bull-board/queue/Submission%20Queue%20-%20submit`);
        await expect(page).toHaveURL(/\/admin\/queues\/submit$/);
    });

    test.describe('a scheduled message in the queue', () => {
        // The token and the account are created inside each test from the admin session the
        // page fixture carries, the way the token pages spec does it; a beforeAll would need
        // a login of its own
        async function setup(page, request) {
            const token = await createApiToken(page, `e2e queue browser ${Date.now()}`);
            await dismissTokenReveal(page);
            const auth = { Authorization: `Bearer ${token}` };

            await request.delete(`/v1/account/${ACCOUNT_ID}`, { headers: auth }).catch(() => {});
            // An SMTP-only account: queuing a message needs no mailbox, and a sendAt a year out
            // means nothing tries to deliver it until the test says so. The outgoing server is a
            // closed local port, so an attempt fails at once with a refused connection rather
            // than hanging in a DNS lookup or a TCP timeout, which left the entry Active for
            // minutes on one run
            const created = await request.post('/v1/account', {
                headers: auth,
                data: {
                    account: ACCOUNT_ID,
                    name: 'Queue browser',
                    email: 'queue-browser@example.com',
                    imap: false,
                    smtp: { auth: { user: 'queue-browser@example.com', pass: 'secret' }, host: '127.0.0.1', port: 1, secure: false }
                }
            });
            expect(created.ok(), `POST /v1/account -> ${created.status()} ${await created.text()}`).toBeTruthy();

            const queueMessage = async (subject, overrides) => {
                const res = await request.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                    headers: auth,
                    // one attempt, so the message is Failed rather than waiting out a backoff once sent
                    data: Object.assign(
                        { to: [{ address: 'nobody@example.com' }], subject, text: 'queued by the e2e suite', sendAt: SEND_AT, deliveryAttempts: 1 },
                        overrides
                    )
                });
                expect(res.ok(), `POST submit -> ${res.status()} ${await res.text()}`).toBeTruthy();
                return (await res.json()).queueId;
            };

            const teardown = async () => {
                await request.delete(`/v1/account/${ACCOUNT_ID}`, { headers: auth }).catch(() => {});
            };

            return { auth, queueMessage, teardown };
        }

        test('is listed under Delayed, opens its own page, and can be sent now and removed', async ({ page, request }) => {
            const errors = trackConsoleErrors(page);
            const { auth, queueMessage, teardown } = await setup(page, request);

            try {
                const subject = `e2e queued ${Date.now()}`;
                const queueId = await queueMessage(subject);

                // Listed, with the account filter the account page links with
                await page.goto(`${BASE_URL}/admin/queues/submit?state=delayed&account=${ACCOUNT_ID}`);
                const row = page.locator('tbody tr', { hasText: subject });
                await expect(row).toBeVisible();
                await expect(row).toContainText('Scheduled');
                await expect(page.getByText(`Entries for account "${ACCOUNT_ID}"`)).toBeVisible();

                // The row leads to the entry's page
                await row.getByRole('link', { name: 'Open message' }).click();
                await expect(page).toHaveURL(new RegExp(`/admin/queues/submit/jobs/${queueId}$`));
                await page.waitForLoadState('load');
                await expect(page.locator('h1')).toContainText(subject);
                await expect(page.locator('#queue-id')).toHaveValue(queueId);

                // Send now moves it out of the delayed set; the one attempt that follows is
                // refused at once, so the message ends up Failed with its content kept
                await page.getByRole('button', { name: 'Send now' }).click();
                await expect(page).toHaveURL(new RegExp(`/admin/queues/submit/jobs/${queueId}$`));
                await expect(page.getByText('runs at the next opportunity')).toBeVisible();

                let promoted;
                for (let i = 0; i < 60; i++) {
                    const entry = await request.get(`/v1/outbox/${queueId}`, { headers: auth });
                    expect(entry.status()).toBe(200);
                    promoted = await entry.json();
                    // the state and the attempt count are two reads, so a job seen the moment it
                    // fails can report the new state with the old count; wait for both
                    if (promoted.state === 'failed' && promoted.attemptsMade > 0) {
                        break;
                    }
                    await page.waitForTimeout(500);
                }
                expect(promoted.state).toBe('failed');
                expect(promoted.attemptsMade).toBe(1);

                // The failed list offers a retry (the content is still kept) and leads to the
                // entry's page. Found through the search the page offers
                await page.goto(`${BASE_URL}/admin/queues/submit?state=failed&query=${encodeURIComponent(subject)}`);
                const listed = page.locator('tbody tr', { hasText: subject });
                await expect(listed).toBeVisible();
                await expect(listed).toContainText('Unreachable');
                await openRowMenu(listed, 'Entry actions');
                await expect(listed.getByRole('button', { name: 'Retry' })).toBeVisible();
                await listed.getByRole('link', { name: 'Open', exact: true }).click();
                await expect(page).toHaveURL(new RegExp(`/admin/queues/submit/jobs/${queueId}$`));

                // Removed from its own page, which asks first, it lands on the list of the state
                // it was in rather than on the page of an entry that no longer exists. The actions
                // are the page header's
                await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
                const kebab = page.locator('.dropdown', { has: page.getByRole('button', { name: 'More entry actions' }) });
                await openRowMenu(kebab, 'More entry actions');
                await kebab.getByRole('button', { name: 'Remove from queue' }).click();
                const modal = page.locator('#removeJob');
                await expect(modal).toBeVisible();
                await expect(modal).toContainText(subject);
                await modal.getByRole('button', { name: 'Remove' }).click();
                await expect(page).toHaveURL(/\/admin\/queues\/submit\?state=failed$/);
                await expect(page.getByText('Removed the message from the queue')).toBeVisible();
                expect((await request.get(`/v1/outbox/${queueId}`, { headers: auth })).status()).toBe(404);

                expect(errors).toHaveLength(0);
            } finally {
                await teardown();
            }
        });

        test('a waiting entry offers only its removal, from a menu that opens over the content', async ({ page, request }) => {
            // Submitted without a send time while the queue is paused, so it stays Waiting. Its
            // page then has nothing to offer but Remove, so the header's action row is Back to
            // list and the kebab: the menu has to open over the content, not off the page's edge
            const errors = trackConsoleErrors(page);
            const { auth, queueMessage, teardown } = await setup(page, request);
            try {
                await page.goto(`${BASE_URL}/admin/queues/submit`);
                await page.getByRole('button', { name: 'Pause' }).click();
                await expect(page.getByText('This queue is paused')).toBeVisible();

                const subject = `e2e waiting ${Date.now()}`;
                const queueId = await queueMessage(subject, { sendAt: undefined });
                await page.goto(`${BASE_URL}/admin/queues/submit/jobs/${queueId}`);
                await expect(page.locator('h1')).toContainText(subject);

                await expect(page.getByRole('button', { name: 'Send now' })).toHaveCount(0);
                const toggle = page.getByRole('button', { name: 'More entry actions' });
                const kebab = page.locator('.dropdown', { has: toggle });
                await openRowMenu(kebab, 'More entry actions');
                const menu = kebab.getByRole('menu');
                // The kebab ends the header row, so the menu hangs off its right edge and lies
                // over the content column, which the header row spans; the fixed-position menu is
                // placed a tick after it opens
                const [toggleBox, headerBox] = await Promise.all([toggle.boundingBox(), page.locator('h1').locator('..').boundingBox()]);
                await expect
                    .poll(
                        async () => {
                            const box = await menu.boundingBox();
                            return box.x >= headerBox.x - 1 && box.x + box.width <= toggleBox.x + toggleBox.width + 1;
                        },
                        { message: 'the menu opens leftward from the kebab, over the content' }
                    )
                    .toBe(true);

                await page.keyboard.press('Escape');

                // The list offers the same removal, which asks first
                await page.goto(`${BASE_URL}/admin/queues/submit`);
                const listed = page.locator('tbody tr', { hasText: subject });
                await expect(listed).toBeVisible();
                await openRowMenu(listed, 'Entry actions');
                await listed.getByRole('button', { name: 'Remove' }).click();
                const modal = page.locator('#removeJob');
                await expect(modal).toBeVisible();
                await expect(modal).toContainText(subject);
                await modal.getByRole('button', { name: 'Remove' }).click();
                await expect(page).toHaveURL(/\/admin\/queues\/submit$/);
                await expect(page.getByText('Removed the message from the queue')).toBeVisible();
                expect((await request.get(`/v1/outbox/${queueId}`, { headers: auth })).status()).toBe(404);

                expect(errors).toHaveLength(0);
            } finally {
                // the later specs share this instance, so the queue must not stay paused
                await request.put('/v1/settings/queue/submit', { headers: auth, data: { paused: false } });
                await teardown();
            }
        });

        test('the account page counts it and links to the filtered listing', async ({ page, request }) => {
            const { queueMessage, teardown } = await setup(page, request);
            try {
                await queueMessage(`e2e account card ${Date.now()}`);

                await page.goto(`${BASE_URL}/admin/accounts/${ACCOUNT_ID}`);
                const link = page.locator(`a[href="/admin/queues/submit?account=${ACCOUNT_ID}"]`, { hasText: 'waiting or scheduled' });
                await expect(link).toBeVisible();
                await link.click();
                await expect(page).toHaveURL(new RegExp(`/admin/queues/submit\\?account=${ACCOUNT_ID}$`));
            } finally {
                await teardown();
            }
        });
    });
});
