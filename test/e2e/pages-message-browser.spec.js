'use strict';

// The message browser (the @postalsys/ee-client widget on /admin/accounts/{account}/browse) as a
// mail client: a ?message= deep link, the address bar following the open message, reply, reply-all
// with a recipient removed, forward with the original attachments, a new message with Cc and an
// uploaded file, a reply saved as a draft, and the replied marker on the original. The compose form
// is the widget's docked panel (ee-client 2), whose message body is a rich text editor.
//
// Ethereal loops everything an account sends back into that account's own inbox, whatever the
// recipient, so every message sent here can be read back over the API and nobody receives anything.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker), and registers its own account rather than relying on happy-path.spec.js.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect, request } = require('./helpers/test');
const { useAdminSession, createApiToken, dismissTokenReveal, expectModalOpen, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');
const { createUsableTestAccount, etherealAccountPayload } = require('./helpers/ethereal');

const ACCOUNT_ID = 'e2e-message-browser';

test.describe('message browser', () => {
    useAdminSession(test, 'message-browser');

    test('reply, reply-all, forward and compose from the message browser', async ({ page }) => {
        test.setTimeout(420000);
        const errors = trackConsoleErrors(page);

        const token = await createApiToken(page, `e2e message browser ${Date.now()}`);
        await dismissTokenReveal(page);
        const api = await request.newContext({ baseURL: BASE_URL, extraHTTPHeaders: { Authorization: `Bearer ${token}` } });

        // Polls the inbox for a message with this subject and returns its details
        const findMessage = async (subject, path = 'INBOX') => {
            let found;
            await expect
                .poll(
                    async () => {
                        const res = await api.get(`/v1/account/${ACCOUNT_ID}/messages?path=${encodeURIComponent(path)}&pageSize=50`);
                        found = res.ok() && (await res.json()).messages.find(message => message.subject === subject);
                        return !!found;
                    },
                    { message: `"${subject}" in ${path}`, timeout: 120000, intervals: [2000, 3000, 5000] }
                )
                .toBe(true);
            return (await api.get(`/v1/account/${ACCOUNT_ID}/message/${found.id}?textType=plain`)).json();
        };

        // Outcomes show as a short notice at the bottom of the widget; a new one replaces the last
        const notice = async text => {
            await expect(page.locator('.ee-toast.show')).toHaveText(text);
        };

        const compose = page.locator('.ee-compose-dialog');
        const field = name => compose.locator(`[name="${name}"]`);
        const editor = compose.locator('.ee-compose-editor');

        try {
            const acct = await createUsableTestAccount();
            const created = await api.post('/v1/account', { data: { account: ACCOUNT_ID, name: 'E2E Browser', ...etherealAccountPayload(acct) } });
            expect(created.ok(), `POST /v1/account -> ${created.status()} ${await created.text()}`).toBeTruthy();
            await expect
                .poll(async () => (await (await api.get(`/v1/account/${ACCOUNT_ID}`)).json()).state, { timeout: 120000, intervals: [1000, 2000, 3000] })
                .toBe('connected');

            const stamp = Date.now();
            const subject = `Browser seed ${stamp}`;
            const other = `other-${stamp}@example.com`;
            const copied = `copied-${stamp}@example.com`;

            const seeded = await api.post(`/v1/account/${ACCOUNT_ID}/submit`, {
                data: {
                    from: { name: 'E2E Browser', address: acct.user },
                    to: [{ address: acct.user }, { address: other }],
                    cc: [{ address: copied }],
                    subject,
                    text: 'The seed message body.',
                    attachments: [{ filename: 'seed.txt', content: Buffer.from('seed attachment').toString('base64'), contentType: 'text/plain' }]
                }
            });
            expect(seeded.ok(), `seed submit -> ${seeded.status()} ${await seeded.text()}`).toBeTruthy();
            const seed = await findMessage(subject);

            await test.step('a ?message= link opens the message, and the address bar follows the reader', async () => {
                await page.goto(`/admin/accounts/${ACCOUNT_ID}/browse?message=${encodeURIComponent(seed.id)}`, { waitUntil: 'load' });
                await expect(page.locator('.ee-message-title')).toHaveText(subject);
                await expect(page.locator('.ee-message-item.active')).toContainText(subject);
                // icons are drawn, not emoji
                await expect(page.locator('.ee-message-item.active .ee-attachment-indicator svg')).toHaveCount(1);

                // a folder change closes the message, and the link with it
                await page.locator('.ee-folder-item[data-path="Drafts"]').click();
                await expect(page).not.toHaveURL(/[?&]message=/);
                await page.locator('.ee-folder-item[data-path="INBOX"]').click();
                await page.locator('.ee-message-item').filter({ hasText: subject }).click();
                await expect(page).toHaveURL(new RegExp(`[?&]message=${encodeURIComponent(seed.id)}`));
            });

            const replyText = `A reply ${stamp}`;
            await test.step('reply quotes the original and threads under it', async () => {
                await page.locator('.ee-message-viewer [data-action="reply"]').click();
                await expect(compose).toBeVisible();
                await expect(compose.locator('.ee-compose-title')).toHaveText('Reply');
                await expect(field('subject')).toHaveValue(`Re: ${subject}`);
                // answering a message the account sent itself goes to the people it went to
                await expect(field('to')).toHaveValue(other);
                // the quote is folded until asked for, and a reply carries no files
                await expect(compose.locator('.ee-compose-quote-toggle')).toHaveAttribute('aria-expanded', 'false');
                await expect(compose.locator('.ee-compose-chip')).toHaveCount(0);

                await editor.fill(replyText);
                await compose.locator('.ee-compose-send').click();
                await notice('Message queued for delivery.');
                await expect(compose).toBeHidden();

                const reply = await findMessage(`Re: ${subject}`);
                expect(reply.inReplyTo).toBe(seed.messageId);
                expect(reply.to.map(entry => entry.address)).toEqual([other]);
                expect(reply.text.plain).toContain(replyText);
                expect(reply.text.plain).toContain('The seed message body.');
            });

            await test.step('the original carries the replied marker once the reply is delivered', async () => {
                await expect
                    .poll(async () => (await (await api.get(`/v1/account/${ACCOUNT_ID}/message/${seed.id}`)).json()).flags || [], {
                        timeout: 60000,
                        intervals: [1000, 2000]
                    })
                    .toContain('\\Answered');
                await page.goto(`/admin/accounts/${ACCOUNT_ID}/browse?message=${encodeURIComponent(seed.id)}`, { waitUntil: 'load' });
                await expect(page.locator('.ee-message-title-markers')).toHaveText('Replied');
                await expect(page.locator('.ee-message-item.active .ee-response-marker[aria-label="Replied"]')).toHaveCount(1);
            });

            await test.step('reply-all sends to the recipients left in the form, not the original list', async () => {
                await page.locator('.ee-message-viewer [data-action="reply-all"]').click();
                await expect(compose.locator('.ee-compose-title')).toHaveText('Reply all');
                await expect(field('to')).toHaveValue(other);
                await expect(field('cc')).toBeVisible();
                await expect(field('cc')).toHaveValue(copied);

                await field('cc').fill('');
                await field('subject').fill(`Re: ${subject} (all)`);
                await editor.fill('To everyone left.');
                await compose.locator('.ee-compose-send').click();
                await notice('Message queued for delivery.');

                const replyAll = await findMessage(`Re: ${subject} (all)`);
                expect(replyAll.inReplyTo).toBe(seed.messageId);
                expect(replyAll.to.map(entry => entry.address)).toEqual([other]);
                expect(replyAll.cc || []).toEqual([]);
            });

            await test.step('a reply saved as a draft keeps its thread', async () => {
                await page.locator('.ee-message-viewer [data-action="reply"]').click();
                await field('subject').fill(`Re: ${subject} (draft)`);
                await editor.fill('Not sent yet.');
                await compose.locator('.ee-compose-save-draft').click();
                await notice('Draft saved.');

                const draft = await findMessage(`Re: ${subject} (draft)`, 'Drafts');
                expect(draft.inReplyTo).toBe(seed.messageId);
                expect(draft.text.plain).toContain('Not sent yet.');
            });

            await test.step('forward carries the original attachments', async () => {
                await page.locator('.ee-message-viewer [data-action="forward"]').click();
                await expect(compose.locator('.ee-compose-title')).toHaveText('Forward');
                await expect(field('subject')).toHaveValue(`Fwd: ${subject}`);
                await expect(field('to')).toHaveValue('');
                // the forwarded message shows with its header, and its files are listed as attachments
                await expect(compose.locator('.ee-compose-quote-header .ee-forward-title')).toHaveText('Forwarded message');
                await expect(compose.locator('.ee-compose-chip-name')).toHaveText(['seed.txt']);

                await field('to').fill(`forward-${stamp}@example.com`);
                // a forward needs no note of its own
                await compose.locator('.ee-compose-send').click();
                await notice('Message queued for delivery.');

                const forwarded = await findMessage(`Fwd: ${subject}`);
                expect((forwarded.attachments || []).map(att => att.filename)).toContain('seed.txt');
                expect(forwarded.text.plain).toContain('The seed message body.');
            });

            let composedId;
            await test.step('a new message takes several recipients, Cc and an uploaded file', async () => {
                const newSubject = `Composed ${stamp}`;
                // wide layouts have the Compose button at the top of the folder pane
                await page.locator('.ee-sidebar-compose-button').click();
                await expect(compose.locator('.ee-compose-title')).toHaveText('New message');
                await expect(field('cc')).toBeHidden();
                await expect(compose.locator('.ee-compose-quote')).toBeHidden();

                // a name without an address is refused before anything is sent
                await field('to').fill('just a name');
                await editor.fill('Hello there.');
                await compose.locator('.ee-compose-send').click();
                await expect(compose.locator('.ee-compose-error')).toHaveText('Not a valid email address: just a name');
                await expect(field('to')).toHaveAttribute('aria-invalid', 'true');

                await field('to').fill(`"Doe, Jane" <jane-${stamp}@example.com>, second-${stamp}@example.com`);
                await compose.locator('[data-action="show-cc"]').click();
                await field('cc').fill(`cc-${stamp}@example.com`);
                await field('subject').fill(newSubject);
                await compose
                    .locator('.ee-compose-file-input')
                    .setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('uploaded from the browser') });
                await expect(compose.locator('.ee-compose-chip')).toContainText('notes.txt');

                // a removed file is not sent
                await compose.locator('.ee-compose-file-input').setInputFiles({ name: 'dropped.txt', mimeType: 'text/plain', buffer: Buffer.from('x') });
                await compose.locator('.ee-compose-chip').filter({ hasText: 'dropped.txt' }).locator('.ee-compose-chip-remove').click();
                await expect(compose.locator('.ee-compose-chip')).toHaveCount(1);

                await compose.locator('.ee-compose-send').click();
                await notice('Message queued for delivery.');

                const composed = await findMessage(newSubject);
                composedId = composed.id;
                expect(composed.to.map(({ name, address }) => ({ name: name || '', address }))).toEqual([
                    { name: 'Doe, Jane', address: `jane-${stamp}@example.com` },
                    { name: '', address: `second-${stamp}@example.com` }
                ]);
                expect(composed.cc.map(entry => entry.address)).toEqual([`cc-${stamp}@example.com`]);
                expect(composed.attachments.map(att => att.filename)).toEqual(['notes.txt']);
            });

            await test.step('closing an unsaved message asks in a dialog the compose panel does not cover', async () => {
                // at this width the docked panel overlaps the centre of the page, where the
                // dialog opens; a click on a covered button fails the actionability check
                // (the one-pane layout, so the form is opened from the message rather than the
                // folder pane's Compose button)
                await page.setViewportSize({ width: 1024, height: 768 });
                await page.goto(`/admin/accounts/${ACCOUNT_ID}/browse?message=${encodeURIComponent(seed.id)}`, { waitUntil: 'load' });
                await page.locator('.ee-message-viewer [data-action="reply"]').click({ timeout: 10000 });
                await editor.fill('Not finished.');
                await compose.locator('[data-action="close"]').click({ timeout: 10000 });
                const modal = page.locator('#confirmModal');
                await expectModalOpen(modal);
                await expect(page.locator('#confirmModalLabel')).toHaveText('Unsaved message');
                await page.locator('#confirm-cancel').click({ timeout: 10000 });
                await expect(compose).toBeHidden();
                await page.setViewportSize({ width: 1280, height: 720 });
            });

            await test.step('delete says where the message goes, and confirms it went', async () => {
                await page.goto(`/admin/accounts/${ACCOUNT_ID}/browse?message=${encodeURIComponent(composedId)}`, { waitUntil: 'load' });
                await page.locator('.ee-message-viewer [data-action="delete"]').click();
                const modal = page.locator('#confirmModal');
                await expectModalOpen(modal);
                await expect(page.locator('#confirm-text')).toHaveText('Delete this message?');
                await page.locator('#confirm-ok').click();
                await notice('Message moved to Trash.');
                await expect(page.locator('.ee-message-item').filter({ hasText: `Composed ${stamp}` })).toHaveCount(0);
            });

            expect(errors, 'no console errors').toEqual([]);
        } finally {
            await api.delete(`/v1/account/${ACCOUNT_ID}`);
            await api.dispose();
        }
    });
});
