'use strict';

// Render tests for the queue browser's listing partials. The per-entry actions menu is a
// ui/row-actions block, and a block whose content is nothing but {{#if}} wrappers loses it
// to the Handlebars program-association bug (see .claude/rules/admin-ui.md) - which is exactly
// what happened to this menu once: every row offered only "Open". Rendering the real template
// with the real partials is the only thing that notices.

const test = require('node:test');
const assert = require('node:assert').strict;
const { compileView } = require('./helpers/admin-templates');

const actionsTemplate = compileView('partials/queue_entry_actions.hbs');
const submitRowsTemplate = compileView('partials/queue_rows_submit.hbs');
const notifyRowsTemplate = compileView('partials/queue_rows_notify.hbs');
const overviewTemplate = compileView('queues/index.hbs');
const retentionNoteTemplate = compileView('partials/queue_retention_note.hbs');
const jobTemplate = compileView('queues/job.hbs');

function entry(overrides) {
    return Object.assign(
        {
            id: 'q1',
            url: '/admin/queues/submit/jobs/q1',
            title: 'Hello there',
            state: 'waiting',
            stateInfo: { name: 'waiting', label: 'Waiting', variant: 'info' },
            account: 'acc',
            accountKnown: true,
            created: '2026-10-14T10:00:00.000Z',
            when: { label: 'Queued', time: '2026-10-14T10:00:00.000Z' },
            attemptsLabel: '0 of 10',
            attemptsMade: 0,
            from: 'a@example.com',
            to: ['b@example.com'],
            toFirst: 'b@example.com',
            toMore: 0,
            failure: null,
            canPromote: false,
            canRetry: false,
            canRemove: true
        },
        overrides
    );
}

test('queue entry actions menu', async t => {
    await t.test('offers exactly the actions the entry allows, after Open', () => {
        const waiting = actionsTemplate(entry());
        assert.match(waiting, /href="\/admin\/queues\/submit\/jobs\/q1">Open</);
        // removal goes through the shared .list-delete-btn flow, aimed at the page's dialog
        assert.match(waiting, /list-delete-btn[^>]*data-delete-modal="#removeJob"[^>]*data-delete-action="\/admin\/queues\/submit\/jobs\/q1\/remove"/);
        assert.doesNotMatch(waiting, /\/promote"/);
        assert.doesNotMatch(waiting, /\/retry"/);

        // the actions are plain forms carrying the page's crumb and return target, so they work
        // before the page script has run and without it
        const delayed = actionsTemplate(entry({ canPromote: true }), { data: { root: { crumb: 'c1', currentUrl: '/admin/queues/submit' } } });
        assert.match(
            delayed,
            /<form method="post" action="\/admin\/queues\/submit\/jobs\/q1\/promote">\s*<input type="hidden" name="crumb" value="c1">\s*<input type="hidden" name="next" value="\/admin\/queues\/submit">/
        );
        assert.match(delayed, />Send now</);

        const failed = actionsTemplate(entry({ state: 'failed', canRetry: true }));
        assert.match(failed, /action="\/admin\/queues\/submit\/jobs\/q1\/retry"/);
        assert.match(failed, />Retry</);

        const active = actionsTemplate(entry({ state: 'active', canRemove: false }));
        assert.match(active, />Open</);
        assert.doesNotMatch(active, /<form|list-delete-btn/, 'an entry a worker is running offers nothing');
    });

    await t.test('a failed message without content keeps Retry, disabled, with the reason', () => {
        const html = actionsTemplate(entry({ state: 'failed', canRetry: false, retryBlockedReason: 'Nothing to send' }));
        assert.match(html, /<span class="tooltip-body">Nothing to send<\/span>/);
        assert.match(html, /<span class="dropdown-item dropdown-disabled w-full" aria-disabled="true">Retry<\/span>/);
        assert.doesNotMatch(html, /\/retry"/);
    });

    await t.test('the removal names the entry, escaped', () => {
        const html = actionsTemplate(entry({ title: 'Quarterly <b>invoice</b>' }));
        assert.match(html, /data-delete-name="Quarterly &lt;b&gt;invoice&lt;\/b&gt;"/);
    });
});

test('queue listing rows', async t => {
    await t.test('a failed message row carries the short failure label, the reason and the actions', () => {
        const html = submitRowsTemplate({
            listing: {
                entries: [
                    entry({
                        state: 'failed',
                        stateInfo: { name: 'failed', label: 'Failed', variant: 'error' },
                        finishedOn: '2026-10-14T10:05:00.000Z',
                        when: { label: 'Failed', time: '2026-10-14T10:05:00.000Z' },
                        attemptsLabel: '10 of 10',
                        failure: { label: 'Rejected by the receiving server', shortLabel: 'Rejected 550', reason: '550 No such user', permanent: true },
                        hasContent: true,
                        canRetry: true
                    })
                ]
            }
        });

        assert.match(html, /Rejected 550/);
        assert.match(html, /550 No such user/);
        assert.doesNotMatch(html, /Content discarded/);
        assert.match(html, /action="\/admin\/queues\/submit\/jobs\/q1\/retry"/);
        assert.match(html, /data-delete-action="\/admin\/queues\/submit\/jobs\/q1\/remove"/);
        assert.match(html, /Failed<\/span> <span class="relative-time" data-time="2026-10-14T10:05:00.000Z">/);
    });

    await t.test('a failed message whose content is gone says so and offers no retry', () => {
        const html = submitRowsTemplate({
            listing: {
                entries: [
                    entry({
                        state: 'failed',
                        stateInfo: { name: 'failed', label: 'Failed', variant: 'error' },
                        when: { label: 'Failed', time: '2026-10-14T10:05:00.000Z' },
                        failure: { label: 'Delivery failed', shortLabel: 'Failed', reason: 'x' },
                        hasContent: false,
                        canRetry: false
                    })
                ]
            }
        });
        assert.match(html, /Content discarded/);
        assert.doesNotMatch(html, /\/retry"/);
    });

    await t.test('a webhook row names the route, or the default target, and flags a deleted account', () => {
        const base = {
            id: '42',
            url: '/admin/queues/notify/jobs/42',
            title: 'messageNew',
            event: 'messageNew',
            state: 'waiting',
            account: 'gone',
            accountKnown: false,
            created: '2026-10-14T10:00:00.000Z',
            when: { label: 'Queued', time: '2026-10-14T10:00:00.000Z' },
            attemptsLabel: '0 of 10',
            failure: null,
            canRemove: true
        };
        const routed = notifyRowsTemplate({ listing: { entries: [Object.assign({}, base, { routeId: 'r1', routeKnown: true, routeName: 'CRM sync' })] } });
        assert.match(routed, /href="\/admin\/webhooks\/webhook\/r1"[^>]*>CRM sync</);
        assert.match(routed, /Account deleted/);

        const unrouted = notifyRowsTemplate({ listing: { entries: [Object.assign({}, base, { account: 'acc', accountKnown: true })] } });
        assert.match(unrouted, /default webhook/);
        assert.match(unrouted, /href="\/admin\/accounts\/acc"/);

        const orphan = notifyRowsTemplate({ listing: { entries: [Object.assign({}, base, { routeId: 'r1', routeKnown: false })] } });
        assert.match(orphan, /Route deleted/);
    });
});

test('queue retention note', async t => {
    const note = (queueName, stateName, overrides) =>
        retentionNoteTemplate(
            Object.assign(
                {
                    userLocale: 'en',
                    queue: { name: queueName, keepsFinished: queueName !== 'export' },
                    state: { name: stateName },
                    retention: { completedCount: 0, failedCount: 500, failedAgeDays: 7 },
                    failedContent: { limits: { maxCount: 100, maxBytesLabel: '100 MB', keepsContent: true } }
                },
                overrides
            )
        );
    const text = html =>
        html
            .replace(/<[^>]+>/g, '')
            .replace(/\s+/g, ' ')
            .trim();

    await t.test('says what the failed tab keeps and names the variables that set it', () => {
        const webhooks = text(note('notify', 'failed'));
        assert.match(webhooks, /^The most recent 500 are kept for 7 days, set with EENGINE_QUEUE_KEEP_FAILED and EENGINE_QUEUE_KEEP_FAILED_AGE\.$/);

        const messages = text(note('submit', 'failed', { retention: { completedCount: 0, failedCount: 2000, failedAgeDays: 1 } }));
        assert.match(messages, /The most recent 2,000 are kept for 1 day, set with/);
        assert.match(
            messages,
            /The content of the 100 most recent failed messages is kept so they can be retried, up to 100 MB in total, set with EENGINE_QUEUE_KEEP_FAILED_CONTENT and EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE\./
        );

        const noContent = text(note('submit', 'failed', { failedContent: { limits: { maxCount: 100, maxBytesLabel: '0 B', keepsContent: false } } }));
        assert.match(
            noContent,
            /The content of a failed message is not kept, so none can be retried from here; set EENGINE_QUEUE_KEEP_FAILED_CONTENT to keep some\./
        );

        assert.match(text(note('export', 'failed')), /^Exports are not kept here once they fail; an export's outcome is on its account's page\.$/);
    });

    await t.test('says what the completed tab keeps and links the setting that changes it', () => {
        const none = note('notify', 'completed');
        assert.match(
            text(none),
            /^Removed as soon as they finish\. To keep the most recent ones for a day, raise the completed job history limit in General settings\.$/
        );
        assert.match(none, /href="\/admin\/config\/service#queue_settings"/);

        const some = text(note('submit', 'completed', { retention: { completedCount: 25, failedCount: 500, failedAgeDays: 7 } }));
        assert.match(some, /^The most recent 25 are kept for at most a day, as set by the completed job history limit in General settings\.$/);

        assert.match(text(note('export', 'completed')), /^Exports are not kept here once they finish; an export's result is on its account's page\.$/);
    });

    await t.test('renders nothing for the other states', () => {
        for (const stateName of ['waiting', 'active', 'delayed']) {
            assert.equal(text(note('submit', stateName)), '');
        }
    });
});

test('queue entry page', async t => {
    const page = (overrides, root) =>
        jobTemplate(
            Object.assign(
                {
                    crumb: 'c1',
                    currentUrl: '/admin/queues/submit/jobs/q1',
                    listHref: '/admin/queues/submit?state=failed',
                    userLocale: 'en',
                    queue: { name: 'submit', label: 'Outgoing messages', icon: 'icon-[tabler--send]', noun: 'message' },
                    entry: Object.assign(
                        entry({
                            state: 'failed',
                            stateInfo: { name: 'failed', label: 'Failed', variant: 'error' },
                            failure: { label: 'Rejected by the receiving server', reason: '550 No such user', permanent: true },
                            attemptsLabel: '1 of 1',
                            raw: '{}'
                        }),
                        overrides
                    )
                },
                root
            )
        );

    await t.test('offers Retry as a form while the content is kept, and disabled with the reason once it is gone', () => {
        const kept = page({ hasContent: true, canRetry: true });
        assert.match(
            kept,
            /<form method="post" action="\/admin\/queues\/submit\/jobs\/q1\/retry">\s*<input type="hidden" name="crumb" value="c1">\s*<input type="hidden" name="next" value="\/admin\/queues\/submit\/jobs\/q1">/
        );
        assert.doesNotMatch(kept, /disabled class="btn/);

        const gone = page({ hasContent: false, canRetry: false, retryBlockedReason: 'Nothing to send' });
        assert.doesNotMatch(gone, /\/retry"/);
        // the button is inside the tooltip's trigger, disabled, and the tooltip carries the reason
        assert.match(gone, /<span class="tooltip-toggle cursor-default">\s*<button type="button" disabled class="btn btn-primary btn-sm pointer-events-none">/);
        assert.match(gone, /<span class="tooltip-body">Nothing to send<\/span>/);
        // the actions sit in the page header, after Back to list, with the kebab last and the
        // details card after all of them
        const order = ['<h1', 'Back to list', '>Retry<', 'aria-label="More entry actions"', 'class="ee-dl"'].map(marker => gone.indexOf(marker));
        assert.ok(order.every(index => index >= 0) && order.every((index, i) => i === 0 || index > order[i - 1]), `page order: ${order.join(' < ')}`);
    });
});

test('queue overview', async t => {
    const queue = name => ({
        name,
        label: name,
        title: `${name} queue`,
        nounPlural: 'entries',
        icon: 'icon-[tabler--webhook]',
        description: 'd',
        isPaused: name === 'submit',
        concurrency: { workers: 1, perWorker: 2, total: 2, workersEnv: 'W', concurrencyEnv: 'C' },
        stateCounts: [{ name: 'waiting', label: 'Waiting', variant: 'info', count: 0, url: `/admin/queues/${name}?state=waiting` }]
    });

    const overview = (context = {}) =>
        overviewTemplate(
            Object.assign(
                {
                    crumb: 'c',
                    userLocale: 'en',
                    queues: [queue('notify'), queue('submit')],
                    failedContent: { count: 0, bytesLabel: '0 B', limits: { maxCount: 100, maxBytesLabel: '100 MB', maxAgeDays: 7 } },
                    retention: { completedCount: 0, failedCount: 500, failedAgeDays: 7 }
                },
                context
            )
        );
    await t.test('every queue card carries its pause controls and both clean items', () => {
        const html = overview();

        for (const name of ['notify', 'submit']) {
            assert.match(html, new RegExp(`action="/admin/queues/${name}/pause"`));
            assert.match(html, new RegExp(`action="/admin/queues/${name}/resume"`));
            assert.match(html, new RegExp(`queue-clean-btn" data-queue="${name}"[^>]*data-state="completed"`));
            assert.match(html, new RegExp(`queue-clean-btn" data-queue="${name}"[^>]*data-state="failed"`));
        }
        // the facts tooltips put one fact per line (the newline survives into the attribute-free body)
        assert.match(html, /<span class="tooltip-body whitespace-pre-line text-start">1 worker thread \(W\)\n2 jobs at a time each \(C\)<\/span>/);
        assert.match(
            html,
            /up to 100 messages \(EENGINE_QUEUE_KEEP_FAILED_CONTENT\)\nup to 100 MB in total \(EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE\)\nfor 7 days \(EENGINE_QUEUE_KEEP_FAILED_AGE\)/
        );

        // the paused queue shows its resume form and hides the pause form
        assert.match(html, /action="\/admin\/queues\/submit\/pause" data-queue-active-only="submit" class="hidden"/);
        assert.match(html, /action="\/admin\/queues\/notify\/resume" data-queue-paused="notify" class="hidden"/);
    });

    await t.test('the help panel lists the states in tile order and reports the live retention', () => {
        const html = overview();
        const states = [...html.matchAll(/<li><strong>([A-Za-z]+)<\/strong>:/g)].map(m => m[1]);
        assert.deepEqual(states, ['Waiting', 'Active', 'Delayed', 'Failed', 'Completed']);
        assert.match(html, /keep their most recent 500 failed\s+entries for 7 days/);
        assert.match(html, /are removed as soon as they finish, as set by the completed job history limit/);
        // paragraphs carry their own spacing, the way every other help panel does it
        assert.match(html, /<p class="mb-2">Webhook deliveries/);

        const kept = overview({ retention: { completedCount: 1250, failedCount: 2000, failedAgeDays: 1 } });
        assert.match(kept, /keep their\s+most recent 1,250 for at most a day, as set by/);
        assert.match(kept, /keep their most recent 2,000 failed\s+entries for 1 day\./);
    });
});
