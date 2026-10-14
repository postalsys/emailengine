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

test('queue overview', async t => {
    await t.test('every queue card carries its pause controls and both clean items', () => {
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
        const html = overviewTemplate({
            crumb: 'c',
            queues: [queue('notify'), queue('submit')],
            failedContent: { count: 0, bytesLabel: '0 B', limits: { maxCount: 100, maxBytesLabel: '100 MB', maxAgeDays: 7 } }
        });

        for (const name of ['notify', 'submit']) {
            assert.match(html, new RegExp(`action="/admin/queues/${name}/pause"`));
            assert.match(html, new RegExp(`action="/admin/queues/${name}/resume"`));
            assert.match(html, new RegExp(`queue-clean-btn" data-queue="${name}"[^>]*data-state="completed"`));
            assert.match(html, new RegExp(`queue-clean-btn" data-queue="${name}"[^>]*data-state="failed"`));
        }
        // the paused queue shows its resume form and hides the pause form
        assert.match(html, /action="\/admin\/queues\/submit\/pause" data-queue-active-only="submit" class="hidden"/);
        assert.match(html, /action="\/admin\/queues\/notify\/resume" data-queue-paused="notify" class="hidden"/);
    });
});
