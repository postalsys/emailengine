'use strict';

// What the queue browser knows about each BullMQ queue and each job state: the wording, the order
// things are listed in, and which actions apply. Dependency-free on purpose - the formatters and
// the tests read it without opening Redis, and the routes read it to validate what a URL names.

// The job states a queue is browsed by, in the order the tabs show them. BullMQ 6 has no `paused`
// state (a paused queue holds its jobs in `waiting`), and `prioritized` and `waiting-children`
// are never used here, so they are not offered.
const STATES = [
    {
        name: 'waiting',
        label: 'Waiting',
        variant: 'info',
        description: 'Ready to run as soon as a worker is free. A paused queue holds its jobs here',
        // Listed first-in first-out, so the top of the list is what runs next
        newestFirst: false
    },
    {
        name: 'active',
        label: 'Active',
        variant: 'primary',
        description: 'Being processed by a worker right now',
        newestFirst: false
    },
    {
        name: 'delayed',
        label: 'Delayed',
        variant: 'neutral',
        description: 'Waiting for a scheduled time, or for the backoff before the next attempt. Soonest first',
        newestFirst: false
    },
    {
        name: 'failed',
        label: 'Failed',
        variant: 'error',
        description: 'Given up on: every attempt failed, or the failure was permanent. Most recent first',
        newestFirst: true
    },
    {
        name: 'completed',
        label: 'Completed',
        variant: 'success',
        description: 'Finished successfully. Kept only while the completed job history limit allows. Most recent first',
        newestFirst: true
    }
];

const STATE_NAMES = STATES.map(state => state.name);

const STATES_BY_NAME = new Map(STATES.map(state => [state.name, state]));

// The queues, in the order the overview shows them.
//
// `concurrency` names where the per-worker job concurrency and the worker thread count come from,
// so the overview can say how many jobs the queue can run at once. `actions` is what the browser
// offers on a job of this queue: exports are driven from the account's own export pages, where
// cancelling one also removes its file, so the export queue is read-only here.
const QUEUES = [
    {
        name: 'notify',
        label: 'Webhooks',
        title: 'Webhooks queue',
        noun: 'webhook delivery',
        nounPlural: 'webhook deliveries',
        icon: 'icon-[tabler--webhook]',
        description: 'Every email event that may trigger a webhook. An event no webhook is configured for completes without sending anything.',
        // what the search box says it looks through
        searchHint: 'Search by event, route, account, subject or message ID',
        concurrency: { workersEnv: 'EENGINE_WORKERS_WEBHOOKS', workersConfig: 'webhooks', concurrencyEnv: 'EENGINE_NOTIFY_QC', concurrencyConfig: 'notify' },
        actions: { retry: true, promote: true, remove: true }
    },
    {
        name: 'submit',
        label: 'Outgoing messages',
        title: 'Outgoing messages queue',
        noun: 'message',
        nounPlural: 'messages',
        icon: 'icon-[tabler--send]',
        description: 'Messages queued for delivery through SMTP or the provider API, including scheduled sends and retries.',
        searchHint: 'Search by subject, address, account, message or queue ID',
        concurrency: { workersEnv: 'EENGINE_WORKERS_SUBMIT', workersConfig: 'submit', concurrencyEnv: 'EENGINE_SUBMIT_QC', concurrencyConfig: 'submit' },
        actions: { retry: true, promote: true, remove: true }
    },
    {
        name: 'export',
        label: 'Exports',
        title: 'Exports queue',
        noun: 'export',
        nounPlural: 'exports',
        icon: 'icon-[tabler--package-export]',
        description: 'Mailbox exports waiting for an export worker. An export itself is managed from its account page.',
        searchHint: 'Search by export or account ID',
        concurrency: { workersEnv: 'EENGINE_WORKERS_EXPORT', workersConfig: 'export', concurrencyEnv: 'EENGINE_EXPORT_QC', concurrencyConfig: 'export' },
        actions: { retry: false, promote: false, remove: false }
    }
];

const QUEUE_NAMES = QUEUES.map(queue => queue.name);

const QUEUES_BY_NAME = new Map(QUEUES.map(queue => [queue.name, queue]));

// The default tab of a queue page. Waiting rather than "whatever is non-empty": a default that
// moves between visits is a page the reader cannot form a habit on, and the overview links every
// count straight to its own tab anyway.
const DEFAULT_STATE = 'waiting';

// How many jobs a filtered listing reads before it stops looking. A BullMQ queue has no index by
// account or by anything else in the payload, so a filter is a scan of the state's list, and a
// scan that reads every job of a busy queue would read every webhook payload with it. Within this
// bound the search is exact; past it the page says how far it looked.
const SCAN_LIMIT = 500;

// Jobs read per round trip while listing or scanning
const BATCH_SIZE = 50;

module.exports = {
    STATES,
    STATE_NAMES,
    STATES_BY_NAME,
    QUEUES,
    QUEUE_NAMES,
    QUEUES_BY_NAME,
    DEFAULT_STATE,
    SCAN_LIMIT,
    BATCH_SIZE
};
