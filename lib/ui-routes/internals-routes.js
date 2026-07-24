'use strict';

// Admin UI routes for the system internals / threads tools (/admin/internals*): the
// worker-thread overview, kill/snapshot actions, and the per-thread account listing.
// Extracted verbatim from lib/routes-ui.js.

const Joi = require('joi');
const Boom = require('@hapi/boom');

const settings = require('../settings');
const { Account } = require('../account');
const { redis } = require('../db');
const { DEFAULT_PAGE_SIZE } = require('../consts');
const { formatAccountData } = require('./route-helpers');

// Worker kinds in the order they are shown on the internals page (known kinds first; any
// unrecognized kind is appended so nothing is dropped).
const THREAD_TYPE_ORDER = ['main', 'api', 'imap', 'webhooks', 'submit', 'export', 'smtp', 'imapProxy', 'documents'];

// Severity ranking for the per-group health roll-up (higher wins).
const STATUS_RANK = { success: 0, neutral: 1, warning: 2, error: 3 };

// Short description of what each worker kind does, shown on the group card header.
const THREAD_PURPOSE = {
    main: 'Orchestrates everything else: spawns and monitors the other worker threads, assigns email accounts to the sync workers, routes inter-thread calls, and manages the Redis connection and licensing.',
    api: 'Serves the REST API and the admin web interface (including this page), the OpenAPI documentation, and real-time account updates.',
    imap: 'Keeps email accounts in sync - IMAP, Gmail API and Outlook/Graph - maintaining connections, detecting new and changed messages in real time, and running message and mailbox operations.',
    webhooks: 'Delivers webhook notifications for email and account events over HTTP, with automatic retries and optional per-route filtering and transforms.',
    submit: 'Sends queued outbound email through SMTP or a provider API (Gmail, Outlook), with retries and delivery, bounce and complaint tracking.',
    export: 'Runs bulk account export jobs, extracting matching messages into compressed files for download.',
    documents: 'Indexes emails into the Document Store (ElasticSearch) for search and processing. This is a deprecated feature.',
    smtp: 'Accepts SMTP submissions from legacy applications and queues them for delivery through the associated account.',
    imapProxy: 'Lets standard IMAP clients reach EmailEngine-managed accounts, hiding the OAuth2 complexity of providers like Gmail and Microsoft 365.'
};

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/admin/internals',
        async handler(request, h) {
            let threads = await call({ cmd: 'threads' });

            // Surface a warning when more API workers were requested than could be started
            let apiWorkerScaling;
            try {
                apiWorkerScaling = await call({ cmd: 'apiWorkerScaling' });
            } catch (err) {
                apiWorkerScaling = false;
            }

            let defaultLocale = (await settings.get('locale')) || 'en';

            let bytesFormatter;

            let bytesFormatterOpts = {
                style: 'unit',
                unit: 'byte',
                notation: 'compact',
                unitDisplay: 'narrow'
            };

            try {
                bytesFormatter = new Intl.NumberFormat(defaultLocale, bytesFormatterOpts);
            } catch (err) {
                bytesFormatter = new Intl.NumberFormat('en-US', bytesFormatterOpts);
            }

            // Process each thread into row data. The per-thread config (expected worker
            // count) is intentionally NOT surfaced per row here - it is a pool-level fact
            // and is shown once on the group header below.
            let processedThreads = threads.map(threadInfo => {
                // Unresponsive / errored worker: the resource-usage probe failed or timed out.
                if (threadInfo.resourceUsageError) {
                    threadInfo.isUnresponsive = true;
                    threadInfo.errorMessage = threadInfo.resourceUsageError.error;
                }

                // CPU metrics removed to prevent potential native code issues

                // Single health signal (variant + label) used by both the per-row status dot
                // and the per-group roll-up badge.
                threadInfo.statusVariant = 'success';
                threadInfo.statusLabel = 'Healthy';
                if (threadInfo.isUnresponsive) {
                    threadInfo.statusVariant = 'error';
                    threadInfo.statusLabel = 'Unresponsive';
                } else {
                    switch (threadInfo.healthStatus) {
                        case 'critical':
                        case 'restarting':
                            threadInfo.statusVariant = 'error';
                            threadInfo.statusLabel = 'Critical';
                            break;
                        case 'unhealthy':
                            threadInfo.statusVariant = 'warning';
                            threadInfo.statusLabel = 'Unhealthy';
                            break;
                        case 'unknown':
                            threadInfo.statusVariant = 'neutral';
                            threadInfo.statusLabel = 'Unknown';
                            break;
                        // 'healthy' or undefined -> success / Healthy
                    }
                }

                if (threadInfo.online) {
                    threadInfo.timeStr = new Date(threadInfo.online).toISOString();
                }

                // Format the heap reading for responsive threads. Unresponsive ones have no
                // reading, so the Memory cell shows a dash and the Status column carries the
                // state (heapTotal/rss/external are available but deliberately not displayed).
                if (!threadInfo.isUnresponsive && typeof threadInfo.heapUsed === 'number') {
                    threadInfo.heapUsed = bytesFormatter.format(threadInfo.heapUsed).replace(/BB$/, 'GB');
                }

                return threadInfo;
            });

            // Group threads by worker kind so the pool-level facts (expected vs actual count,
            // config env var, health roll-up) live on the group header instead of being
            // repeated on every member row.
            let groupMap = new Map();
            for (let threadInfo of processedThreads) {
                if (!groupMap.has(threadInfo.type)) {
                    groupMap.set(threadInfo.type, []);
                }
                groupMap.get(threadInfo.type).push(threadInfo);
            }

            let orderedTypes = THREAD_TYPE_ORDER.filter(type => groupMap.has(type)).concat(
                [...groupMap.keys()].filter(type => !THREAD_TYPE_ORDER.includes(type))
            );

            let groups = orderedTypes.map(type => {
                let list = groupMap.get(type);
                let cfg = list[0].config; // { key, value } expected-count config, or undefined
                let expected = cfg && cfg.value != null ? Number(cfg.value) : null;
                let hasExpected = expected !== null && !isNaN(expected);
                let actual = list.length;

                // Fleet completeness: green when the running count matches the configured
                // count, red when a worker is missing (crashed and not restarted), amber when
                // there are more running than configured.
                let countVariant = 'neutral';
                if (hasExpected) {
                    countVariant = actual < expected ? 'error' : actual > expected ? 'warning' : 'success';
                }

                // Health roll-up = worst member status.
                let rollup = list.reduce(
                    (worst, threadInfo) =>
                        STATUS_RANK[threadInfo.statusVariant] > STATUS_RANK[worst.variant]
                            ? { variant: threadInfo.statusVariant, label: threadInfo.statusLabel }
                            : worst,
                    { variant: 'success', label: 'Healthy' }
                );

                return {
                    type,
                    description: list[0].description || type,
                    purpose: THREAD_PURPOSE[type] || null,
                    threads: list,
                    hasExpected,
                    countLabel: hasExpected ? `${actual} / ${expected} running` : `${actual} running`,
                    countVariant,
                    configRef: hasExpected ? `${cfg.key}=${expected}` : null,
                    healthVariant: rollup.variant,
                    healthLabel: rollup.label
                };
            });

            return h.view(
                'internals/index',
                {
                    pageTitle: 'Workers',
                    menuWorkers: true,

                    threadCount: threads.length,

                    apiWorkerWarning: apiWorkerScaling && apiWorkerScaling.fallback ? apiWorkerScaling : false,

                    groups
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/internals/kill',
        async handler(request, h) {
            try {
                let killed = await call({ cmd: 'kill-thread', thread: request.payload.thread });
                if (killed) {
                    await request.flash({ type: 'info', message: `Worker stopped` });
                }

                return h.redirect('/admin/internals');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't stop worker. Try again.` });
                request.logger.error({ msg: 'Failed to kill thread', err, thread: request.payload.thread, remoteAddress: request.app.ip });
                return h.redirect('/admin/internals');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't stop worker. Try again.` });
                    request.logger.error({ msg: 'Failed to kill thread', err });

                    return h.redirect('/admin/internals').takeover();
                },

                payload: Joi.object({
                    thread: Joi.number().integer().min(1).max(1000000).required().example(1).description('Thread ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/internals/snapshot',
        async handler(request, h) {
            try {
                let snapshot = await call({ cmd: 'snapshot-thread', thread: request.payload.thread, timeout: 10 * 60 * 1000 });
                if (!snapshot) {
                    let error = Boom.boomify(new Error('Snapshot was not found'), { statusCode: 404 });
                    throw error;
                }

                return h
                    .response(Buffer.from(snapshot))
                    .header('Content-Type', 'application/octet-stream')
                    .header(
                        'Content-Disposition',
                        `attachment; filename=Heap-${new Date()
                            .toISOString()
                            .substring(0, 19)
                            .replace(/[^0-9T]+/g, '')}.heapsnapshot`
                    )
                    .header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0')
                    .header('Pragma', 'no-cache')
                    .code(200);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't create snapshot. Try again.` });
                request.logger.error({ msg: 'Failed to generate snapshot', err, thread: request.payload.thread, remoteAddress: request.app.ip });
                return h.redirect('/admin/internals');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't create snapshot. Try again.` });
                    request.logger.error({ msg: 'Failed to generate snapshot', err });

                    return h.redirect('/admin/internals').takeover();
                },

                payload: Joi.object({
                    thread: Joi.number().integer().empty('').min(0).max(1000000).required().example(1).description('Thread ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/internals/thread/{threadId}',
        async handler(request, h) {
            const threadId = request.params.threadId;

            // Get thread info to verify this is a valid email worker
            const threads = await call({ cmd: 'threads' });
            const threadInfo = threads.find(t => t.threadId === threadId);

            if (!threadInfo) {
                await request.flash({ type: 'danger', message: `Worker not found` });
                return h.redirect('/admin/internals');
            }

            if (threadInfo.type !== 'imap') {
                await request.flash({ type: 'warning', message: `Only email workers have assigned accounts` });
                return h.redirect('/admin/internals');
            }

            // Get accounts assigned to this worker
            const result = await call({
                cmd: 'worker-accounts',
                threadId,
                page: request.query.page,
                pageSize: request.query.pageSize
            });

            const runIndex = await call({ cmd: 'runIndex' });

            // Load account data for each account
            const accountsWithData = [];
            for (const accountId of result.accounts) {
                const accountObject = new Account({ redis, account: accountId });
                const accountData = await accountObject.loadAccountData(null, null, runIndex);
                if (accountData) {
                    accountsWithData.push(formatAccountData(accountData, request.app.gt));
                } else {
                    // Account exists in assignment but data couldn't be loaded
                    accountsWithData.push({
                        account: accountId,
                        name: accountId,
                        email: '',
                        type: { name: 'Unknown' },
                        stateLabel: { type: 'neutral', name: 'Unknown' }
                    });
                }
            }

            // Build pagination
            let nextPage = false;
            let prevPage = false;

            const getPagingUrl = page => {
                const url = new URL(`admin/internals/thread/${threadId}`, 'http://localhost');
                if (page) {
                    url.searchParams.append('page', page);
                }
                if (request.query.pageSize && request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }
                return url.pathname + url.search;
            };

            if (result.pages > result.page) {
                nextPage = getPagingUrl(result.page + 1);
            }

            if (result.page > 1) {
                prevPage = getPagingUrl(result.page - 1);
            }

            return h.view(
                'internals/thread',
                {
                    pageTitle: `Thread ${threadId} Accounts`,
                    menuWorkers: true,

                    threadId,
                    threadInfo: {
                        type: threadInfo.type,
                        description: threadInfo.description,
                        accounts: threadInfo.accounts
                    },

                    accounts: accountsWithData,
                    total: result.total,

                    showPaging: result.pages > 1,
                    nextPage,
                    prevPage,
                    pageLinks: new Array(result.pages).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i + 1 === result.page
                    }))
                },
                {
                    layout: 'app'
                }
            );
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to load thread accounts', err });
                    return h.redirect('/admin/internals').takeover();
                },

                params: Joi.object({
                    threadId: Joi.number().integer().min(0).max(1000000).required().description('Thread ID')
                }),

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });
}

module.exports = init;
