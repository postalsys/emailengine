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

            return h.view(
                'internals/index',
                {
                    pageTitle: 'Workers',
                    menuWorkers: true,

                    apiWorkerWarning: apiWorkerScaling && apiWorkerScaling.fallback ? apiWorkerScaling : false,

                    threads: threads.map(threadInfo => {
                        // Check if this worker is unresponsive
                        if (threadInfo.resourceUsageError) {
                            threadInfo.isUnresponsive = true;
                            threadInfo.heapUsed = threadInfo.resourceUsageError.unresponsive ? 'UNRESPONSIVE' : 'ERROR';
                            threadInfo.errorMessage = threadInfo.resourceUsageError.error;
                        }

                        // CPU metrics removed to prevent potential native code issues

                        // Process health status
                        if (threadInfo.healthStatus) {
                            switch (threadInfo.healthStatus) {
                                case 'unhealthy':
                                    threadInfo.healthBadge = 'Unhealthy';
                                    threadInfo.healthBadgeType = 'warning';
                                    break;
                                case 'critical':
                                case 'restarting':
                                    threadInfo.healthBadge = 'Critical';
                                    threadInfo.healthBadgeType = 'error';
                                    break;
                                case 'unknown':
                                    threadInfo.healthBadge = 'Unknown';
                                    threadInfo.healthBadgeType = 'neutral';
                                    break;
                                // healthy - no badge shown to avoid clutter
                            }
                        }

                        for (let key of Object.keys(threadInfo)) {
                            switch (key) {
                                case 'online':
                                    threadInfo.timeStr = new Date(threadInfo.online).toISOString();
                                    break;

                                /*
                                // managed by the template helper
                                case 'messages':
                                case 'called':
                                case 'accounts':
                                case 'threadId':
                                    threadInfo[key] = threadInfo[key];
                                    break;
                                */

                                case 'heapUsed':
                                    if (!threadInfo.isUnresponsive) {
                                        threadInfo.heapUsed = bytesFormatter.format(threadInfo[key]).replace(/BB$/, 'GB');
                                    }
                                    break;

                                case 'heapTotal':
                                    // Not displayed anymore to avoid confusion with heap limit
                                    break;

                                // Handle other memory metrics from new format
                                case 'rss':
                                case 'external':
                                case 'arrayBuffers':
                                    // These are available but not displayed in the current UI
                                    break;
                            }
                        }

                        return threadInfo;
                    })
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
