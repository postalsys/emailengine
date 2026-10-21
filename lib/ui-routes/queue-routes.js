'use strict';

// Admin UI routes for the queue browser: the overview of the BullMQ queues, one page per queue
// with its jobs by state, a page per job, and the actions on them. The model is lib/queue-browser;
// these routes only validate what a URL names, render, and turn the outcomes into flash messages.
//
// This is the "Queues" entry in the side menu. It replaced the bundled bull-board UI, which was
// mounted at /admin/bull-board; that path and its deep links redirect here.

const Joi = require('joi');
const Boom = require('@hapi/boom');

const { buildPagingView } = require('./route-helpers');
const queueBrowser = require('../queue-browser');
const { QUEUE_NAMES, STATE_NAMES, DEFAULT_STATE, SCAN_LIMIT, BULL_BOARD_DEPRECATION } = require('../queue-browser/definitions');
const { DEFAULT_PAGE_SIZE } = require('../consts');

const QUEUE_PARAM = Joi.string()
    .valid(...QUEUE_NAMES)
    .required()
    .description('Queue name');
const JOB_PARAM = Joi.string().max(256).required().description('Job ID');

// Where an action returns to: only a page of this browser, so a posted value cannot send the
// browser anywhere else. The actions are posted from a filtered or paged list and from a
// detail page alike, which is why they carry a return target where other admin actions
// redirect to a fixed page.
const NEXT_PARAM = Joi.string()
    .empty('')
    .max(2048)
    .pattern(/^\/admin\/queues(?:[/?]|$)/)
    .description('Page to return to');

const VALIDATE_OPTIONS = {
    stripUnknown: true,
    abortEarly: false,
    convert: true
};

// A request this browser cannot make sense of lands on the overview
async function redirectToOverview(request, h /*, err*/) {
    return h.redirect('/admin/queues').takeover();
}

/**
 * The URL of a queue listing, from its parameters. Only values that differ from the defaults
 * are written, so the tab links and the pagination stay short.
 */
function listUrl(queueName, params) {
    const url = new URL(`/admin/queues/${queueName}`, 'http://localhost');
    if (params.state && params.state !== DEFAULT_STATE) {
        url.searchParams.set('state', params.state);
    }
    for (const key of ['query', 'account', 'route']) {
        if (params[key]) {
            url.searchParams.set(key, params[key]);
        }
    }
    if (params.page && params.page > 1) {
        url.searchParams.set('page', params.page);
    }
    if (params.pageSize && params.pageSize !== DEFAULT_PAGE_SIZE) {
        url.searchParams.set('pageSize', params.pageSize);
    }
    return url.pathname + url.search;
}

/**
 * Turns a browser error into a flash message, so a refused action lands the reader back where
 * they were with the reason, and anything unexpected is logged as such.
 */
async function flashFailure(request, err, fallback) {
    if (err && err.statusCode && err.statusCode < 500) {
        await request.flash({ type: 'warning', message: err.message });
    } else {
        request.logger.error({ msg: fallback, err, queue: request.params.queue, job: request.params.jobId });
        await request.flash({ type: 'danger', message: `${fallback}. Try again.` });
    }
}

/**
 * A POST route that runs an action on a queue (or one of its jobs), flashes the outcome and
 * returns to the page it was posted from.
 *
 * @param {Object} options
 * @param {string} options.path - Route path, with the {queue} and optionally {jobId} params
 * @param {Object} [options.payload] - Extra payload fields, beyond `next`
 * @param {Function} options.run - `(queueDef, request) => outcome` ({ type, message, next }); `next`, when set,
 *   replaces the posted return target
 * @param {string} options.fallback - What to say when the action throws something unexpected
 */
function actionRoute({ path, payload, run, fallback }) {
    return {
        method: 'POST',
        path,
        async handler(request, h) {
            const queueDef = queueBrowser.QUEUES_BY_NAME.get(request.params.queue);
            let next;
            try {
                const outcome = await run(queueDef, request);
                next = outcome.next;
                await request.flash({ type: outcome.type, message: outcome.message });
            } catch (err) {
                await flashFailure(request, err, fallback);
            }
            return h.redirect(next || request.payload.next || `/admin/queues/${queueDef.name}`);
        },
        options: {
            validate: {
                options: VALIDATE_OPTIONS,
                failAction: redirectToOverview,
                params: Joi.object(Object.assign({ queue: QUEUE_PARAM }, path.includes('{jobId}') ? { jobId: JOB_PARAM } : {})),
                payload: Joi.object(Object.assign({ next: NEXT_PARAM }, payload || {}))
            }
        }
    };
}

function init(args) {
    const { server } = args;

    server.route({
        method: 'GET',
        path: '/admin/queues',
        async handler(request, h) {
            const model = await queueBrowser.overview();

            return h.view('queues/index', Object.assign({ pageTitle: 'Queues', menuQueues: true }, model), { layout: 'app' });
        }
    });

    // What the pages poll for live counts. A literal segment, so it is routed ahead of the
    // /{queue} page below; no queue is called "counts".
    server.route({
        method: 'GET',
        path: '/admin/queues/counts',
        async handler() {
            return { queues: await queueBrowser.allCounts() };
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/queues/{queue}',
        async handler(request, h) {
            const queueDef = queueBrowser.QUEUES_BY_NAME.get(request.params.queue);
            const { state, query, account, route } = request.query;

            // What is kept and where that is set, for the Failed and Completed tabs (the note partial
            // renders nothing on the others)
            const [status, retention] = await Promise.all([queueBrowser.queueCounts(queueDef), queueBrowser.retention()]);
            const listing = await queueBrowser.listJobs({
                queue: queueDef,
                state,
                stateTotal: status.counts[state],
                page: request.query.page - 1,
                pageSize: request.query.pageSize,
                query,
                account,
                route,
                logger: request.logger
            });

            const filterParams = { query, account, route };
            const currentUrl = listUrl(queueDef.name, Object.assign({ state, page: request.query.page, pageSize: request.query.pageSize }, filterParams));

            const states = queueBrowser.STATES.map(stateInfo =>
                Object.assign({}, stateInfo, {
                    count: status.counts[stateInfo.name],
                    active: stateInfo.name === state,
                    url: listUrl(queueDef.name, Object.assign({ state: stateInfo.name }, filterParams))
                })
            );

            // The one sentence that names the active filter, with the way out of it
            let filterLabel = null;
            if (account) {
                filterLabel = `Entries for account "${account}"`;
            } else if (route) {
                const routed = listing.entries.find(entry => entry.routeName);
                filterLabel = `Deliveries through webhook route "${routed ? routed.routeName : route}"`;
            }

            return h.view(
                'queues/queue',
                Object.assign(
                    {
                        pageTitle: `Queues - ${queueDef.label}`,
                        menuQueues: true,

                        queue: Object.assign({}, queueDef, status, { concurrency: queueBrowser.concurrencyInfo(queueDef) }),
                        states,
                        state: queueBrowser.STATES_BY_NAME.get(state),
                        listing,
                        scanLimit: SCAN_LIMIT,
                        retention,
                        failedContent: { limits: await queueBrowser.failedContentLimits() },

                        filter: Object.assign({ active: listing.filtered, label: filterLabel }, filterParams),
                        clearHref: listUrl(queueDef.name, { state }),
                        currentUrl
                    },
                    buildPagingView(listUrl(queueDef.name, Object.assign({ state }, filterParams)), listing, request.query)
                ),
                { layout: 'app' }
            );
        },
        options: {
            validate: {
                options: VALIDATE_OPTIONS,
                failAction: redirectToOverview,

                params: Joi.object({
                    queue: QUEUE_PARAM
                }),

                query: Joi.object({
                    state: Joi.string()
                        .valid(...STATE_NAMES)
                        .default(DEFAULT_STATE),
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
                    query: Joi.string().empty('').trim().max(256),
                    account: Joi.string().empty('').trim().max(256),
                    route: Joi.string().empty('').trim().max(512)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/queues/{queue}/jobs/{jobId}',
        async handler(request, h) {
            const queueDef = queueBrowser.QUEUES_BY_NAME.get(request.params.queue);

            const found = await queueBrowser.getJob({ queue: queueDef, jobId: request.params.jobId, logger: request.logger });
            if (!found) {
                throw Boom.notFound(`There is no such ${queueDef.noun} in the queue. It may have finished and been removed.`);
            }

            const { entry, raw } = found;

            return h.view(
                'queues/job',
                {
                    pageTitle: `Queues - ${queueDef.label} - ${entry.title}`,
                    menuQueues: true,

                    queue: queueDef,
                    entry,
                    raw,
                    listHref: listUrl(queueDef.name, { state: entry.state }),
                    // the actions on this page return to it
                    currentUrl: entry.url
                },
                { layout: 'app' }
            );
        },
        options: {
            validate: {
                options: VALIDATE_OPTIONS,
                failAction: redirectToOverview,

                params: Joi.object({
                    queue: QUEUE_PARAM,
                    jobId: JOB_PARAM
                })
            }
        }
    });

    for (const paused of [true, false]) {
        server.route(
            actionRoute({
                path: `/admin/queues/{queue}/${paused ? 'pause' : 'resume'}`,
                fallback: `Could not ${paused ? 'pause' : 'resume'} the queue`,
                run: async (queueDef, request) => {
                    const isPaused = await queueBrowser.setPaused(queueDef, paused);
                    request.logger.info({ msg: isPaused ? 'Queue paused' : 'Queue resumed', queue: queueDef.name, remoteAddress: request.app.ip });
                    return {
                        type: 'info',
                        message: isPaused
                            ? `${queueDef.title} paused. Workers finish what they are running and take nothing new until it is resumed.`
                            : `${queueDef.title} resumed.`
                    };
                }
            })
        );
    }

    server.route(
        actionRoute({
            path: '/admin/queues/{queue}/clean',
            payload: { state: Joi.string().valid('completed', 'failed').required() },
            fallback: 'Could not clean the queue',
            run: async (queueDef, request) => {
                const { state } = request.payload;
                const removed = await queueBrowser.cleanQueue({ queue: queueDef, state, logger: request.logger });
                return {
                    type: 'info',
                    message: removed
                        ? `Removed ${removed} ${state} ${removed === 1 ? queueDef.noun : queueDef.nounPlural}.`
                        : `There were no ${state} ${queueDef.nounPlural} to remove.`
                };
            }
        })
    );

    // The per-job actions. A job that is gone by the time the action lands is reported, not
    // treated as an error: the queue moves on its own, and "it finished meanwhile" is the
    // usual reason.
    const JOB_ACTION_DONE = {
        remove: queueDef => `Removed the ${queueDef.noun} from the queue.`,
        retry: queueDef => `The ${queueDef.noun} is queued for a new attempt, with a full set of retries.`,
        promote: queueDef => `The ${queueDef.noun} runs at the next opportunity instead of waiting for its time.`
    };

    for (const [action, done] of Object.entries(JOB_ACTION_DONE)) {
        server.route(
            actionRoute({
                path: `/admin/queues/{queue}/jobs/{jobId}/${action}`,
                fallback: `Could not ${action} the entry`,
                run: async (queueDef, request) => {
                    const { jobId } = request.params;
                    // An action posted from the entry's own page can leave no page to return to, so
                    // the state is read first: a removal then lands on the list of the state the
                    // entry was in. A refused one (a worker holds the entry) keeps the page, where
                    // the warning says to try again.
                    const fromEntryPage = request.payload.next === queueBrowser.entryUrl(queueDef.name, jobId);
                    const toList = fromEntryPage ? { next: listUrl(queueDef.name, { state: await queueBrowser.jobState(queueDef, jobId) }) } : {};

                    const result = await queueBrowser.runJobAction(action, { queue: queueDef, jobId, logger: request.logger });
                    if (result && result.locked) {
                        return {
                            type: 'warning',
                            message: `A worker is processing this ${queueDef.noun} right now, so it was not removed. Try again once the attempt is over.`
                        };
                    }
                    if (!result || result.removed === false) {
                        return Object.assign({ type: 'warning', message: `This ${queueDef.noun} is no longer in the queue.` }, toList);
                    }
                    return Object.assign({ type: 'info', message: done(queueDef) }, action === 'remove' ? toList : {});
                }
            })
        );
    }

    // Compatibility for the retired bull-board page: its own URL and the queue deep links
    // written against it (the docs, the dashboard of older releases, bookmarks) land on the
    // matching page here. Deprecated, removed after REMOVAL_DATE (lib/deprecations.js)

    server.route({
        method: 'GET',
        path: '/admin/bull-board',
        handler(request, h) {
            return h.redirect('/admin/queues');
        },
        options: { plugins: { deprecation: BULL_BOARD_DEPRECATION } }
    });

    server.route({
        method: 'GET',
        path: '/admin/bull-board/{path*}',
        handler(request, h) {
            const path = decodeURIComponent(request.params.path || '');
            const queueName = QUEUE_NAMES.find(name => path.includes(name));
            return h.redirect(queueName ? `/admin/queues/${queueName}` : '/admin/queues');
        },
        options: { plugins: { deprecation: BULL_BOARD_DEPRECATION } }
    });
}

module.exports = init;
