'use strict';

const packageData = require('../package.json');
const logger = require('./logger');
const { readEnvValue, httpAgent } = require('./tools');
const { COMMUNITY_SENTRY_DSN } = require('./consts');
const { fetch: fetchCmd } = require('undici');

const SENTRY_SETTINGS_CHECK_INTERVAL = 60 * 1000;

let Sentry;
let workerName;
let activeDsn = false;

// Sentry's own transport speaks Node http/https and knows only the http_proxy environment
// variables (HTTP proxies, no SOCKS), so a proxy configured in EmailEngine would not cover error
// reports. Deliveries go through the shared dispatcher instead, read at send time so a proxy
// settings change applies to the next event without a restart. Only the two headers Sentry's
// rate limiting reads are handed back.
function makeTransport(options) {
    const { createTransport } = require('@sentry/node');

    return createTransport(options, async request => {
        let res = await fetchCmd(options.url, {
            method: 'POST',
            headers: options.headers,
            body: request.body,
            dispatcher: httpAgent.fetch
        });

        // the body is never used, but consuming it lets the keep-alive socket be reused
        await res.arrayBuffer();

        return {
            statusCode: res.status,
            headers: {
                'x-sentry-rate-limits': res.headers.get('x-sentry-rate-limits'),
                'retry-after': res.headers.get('retry-after')
            }
        };
    });
}

function startSentry(dsn) {
    // require lazily, the SDK loads several hundred modules in every worker thread,
    // so only pay that cost when error tracking is actually enabled
    if (!Sentry) {
        Sentry = require('@sentry/node');
    }

    Sentry.init({
        dsn,
        release: packageData.version,
        transport: makeTransport,
        // Error capture only: skip the OpenTelemetry setup and the default
        // integrations that patch http/fetch/console on hot paths. Sentry's own
        // uncaughtException/unhandledRejection integrations are left out on
        // purpose - they do not run in worker threads and do not guarantee a
        // process exit, so lib/logger.js owns reporting and exiting instead.
        skipOpenTelemetrySetup: true,
        defaultIntegrations: false,
        integrations: [
            Sentry.eventFiltersIntegration(),
            Sentry.functionToStringIntegration(),
            Sentry.linkedErrorsIntegration(),
            Sentry.contextLinesIntegration(),
            Sentry.nodeContextIntegration(),
            Sentry.modulesIntegration()
        ],
        initialScope: {
            tags: { worker: workerName }
        }
    });

    logger.notifyError = (err, opts) => {
        let captureContext = {};
        if (opts?.user) {
            captureContext.user = { id: `${opts.user}` };
        }
        if (opts?.meta && Object.keys(opts.meta).length) {
            captureContext.contexts = { ee: opts.meta };
        }
        // Tags are indexed and searchable, contexts are display-only, so anything
        // worth filtering or alerting on belongs here rather than in `meta`
        if (opts?.tags) {
            captureContext.tags = opts.tags;
        }
        if (opts?.level) {
            captureContext.level = opts.level;
        }
        Sentry.captureException(err, captureContext);
    };

    // the global exception handlers in lib/logger.js wait for this before exiting
    logger.flushNotifications = () => Sentry.flush(2000);
}

// Tag all events with the installation identity, so reports from different
// EmailEngine instances sharing the same DSN can be told apart. Read once per
// SDK start - a license swapped at runtime is reflected after the next restart.
async function applyIdentityTags() {
    const settings = require('./settings');
    let { serviceId, tract } = await settings.getMulti('serviceId', 'tract');
    let tags = {};
    if (serviceId) {
        tags.instance = serviceId;
    }
    if (tract?.key) {
        tags.license = tract.key;
    }
    Sentry.getGlobalScope().setTags(tags);
}

async function applySentryState(dsn) {
    dsn = dsn || false;
    if (dsn === activeDsn) {
        return;
    }

    if (activeDsn) {
        delete logger.notifyError;
        delete logger.flushNotifications;
        await Sentry.close(2000);
        logger.info({ msg: 'Disabled Sentry error reporting', worker: workerName });
    }

    if (dsn) {
        startSentry(dsn);
        logger.info({ msg: 'Enabled Sentry error reporting', worker: workerName });

        // identity lookup failure must not break error reporting, events just lack the tags
        applyIdentityTags().catch(err => {
            logger.error({ msg: 'Failed to apply Sentry identity tags', worker: workerName, err });
        });
    }

    activeDsn = dsn;
}

async function checkSentrySettings() {
    const settings = require('./settings');
    let { sentryEnabled, sentryDsn } = await settings.getMulti('sentryEnabled', 'sentryDsn');
    await applySentryState(sentryEnabled ? sentryDsn || COMMUNITY_SENTRY_DSN : false);
}

// Initialize Sentry error tracking. If the SENTRY_DSN environment variable is set,
// it pins the configuration and runtime settings are ignored. Otherwise the
// `sentryEnabled` and `sentryDsn` settings are applied at runtime and re-checked
// periodically, so error reporting can be toggled from the admin UI without a
// restart. While disabled, logger.notifyError stays undefined and the global
// exception handlers in lib/logger.js exit without waiting for a delivery flush.
function initSentry(worker) {
    workerName = worker;

    let envDsn = readEnvValue('SENTRY_DSN');
    if (envDsn) {
        applySentryState(envDsn).catch(err => {
            logger.error({ msg: 'Failed to initialize Sentry', worker: workerName, err });
        });
        return;
    }

    // Settings changes are detected by polling instead of the {cmd: 'settings'}
    // broadcast: the broadcast only carries the keys one settings form saved, and
    // the main thread, which also initializes Sentry, is its sender rather than a
    // recipient.
    let checkSettings = async () => {
        try {
            await checkSentrySettings();
        } catch (err) {
            logger.error({ msg: 'Failed to apply Sentry settings', worker: workerName, err });
        }
        setTimeout(checkSettings, SENTRY_SETTINGS_CHECK_INTERVAL).unref();
    };

    setImmediate(checkSettings);
}

module.exports = { initSentry, makeTransport };
