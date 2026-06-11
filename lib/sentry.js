'use strict';

const packageData = require('../package.json');
const logger = require('./logger');
const { readEnvValue } = require('./tools');
const { COMMUNITY_SENTRY_DSN } = require('./consts');

const SENTRY_SETTINGS_CHECK_INTERVAL = 60 * 1000;

let Sentry;
let workerName;
let activeDsn = false;

function startSentry(dsn) {
    // require lazily, the SDK loads several hundred modules in every worker thread,
    // so only pay that cost when error tracking is actually enabled
    if (!Sentry) {
        Sentry = require('@sentry/node');
    }

    Sentry.init({
        dsn,
        release: packageData.version,
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
        Sentry.captureException(err, captureContext);
    };

    // the global exception handlers in lib/logger.js wait for this before exiting
    logger.flushNotifications = () => Sentry.flush(2000);
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
    // broadcast because that broadcast does not reach all the threads that
    // initialize Sentry (smtp, imap-proxy, documents, and the main thread).
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

module.exports = { initSentry };
