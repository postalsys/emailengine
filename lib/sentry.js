'use strict';

const packageData = require('../package.json');
const logger = require('./logger');
const { readEnvValue } = require('./tools');

// Initialize Sentry error tracking if a DSN is provided. Without SENTRY_DSN this is
// a no-op: logger.notifyError stays undefined and the global exception handlers in
// lib/logger.js exit without waiting for a delivery flush.
function initSentry(worker) {
    let dsn = readEnvValue('SENTRY_DSN');
    if (!dsn) {
        return;
    }

    // require lazily, the SDK loads several hundred modules in every worker thread,
    // so only pay that cost when error tracking is actually enabled
    const Sentry = require('@sentry/node');

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
            tags: { worker }
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

module.exports = { initSentry };
