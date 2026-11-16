'use strict';

const crypto = require('crypto');
const os = require('os');
const pathlib = require('path');
const packageData = require('../package.json');
const logger = require('./logger');
const { readEnvValue, httpAgent } = require('./tools');
const { COMMUNITY_SENTRY_DSN } = require('./consts');
const { fetch: fetchCmd } = require('undici');

const SENTRY_SETTINGS_CHECK_INTERVAL = 60 * 1000;

let Sentry;
let workerName;
let activeDsn = false;

// Sentry only orders a project's releases by semver when the version carries a package prefix:
// Release.is_semver_version() refuses anything without an "@", and the server then falls back to
// ordering by the date each version was first seen. EmailEngine reported a bare "2.79.6", so an
// instance that met 2.79.8 before 2.79.6 sorted the older release as the newer one, and
// "resolve in release" reopened the issue it had just closed.
//
// The prefix is the npm package name, not the "@postalsys/emailengine-app" licence identifier
// used elsewhere: Relay rejects a scoped name outright ("bad characters in release name"), which
// would leave the release unparseable rather than merely unordered.
const SENTRY_RELEASE = `${packageData.name}@${packageData.version}`;

// Sentry's own transport speaks Node http/https and knows only the http_proxy environment
// variables (HTTP proxies, no SOCKS), so a proxy configured in EmailEngine would not cover error
// reports. Deliveries go through the shared dispatcher instead, read at send time so a proxy
// settings change applies to the next event without a restart. Only the two headers Sentry's
// rate limiting reads are handed back.
function makeTransport(options) {
    const { createTransport } = require('@sentry/core');

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

// The module name Sentry groups a frame under: the path below the last node_modules with dots for
// slashes, or below the application directory, then the file name without its extension
// ("@hapi.hapi.lib:server", "lib:tools"). The same rule @sentry/node-core applied.
function createGetModuleFromFilename(basePath = pathlib.join(__dirname, '..')) {
    const toPosix = value => value.replace(/\\/g, '/');
    const base = toPosix(basePath);
    return filename => {
        if (!filename) {
            return undefined;
        }
        let { dir, name, ext } = pathlib.posix.parse(toPosix(filename));
        let file = decodeURIComponent(['.js', '.mjs', '.cjs'].includes(ext) ? name : name + ext);
        let index = dir.lastIndexOf('/node_modules');
        if (index > -1) {
            return `${dir.slice(index + 14).replace(/\//g, '.')}:${file}`;
        }
        if (dir.startsWith(base)) {
            let moduleName = dir.slice(base.length + 1).replace(/\//g, '.');
            return moduleName ? `${moduleName}:${file}` : file;
        }
        return file;
    };
}

/**
 * The client options EmailEngine starts Sentry with.
 *
 * @param {string} dsn
 * @param {Object} [overrides] Replaces any option, e.g. the transport in the tests
 * @returns {Object}
 */
function sentryOptions(dsn, overrides) {
    const { createStackParser, eventFiltersIntegration, functionToStringIntegration, linkedErrorsIntegration } = Sentry;
    const { nodeStackLineParser } = require('@sentry/core/server');
    const { contextLinesIntegration, nodeContextIntegration, modulesIntegration } = require('./sentry-integrations');

    return {
        dsn,
        release: SENTRY_RELEASE,
        environment: readEnvValue('SENTRY_ENVIRONMENT') || 'production',
        transport: makeTransport,
        stackParser: createStackParser(nodeStackLineParser(createGetModuleFromFilename())),
        platform: 'node',
        runtime: { name: 'node', version: process.version },
        serverName: readEnvValue('SENTRY_NAME') || os.hostname(),
        // Error capture only: no tracing ('static' also keeps ServerRuntimeClient from adding its
        // span streaming integration), and none of the integrations that patch http/fetch/console
        // on hot paths. Sentry's own uncaughtException/unhandledRejection handling is left out on
        // purpose - it does not run in worker threads and does not guarantee a process exit, so
        // lib/logger.js owns reporting and exiting instead.
        traceLifecycle: 'static',
        integrations: [
            eventFiltersIntegration(),
            functionToStringIntegration(),
            linkedErrorsIntegration(),
            contextLinesIntegration(),
            nodeContextIntegration(),
            modulesIntegration()
        ],
        initialScope: {
            tags: { worker: workerName }
        },
        ...overrides
    };
}

function startSentry(dsn, overrides) {
    // require lazily, the SDK is a few hundred modules in every worker thread, so only pay that
    // cost when error tracking is actually enabled. EmailEngine builds its client from
    // @sentry/core directly: @sentry/node-core, the light Node.js SDK it used before, has no 11.x,
    // and @sentry/node 11 pulls the FSL-licensed Sentry CLI into the tree (see .ncurc.js).
    if (!Sentry) {
        Sentry = require('@sentry/core');
    }

    const { ServerRuntimeClient } = require('@sentry/core/server');
    const options = sentryOptions(dsn, overrides);
    Sentry.applySdkMetadata(options, 'node', ['core']);
    Sentry.initAndBind(ServerRuntimeClient, options);

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

/**
 * The license identity sent with error reports: a short SHA-256 digest of the key rather than the
 * key itself. Tags are indexed and searchable by anyone with access to the Sentry project (the
 * community one is shared), while the logs carefully keep the key out. A known key still maps to
 * its digest, so reports stay attributable to a customer.
 * @param {string} key - License key
 * @returns {string}
 */
function licenseTag(key) {
    return crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 16);
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
        tags.license = licenseTag(tract.key);
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

module.exports = { initSentry, makeTransport, licenseTag, SENTRY_RELEASE, startSentry, createGetModuleFromFilename };
