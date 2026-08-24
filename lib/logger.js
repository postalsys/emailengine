'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('@zone-eu/wild-config');
const pino = require('pino');
const { TRANSIENT_NETWORK_CODES, REDACTED_LOG_KEYS } = require('./consts');

config.log = config.log || {
    level: 'trace'
};

config.log.level = config.log.level || 'trace';

// undici raises every connection failure as a generic `TypeError` (e.g. "fetch failed"
// or "terminated") with the real DNS/socket error attached as err.cause. Those are
// transient, environmental blips - not code bugs - so they must not be forwarded to
// error tracking, where they pile up as useless "fetch failed" reports. Genuine
// TypeError/RangeError bugs have no network errno cause and still get reported.
function isTransientFetchError(err) {
    return err && err.name === 'TypeError' && err.cause && TRANSIENT_NETWORK_CODES.has(err.cause.code);
}

let logger = pino({
    // Redaction belongs on the root logger, not on a single worker's child: the imap, smtp,
    // imap-proxy, submit, webhooks, export and documents workers all log through this instance,
    // and several of them log joi errors carrying credentials.
    redact: REDACTED_LOG_KEYS,
    formatters: {
        log(object) {
            if (object.err && ['TypeError', 'RangeError'].includes(object.err.name) && !isTransientFetchError(object.err)) {
                if (logger.notifyError) {
                    let meta = {};
                    for (let key of ['msg', 'path', 'cid']) {
                        if (object[key]) {
                            meta[key] = object[key];
                        }
                    }
                    logger.notifyError(object.err, { user: object.account, meta });
                }
            }
            return object;
        }
    }
});
logger.level = process.env.EENGINE_LOG_LEVEL || config.log.level;

const { threadId } = require('worker_threads');

if (threadId) {
    logger = logger.child({ tid: threadId });
}

const FATAL_EXIT_CODES = {
    uncaughtException: 1,
    unhandledRejection: 2
};

// How long the process stays alive after a fatal error before the exit lands. This is not the
// error-tracking delivery window - lib/sentry.js installs notifyError and flushNotifications
// together, so whenever there is a report to deliver its own Sentry.flush() promise already
// covers it. What this covers is Node's: a handler that arrives a microtask after a rejection was
// reported raises 'rejectionHandled' a turn later, and without a timer the exit beats it (see the
// listener at the bottom of this file). Tune it against event-loop turns, not network latency.
const FATAL_EXIT_GRACE = 10;

// An error that reaches the global handlers leaves the process in an unknown state,
// so the process must always exit. If error tracking is enabled, report the error
// first and allow a short flush window for the delivery. The report is tagged with
// the handler that caught it because a crash carries no call site of its own - a
// bare socket error arrives with nothing but a `node:internal` frame, so without the
// tag there is no way to tell a dead worker apart from a handled error.
function fatalShutdown(handler, err) {
    if (logger.notifyError) {
        logger.notifyError(err, { level: 'fatal', tags: { handler } });
    }

    // The exit is always taken a timer turn later, never straight off the flush promise. Node
    // decides a rejection went unhandled at the end of the tick it settled in and only emits
    // 'rejectionHandled' once a handler turns up after that, so exiting from a resolved flush's
    // microtask races the event away - and it did, on exactly the installations that have error
    // tracking switched on and therefore report the most crashes.
    let exit = () => setTimeout(() => process.exit(FATAL_EXIT_CODES[handler]), FATAL_EXIT_GRACE);

    if (logger.flushNotifications) {
        logger.flushNotifications().then(exit, exit);
    } else {
        exit();
    }
}

process.on('uncaughtException', err => {
    logger.fatal({
        msg: 'uncaughtException',
        _msg: 'uncaughtException',
        err
    });

    fatalShutdown('uncaughtException', err);
});

// Promises that already reached the handler below, so a late handler can be recognised. Weak
// keys, because the entry is only ever looked up from the promise Node hands back.
const reportedRejections = new WeakMap();

process.on('unhandledRejection', (err, promise) => {
    logger.fatal({
        msg: 'unhandledRejection',
        _msg: 'unhandledRejection',
        err
    });

    reportedRejections.set(promise, Date.now());

    fatalShutdown('unhandledRejection', err);
});

// Node decides a rejection is unhandled at the end of the tick it settled in, so a handler that
// arrives one microtask late still counts as unhandled. Such a handler fires 'rejectionHandled'
// afterwards, and fatalShutdown() always leaves FATAL_EXIT_GRACE before the exit lands, so the
// event has time to arrive. The worker still dies either way - a rejection that escaped is a bug
// wherever it came from - but this line is the difference between a genuinely missing catch and a
// handler that lost a race, which is otherwise impossible to tell apart from a crash log.
process.on('rejectionHandled', promise => {
    let reportedAt = reportedRejections.get(promise);
    if (!reportedAt) {
        return;
    }
    reportedRejections.delete(promise);

    logger.fatal({
        msg: 'unhandledRejection was handled after it was reported',
        _msg: 'unhandledRejection was handled after it was reported',
        delay: Date.now() - reportedAt
    });
});

module.exports = logger;
