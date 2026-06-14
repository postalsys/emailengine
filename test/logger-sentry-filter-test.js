'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const logger = require('../lib/logger');

// The pino `formatters.log` hook in lib/logger.js decides which logged errors are
// forwarded to error tracking (Sentry) via logger.notifyError. undici raises every
// connection failure as a `TypeError` with the real DNS/socket error on err.cause;
// those transient blips must be filtered out, while genuine TypeError/RangeError
// bugs must still be reported.
test('logger Sentry forwarding filter', async t => {
    // error level must be enabled or the formatter never runs
    logger.level = 'trace';

    let forwarded = [];
    logger.notifyError = err => forwarded.push(err);

    t.beforeEach(() => {
        forwarded = [];
    });

    t.after(() => {
        delete logger.notifyError;
    });

    await t.test('forwards a genuine TypeError bug', () => {
        let err = new TypeError("Cannot read properties of undefined (reading 'x')");
        logger.error({ msg: 'boom', err });
        assert.equal(forwarded.length, 1);
        assert.equal(forwarded[0], err);
    });

    await t.test('forwards a RangeError', () => {
        let err = new RangeError('Invalid array length');
        logger.error({ msg: 'boom', err });
        assert.equal(forwarded.length, 1);
        assert.equal(forwarded[0], err);
    });

    await t.test('does not forward an undici fetch failure caused by EAI_AGAIN', () => {
        let cause = new Error('getaddrinfo EAI_AGAIN gmail.googleapis.com');
        cause.code = 'EAI_AGAIN';
        let err = new TypeError('fetch failed');
        err.cause = cause;
        logger.error({ msg: 'Failed to process account history', err });
        assert.equal(forwarded.length, 0);
    });

    await t.test('does not forward an undici "terminated" failure caused by ECONNRESET', () => {
        let cause = new Error('socket hang up');
        cause.code = 'ECONNRESET';
        let err = new TypeError('terminated');
        err.cause = cause;
        logger.error({ msg: 'request failed', err });
        assert.equal(forwarded.length, 0);
    });

    await t.test('forwards a fetch failure with a non-network cause', () => {
        // A TypeError whose cause is not a transient network errno is still a real
        // bug worth reporting.
        let cause = new Error('something unexpected');
        cause.code = 'ERR_INVALID_STATE';
        let err = new TypeError('fetch failed');
        err.cause = cause;
        logger.error({ msg: 'request failed', err });
        assert.equal(forwarded.length, 1);
        assert.equal(forwarded[0], err);
    });

    await t.test('forwards a TypeError with no cause', () => {
        let err = new TypeError('fetch failed');
        logger.error({ msg: 'request failed', err });
        assert.equal(forwarded.length, 1);
        assert.equal(forwarded[0], err);
    });
});
