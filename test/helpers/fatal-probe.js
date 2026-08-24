'use strict';

// Child process for test/fatal-shutdown-test.js. Reports a rejection nothing handles, and
// schedules a marker one timer turn out - the marker only reaches the log if the process was
// still alive by then, which is the guarantee the late-handler diagnostic rests on.
//
// Run as `node test/helpers/fatal-probe.js [flush]`. With `flush`, the logger gets an
// error-tracking hook whose flush resolves immediately, which is the shape that used to exit in a
// microtask and skip the window.

const logger = require('../../lib/logger.js');

if (process.argv[2] === 'flush') {
    logger.notifyError = () => {};
    logger.flushNotifications = () => Promise.resolve();
}

setTimeout(() => logger.fatal({ msg: 'still-alive-marker' }), 1);

Promise.reject(new Error('probe rejection'));
