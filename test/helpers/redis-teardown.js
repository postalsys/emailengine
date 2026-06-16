'use strict';

const { after } = require('node:test');

// Tests that pull in lib/db (directly or transitively) inherit its persistent
// Redis client and the BullMQ queue connection. The queue connection is
// internal to lib/db and not exported, so it cannot be closed individually.
// Those open handles keep the event loop alive, and the unit runner uses plain
// `node --test` with no --test-force-exit, so without this the process would
// hang after the tests have already passed.
//
// The force-exit is a deliberate stopgap that matches the long-standing
// convention used across the rest of the suite. The deeper fix would be for
// lib/db.js to export a shutdown that closes all of its connections, which
// tests (and graceful shutdown) could await instead of forcing the process out.
//
// Registers a single root after-hook that runs the optional cleanup callback,
// gracefully quits the primary Redis client (when provided), and then forces
// the process to exit. process.exit() is called with NO argument so that a
// non-zero exit code set by a failed test is preserved - passing 0 would mask
// failures.
//
// @param {Object} [redis] - ioredis client to quit before exiting
// @param {Function} [cleanup] - async cleanup run before redis is quit
module.exports = function registerRedisTeardown(redis, cleanup) {
    after(async () => {
        if (cleanup) {
            try {
                await cleanup();
            } catch (err) {
                // ignore - best-effort teardown
            }
        }
        if (redis) {
            try {
                await redis.quit();
            } catch (err) {
                // ignore - connection may already be closing
            }
        }
        setTimeout(() => process.exit(), 1000).unref();
    });
};
