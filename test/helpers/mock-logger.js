'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): a logger stand-in for the
// tests that drive lib/account.js and the email clients through their prototypes. Every level
// records what it was given in `entries`, so a test can assert on what was logged; the tests
// that never look at them pay nothing for the record.

const LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];

function createMockLogger() {
    const logger = { entries: [] };
    for (const level of LEVELS) {
        logger[level] = entry => logger.entries.push(entry && typeof entry === 'object' ? Object.assign({ level }, entry) : { level, msg: entry });
    }
    return logger;
}

module.exports = { createMockLogger };
