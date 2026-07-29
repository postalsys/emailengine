'use strict';

// Flushes the Redis database that @zone-eu/wild-config resolves for the current NODE_ENV, so every
// run starts from a clean instance (no admin password, no license, no accounts). Shared by all the
// tiers that need it: the unit and integration tiers via test/run-tests.js (NODE_ENV=test, db 13),
// the Playwright webServer command (NODE_ENV=e2e, db 14) and test/dovecot/run-dovecot-tests.sh.
// Uses ioredis (already a dependency) to stay cross-platform - no dependency on a `redis-cli` binary
// being on PATH.
//
// NODE_ENV must be set by the caller before this module is loaded; without it wild-config resolves
// config/default.toml and this flushes the development database instead.

const config = require('@zone-eu/wild-config');
const Redis = require('ioredis');

async function flushRedis() {
    const redis = new Redis(config.dbs.redis);
    try {
        await redis.flushdb();
        console.log(`Flushed Redis DB ${config.dbs.redis}`);
    } finally {
        await redis.quit();
    }
}

module.exports = { flushRedis };

if (require.main === module) {
    flushRedis().catch(err => {
        console.error('Failed to flush Redis', err);
        process.exit(1);
    });
}
