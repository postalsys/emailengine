'use strict';

// Flushes the isolated e2e Redis DB so every Playwright run boots a truly fresh EmailEngine
// instance (no admin password, no license, no accounts). Invoked by the Playwright webServer
// command before `node server.js`, inheriting NODE_ENV=e2e so @zone-eu/wild-config resolves the
// e2e Redis URL (config/e2e.toml). Uses ioredis (already a dependency) to stay cross-platform -
// no dependency on a `redis-cli` binary being on PATH.

const config = require('@zone-eu/wild-config');
const Redis = require('ioredis');

async function main() {
    const redis = new Redis(config.dbs.redis);
    try {
        await redis.flushdb();
        console.log(`[e2e] flushed Redis DB ${config.dbs.redis}`);
    } finally {
        await redis.quit();
    }
}

main().catch(err => {
    console.error('[e2e] failed to flush Redis', err);
    process.exit(1);
});
