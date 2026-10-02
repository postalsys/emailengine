'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

const fs = require('fs');
const config = require('@zone-eu/wild-config');
const pathlib = require('path');
const redisUrl = require('./redis-url');
const { threadId } = require('worker_threads');
const logger = require('./logger');
const { readEnvValue } = require('./read-env-value');
const { REDIS_PREFIX } = require('./consts');
const Path = require('path');
const { isMainThread } = require('worker_threads');

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

const { Queue } = require('bullmq');
const Redis = require('ioredis');

const redisConf = readEnvValue('EENGINE_REDIS') || readEnvValue('REDIS_URL') || config.dbs.redis;
const REDIS_CONF = Object.assign(
    {
        // some defaults
        maxRetriesPerRequest: null, // must be null, otherwise Bull.js will reject it
        showFriendlyErrorStack: true,
        disableClientInfo: true,
        retryStrategy(times) {
            const delay = !times ? 1000 : Math.min(2 ** times * 500, 15 * 1000);
            logger.trace({ msg: 'Connection retry', isMainThread, threadId, times, delay });
            return delay;
        },
        reconnectOnError(err) {
            // Not fatal: this fires on every transient connection error and we always reconnect,
            // so logging it at fatal turned an ordinary Redis failover into a burst of top
            // severity alerts. The retryStrategy above reports the actual retry cadence.
            logger.warn({ msg: 'Redis connection error', isMainThread, threadId, err });
            // always try to reconnect
            return true;
        },
        offlineQueue: true
    },
    typeof redisConf === 'string' ? redisUrl(redisConf) : redisConf || {}
);

const getRedisURL = (masked = true) => {
    let redisUrlParts = [`redis${REDIS_CONF.tls ? 's' : ''}://`];

    let pass = REDIS_CONF.password;
    if (pass && masked) {
        pass = '******';
    }

    if (REDIS_CONF.username && pass) {
        redisUrlParts.push(`${REDIS_CONF.username}:${pass}@`);
    } else if (pass) {
        redisUrlParts.push(`:${pass}@`);
    } else if (REDIS_CONF.username) {
        redisUrlParts.push(`${REDIS_CONF.username}@`);
    }

    redisUrlParts.push(REDIS_CONF.host || '127.0.0.1');

    if (REDIS_CONF.port) {
        redisUrlParts.push(`:${REDIS_CONF.port}`);
    }

    if (REDIS_CONF.db) {
        redisUrlParts.push(`/${REDIS_CONF.db}`);
    }

    let searchArgs = [];
    if (REDIS_CONF.family) {
        searchArgs.push(`family=${encodeURIComponent(REDIS_CONF.family)}`);
    }

    if (searchArgs.length) {
        redisUrlParts.push(`?${searchArgs.join('&')}`);
    }

    return redisUrlParts.join('');
};

const redis = new Redis(REDIS_CONF);

const reqisQueue = new Redis(REDIS_CONF);

// Passing an ioredis instance as `connection` (rather than connection options) is what keeps BullMQ
// from closing the client on its own: it marks the connection shared via isRedisInstance() and only
// disconnects the ones it created itself.
module.exports.queueConf = {
    connection: reqisQueue,
    prefix: `${REDIS_PREFIX}bull`
};

/**
 * Routes the 'error' events of a BullMQ Worker, Queue or QueueEvents to the log.
 * With no listener BullMQ catches the unhandled-'error' throw itself and prints it with
 * console.error, so the error never reached pino or Sentry, and nothing crashed either
 * @param {EventEmitter} emitter - The BullMQ object
 * @param {string} component - What it is, e.g. 'queue:notify' or 'worker:submit'
 * @returns {EventEmitter} The same object
 */
const logBullErrors = (emitter, component) => {
    emitter.on('error', err => {
        logger.error({ msg: 'Queue error', component, err });
    });
    return emitter;
};
module.exports.logBullErrors = logBullErrors;

const notifyQueue = logBullErrors(new Queue('notify', module.exports.queueConf), 'queue:notify');
const submitQueue = logBullErrors(new Queue('submit', module.exports.queueConf), 'queue:submit');
const exportQueue = logBullErrors(new Queue('export', module.exports.queueConf), 'queue:export');

const zExpungeScript = fs.readFileSync(pathlib.join(__dirname, '/lua/z-expunge.lua'), 'utf-8');
const zSetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-set.lua'), 'utf-8');
const zGetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get.lua'), 'utf-8');
const zGetByUidScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-by-uid.lua'), 'utf-8');
const zGetMailboxIdScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-id.lua'), 'utf-8');
const zGetMailboxPathScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-path.lua'), 'utf-8');
const sListAccountsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/s-list-accounts.lua'), 'utf-8');
const hSetBiggerScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-bigger.lua'), 'utf-8');
const hUpdateBiggerScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-update-bigger.lua'), 'utf-8');
const hSetExistsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-exists.lua'), 'utf-8');
const hSetNewScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-new.lua'), 'utf-8');
const hSetIfEqualsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-if-equals.lua'), 'utf-8');
const hDelIfEqualsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-del-if-equals.lua'), 'utf-8');
const hSetNewMarkScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-new-mark.lua'), 'utf-8');
const hIncrbyExistsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-incrby-exists.lua'), 'utf-8');
const eeListAddScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-list-add.lua'), 'utf-8');
const eeListRemoveScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-list-remove.lua'), 'utf-8');
const eeGetIdempotencyScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-get-idempotency.lua'), 'utf-8');
const eeReserveAttemptsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-reserve-attempts.lua'), 'utf-8');
const eeReleaseAttemptsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-release-attempts.lua'), 'utf-8');
const eeExportQueueAddScript = fs.readFileSync(pathlib.join(__dirname, 'lua/ee-export-queue-add.lua'), 'utf-8');

redis.defineCommand('zExpunge', {
    numberOfKeys: 2,
    lua: zExpungeScript
});

redis.defineCommand('zSet', {
    numberOfKeys: 1,
    lua: zSetScript
});

redis.defineCommand('zGet', {
    numberOfKeys: 1,
    lua: zGetScript
});

redis.defineCommand('zGetByUid', {
    numberOfKeys: 1,
    lua: zGetByUidScript
});

redis.defineCommand('zGetMailboxId', {
    numberOfKeys: 2,
    lua: zGetMailboxIdScript
});

redis.defineCommand('zGetMailboxPath', {
    numberOfKeys: 1,
    lua: zGetMailboxPathScript
});

redis.defineCommand('sListAccounts', {
    numberOfKeys: 1,
    lua: sListAccountsScript
});

redis.defineCommand('hSetBigger', {
    numberOfKeys: 1,
    lua: hSetBiggerScript
});

redis.defineCommand('hUpdateBigger', {
    numberOfKeys: 1,
    lua: hUpdateBiggerScript
});

redis.defineCommand('hSetExists', {
    numberOfKeys: 1,
    lua: hSetExistsScript
});

redis.defineCommand('hSetNew', {
    numberOfKeys: 1,
    lua: hSetNewScript
});

redis.defineCommand('hSetIfEquals', {
    numberOfKeys: 1,
    lua: hSetIfEqualsScript
});

redis.defineCommand('hDelIfEquals', {
    numberOfKeys: 1,
    lua: hDelIfEqualsScript
});

redis.defineCommand('hSetNewMark', {
    numberOfKeys: 1,
    lua: hSetNewMarkScript
});

redis.defineCommand('hIncrbyExists', {
    numberOfKeys: 1,
    lua: hIncrbyExistsScript
});

redis.defineCommand('eeListAdd', {
    numberOfKeys: 2,
    lua: eeListAddScript
});

redis.defineCommand('eeListRemove', {
    numberOfKeys: 2,
    lua: eeListRemoveScript
});

redis.defineCommand('eeGetIdempotency', {
    numberOfKeys: 1,
    lua: eeGetIdempotencyScript
});

// The budget scripts take one key per budget, so the key count is passed as the first argument
// (lib/rate-limit.js reserveAttempts / releaseAttempts)
redis.defineCommand('eeReserveAttempts', {
    lua: eeReserveAttemptsScript
});

redis.defineCommand('eeReleaseAttempts', {
    lua: eeReleaseAttemptsScript
});

redis.defineCommand('eeExportQueueAdd', {
    numberOfKeys: 2,
    lua: eeExportQueueAddScript
});

module.exports.redis = redis;
module.exports.notifyQueue = notifyQueue;
module.exports.submitQueue = submitQueue;
module.exports.exportQueue = exportQueue;

// Queues addressable by the name the API and the stats payload use for them. `export` is
// deliberately absent: neither surface exposes it, and the {queue} route parameter is validated
// against this same set of names.
module.exports.QUEUES_BY_NAME = {
    notify: notifyQueue,
    submit: submitQueue
};

module.exports.REDIS_CONF = REDIS_CONF;

/**
 * Calls `onReconnect` when a client that had been ready becomes ready again after losing its
 * connection. ioredis emits 'end' only on a final close (retryStrategy returning a non-number, which
 * the one above never does), so an ordinary reconnect is close -> reconnecting -> ready and a
 * watcher that waited for 'end' never fired
 * @param {Redis} client - ioredis client
 * @param {Function} onReconnect - Called on the first 'ready' after a lost connection
 * @param {Function} [onDisconnect] - Called once when a stable connection is lost
 */
module.exports.watchRedisReconnect = (client, onReconnect, onDisconnect) => {
    let hasSeenStableConnection = client.status === 'ready';
    let wasDisconnected = false;

    const lost = () => {
        // A failed first connection is not a reconnect; only a connection that was ready counts
        if (hasSeenStableConnection && !wasDisconnected) {
            wasDisconnected = true;
            if (onDisconnect) {
                onDisconnect();
            }
        }
    };

    client.on('close', lost);
    client.on('reconnecting', lost);
    client.on('end', lost);

    client.on('ready', () => {
        if (wasDisconnected) {
            wasDisconnected = false;
            onReconnect();
            return;
        }
        hasSeenStableConnection = true;
    });
};

let redisConnected = false;
const showRedisError = (msg, err, forceClose) => {
    if (isMainThread && (forceClose || (!redisConnected && process.stdout.isTTY && isMainThread && !process.env.ENCRYPT_SECRET))) {
        let appPath = Path.basename(process.argv[0]);
        let scriptPath = Path.basename(process.argv[1]);
        let displayScriptPath = scriptPath === 'emailengine.js' ? appPath : `${appPath} ${scriptPath}`;

        let logmessage = `Failed to establish connection to Redis using "${getRedisURL(true)}"
${msg || err.message}

To run EmailEngine provide valid Redis configuration
  $ ${displayScriptPath} --dbs.redis="redis://username:password@1.2.3.4:6379/0"`;

        let maxLineLength = logmessage.split(/\r?\n/).reduce((maxLen, line) => Math.max(maxLen, line.length), 0);
        console.error('='.repeat(maxLineLength));
        console.error(logmessage);
        console.error('='.repeat(maxLineLength));

        process.exit(1);
    }

    // Only reached when the process stays up (the exit path above never returns), so this must
    // not log at fatal. A post-connection error is retried by ioredis on its own, so it is a
    // warning; config-class errors (forceClose) that did not trigger an exit are logged at error.
    if (forceClose) {
        logger.error({ msg: msg || 'Redis connection error', err });
    } else {
        logger.warn({ msg: msg || 'Redis connection error', err });
    }
};

redis.on('connect', () => {
    redisConnected = true;
});

for (let redisClient of [redis, reqisQueue]) {
    redisClient.on('error', err => {
        if (/NOAUTH/.test(err.message)) {
            if (REDIS_CONF.password) {
                return showRedisError('Redis requires a valid password', err, true);
            } else {
                return showRedisError('Redis password is required but not provided', err, true);
            }
        }

        if (/WRONGPASS/.test(err.message)) {
            return showRedisError('Provided Redis password was not accepted', err, true);
        }

        switch (err.code) {
            case 'ECONNREFUSED':
                return showRedisError(
                    'Can not connect to the database. Redis might not be running. Are you using correct hostname and port values?',
                    err,
                    !redisConnected
                );

            case 'ETIMEDOUT':
                return showRedisError(
                    'Connection to the database timed out. Seems like you are firewalled. Are you using correct hostname and port values?',
                    err,
                    !redisConnected
                );

            case 'ReplyError':
                if (/MISCONF/.test(err.message)) {
                    return showRedisError(false, err, true);
                }
                return showRedisError(false, err);

            default:
                return showRedisError(false, err);
        }
    });
}
