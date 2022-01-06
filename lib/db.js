'use strict';

const fs = require('fs');
const config = require('wild-config');
const pathlib = require('path');
const redisUrl = require('./redis-url');
const packageData = require('../package.json');
const { threadId } = require('worker_threads');
const logger = require('./logger');

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

const Queue = require('bull');
const Redis = require('ioredis');

const redisConf = process.env.EENGINE_REDIS || process.env.REDIS_URL || config.dbs.redis;
const REDIS_CONF = Object.assign(
    {
        // some defaults
        maxRetriesPerRequest: null,
        showFriendlyErrorStack: true,
        retryStrategy(times) {
            const delay = !times ? 50 : Math.min(2 ** times * 50, 10 * 1000);
            logger.trace({ msg: 'Connection retry', times, delay });
            return delay;
        },
        connectionName: `${packageData.name}@${packageData.version}[${process.pid}${threadId ? `:${threadId}` : ''}]`
    },
    typeof redisConf === 'string' ? redisUrl(redisConf) : redisConf || {}
);

const redis = new Redis(REDIS_CONF);

const notifyQueue = new Queue('notify', { redis: Object.assign({ connectionName: `${REDIS_CONF.connectionName}[notify]` }, REDIS_CONF) });
const submitQueue = new Queue('submit', { redis: Object.assign({ connectionName: `${REDIS_CONF.connectionName}[submit]` }, REDIS_CONF) });

const zExpungeScript = fs.readFileSync(pathlib.join(__dirname, '/lua/z-expunge.lua'), 'utf-8');
const zSetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-set.lua'), 'utf-8');
const zGetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get.lua'), 'utf-8');
const zGetByUidScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-by-uid.lua'), 'utf-8');
const zGetMailboxIdScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-id.lua'), 'utf-8');
const zGetMailboxPathScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-path.lua'), 'utf-8');
const sListAccountsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/s-list-accounts.lua'), 'utf-8');
const zPushScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-push.lua'), 'utf-8');

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

redis.defineCommand('zPush', {
    numberOfKeys: 1,
    lua: zPushScript
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

module.exports.redis = redis;
module.exports.notifyQueue = notifyQueue;
module.exports.submitQueue = submitQueue;
module.exports.REDIS_CONF = REDIS_CONF;

redis.on('error', err => {
    if (/NOAUTH/.test(err.message)) {
        if (REDIS_CONF.password) {
            logger.fatal({ msg: 'Redis requires a valid password', err });
        } else {
            logger.fatal({ msg: 'Redis password is required but not provided', err });
        }
        return;
    }

    if (/WRONGPASS/.test(err.message)) {
        logger.fatal({ msg: 'Provided Redis password was not accepted', err });
        return;
    }

    switch (err.code) {
        case 'ECONNREFUSED':
            logger.fatal({ msg: 'Can not connect to the database', err });
            break;
        default:
            logger.fatal({ msg: 'Database error', err });
    }
});
