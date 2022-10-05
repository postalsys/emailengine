'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

const fs = require('fs');
const config = require('wild-config');
const pathlib = require('path');
const redisUrl = require('./redis-url');
const packageData = require('../package.json');
const { threadId } = require('worker_threads');
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

const { Queue, FlowProducer } = require('bullmq');
const Redis = require('ioredis');

// duplicat function declaration to avoid requireing tools.js
const readEnvValue = key => {
    if (key in process.env) {
        return process.env[key];
    }

    if (typeof process.env[`${key}_FILE`] === 'string' && process.env[`${key}_FILE`]) {
        try {
            // try to load from file
            process.env[key] = fs.readFileSync(process.env[`${key}_FILE`], 'utf-8').replace(/\r?\n$/, '');
            logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
        } catch (err) {
            logger.error({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
            process.env[key] = '';
        }
        return process.env[key];
    }
};

const redisConf = readEnvValue('EENGINE_REDIS') || readEnvValue('REDIS_URL') || config.dbs.redis;
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

module.exports.queueConf = {
    connection: Object.assign({ connectionName: `${REDIS_CONF.connectionName}[notify]` }, REDIS_CONF),
    prefix: `${REDIS_PREFIX}bull`
};

const notifyQueue = new Queue('notify', module.exports.queueConf);
const submitQueue = new Queue('submit', module.exports.queueConf);
const documentsQueue = new Queue('documents', module.exports.queueConf);

const zExpungeScript = fs.readFileSync(pathlib.join(__dirname, '/lua/z-expunge.lua'), 'utf-8');
const zSetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-set.lua'), 'utf-8');
const zGetScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get.lua'), 'utf-8');
const zGetByUidScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-by-uid.lua'), 'utf-8');
const zGetMailboxIdScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-id.lua'), 'utf-8');
const zGetMailboxPathScript = fs.readFileSync(pathlib.join(__dirname, 'lua/z-get-mailbox-path.lua'), 'utf-8');
const sListAccountsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/s-list-accounts.lua'), 'utf-8');
const hPushScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-push.lua'), 'utf-8');
const hSetBiggerScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-bigger.lua'), 'utf-8');
const hUpdateBiggerScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-update-bigger.lua'), 'utf-8');
const hSetExistsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-set-exists.lua'), 'utf-8');
const hIncrbyExistsScript = fs.readFileSync(pathlib.join(__dirname, 'lua/h-incrby-exists.lua'), 'utf-8');

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

redis.defineCommand('hPush', {
    numberOfKeys: 1,
    lua: hPushScript
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

redis.defineCommand('hIncrbyExists', {
    numberOfKeys: 1,
    lua: hIncrbyExistsScript
});

module.exports.redis = redis;
module.exports.notifyQueue = notifyQueue;
module.exports.submitQueue = submitQueue;
module.exports.documentsQueue = documentsQueue;

// do not set up the flow producer by default
module.exports.getFlowProducer = () => new FlowProducer(module.exports.queueConf /*, Redis*/);

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
