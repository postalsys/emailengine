/* eslint no-console: 0, id-length: 0, no-plusplus: 0 */

'use strict';

const config = require('wild-config');
const Redis = require('ioredis');
const redisUrl = require('./lib/redis-url');
const packageData = require('./package.json');
const { threadId } = require('worker_threads');
const { readEnvValue } = require('./lib/tools');

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

const redisConf = readEnvValue('EENGINE_REDIS') || readEnvValue('REDIS_URL') || config.dbs.redis;
const REDIS_CONF = Object.assign(
    {
        // some defaults
        showFriendlyErrorStack: true,
        connectionName: `${packageData.name}@${packageData.version}[${process.pid}${threadId ? `:${threadId}` : ''}][scan]`
    },
    typeof redisConf === 'string' ? redisUrl(redisConf) : redisConf || {}
);

const redis = new Redis(REDIS_CONF);

const MAX_PAGE = 1000;

let keymap = new Map();
let countKeys = 0;

const scanKeys = () => {
    console.log('KEY,COUNT');
    return new Promise((resolve, reject) => {
        const stream = redis.scanStream({
            count: MAX_PAGE
        });

        let reading = false;
        let finished = false;

        const countKey = str => {
            if (str.match(/^bull:/)) {
                str = str.replace(/:[^:]+$/, ':*');
            } else if (/^ia[mlhrq]:/.test(str)) {
                str = str.replace(/:[^:]+$/, ':*');
            } else {
                str = str
                    .replace(/\b[a-f0-9]{16,}\b/g, m => `hash(${m.length})`)
                    .replace(/\b[0-9]{6,}\b/g, m => `num(${m.length})`)
                    .replace(/\b[a-f0-9]{8,}\b/g, m => `hash(${m.length})`)
                    .replace(/[a-z0-9._-]+@[a-z0-9.-]+/g, () => 'email()')
                    .replace(/\d{4}\/\d{2}\/\d{2}/g, () => `date(yyyy/mm/dd)`);
            }
            if (keymap.has(str)) {
                keymap.set(str, keymap.get(str) + 1);
            } else {
                keymap.set(str, 1);
            }
        };

        const readFromStream = async () => {
            let resultKeys;

            while ((resultKeys = stream.read()) !== null) {
                for (let i = 0; i < resultKeys.length; i++) {
                    countKey(resultKeys[i]);
                    countKeys++;
                }
            }
        };

        const finish = async () => {
            for (let [key, val] of keymap) {
                console.log(`"${key.replace(/"/g, '""')}",${val}`);
            }

            console.error(`Checked ${countKeys} keys`);
            resolve();
        };

        stream.on('readable', () => {
            if (!reading) {
                reading = true;
                readFromStream().then(() => {
                    reading = false;

                    if (finished) {
                        finish();
                    }
                });
            }
        });

        stream.on('end', () => {
            finished = true;
            if (reading) {
                return;
            }
            finish();
        });

        stream.on('error', err => {
            reject(err);
        });
    });
};

let start = Date.now();

let interval = setInterval(() => {
    console.error(`Key size: ${keymap.size}; Counted: ${countKeys}`);
}, 10 * 1000);

scanKeys()
    .then(() => console.error('done'))
    .catch(err => console.error(err))
    .finally(() => {
        clearInterval(interval);
        console.error(`Time: ${Date.now() - start}ms`);
        process.exit();
    });
