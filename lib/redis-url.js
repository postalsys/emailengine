'use strict';

const { readEnvValue } = require('./read-env-value');
const { getBoolean } = require('./get-boolean');

/**
 * Some managed Redis services (the Heroku Redis add-on among them) present a certificate no CA
 * signed. `EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED=false` relaxes verification for the Redis
 * connection alone. The Heroku manifest used to set NODE_TLS_REJECT_UNAUTHORIZED=0 for that, which
 * switched certificate checks off for every outbound connection of the instance: OAuth2 token
 * refreshes, webhooks, IMAP and SMTP included.
 *
 * @param {Object} conf - ioredis options; changed in place
 * @returns {Object} conf
 */
function applyRedisTlsSwitch(conf) {
    const value = readEnvValue('EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED');
    if (conf.tls && typeof value === 'string' && value.trim() && !getBoolean(value)) {
        conf.tls = Object.assign({}, conf.tls, { rejectUnauthorized: false });
    }
    return conf;
}

module.exports = redisConf => {
    let parsedRedisUrl = new URL(redisConf);
    let parsedUrl = {};

    let usernameAllowed = false;
    for (let key of parsedRedisUrl.searchParams.keys()) {
        let value = parsedRedisUrl.searchParams.get(key);
        if (!value) {
            continue;
        }
        switch (key) {
            case 'password':
                parsedUrl.password = value;
                break;

            case 'family':
                parsedUrl.family = Number(value.replace(/[^\d]/g, '')) || 0;
                break;

            case 'db':
                {
                    if (value && !isNaN(value)) {
                        parsedUrl.db = Number(value);
                    }
                }
                break;
            case 'allowUsernameInURI':
                if (/^(true|1|yes|y)$/i.test(value)) {
                    usernameAllowed = true;
                }
                break;
        }
    }

    for (let key of ['hostname', 'port', 'password', 'pathname', 'protocol', 'username']) {
        let value = parsedRedisUrl[key];
        if (!value) {
            continue;
        }
        switch (key) {
            case 'hostname':
                // WHATWG URL keeps the brackets around an IPv6 literal, which net.connect() cannot
                // resolve, so redis://[::1]:6379 never connected
                parsedUrl.host = value.replace(/^\[(.*)\]$/, '$1');
                break;

            case 'port':
                parsedUrl.port = Number(value);
                break;

            case 'password':
                parsedUrl.password = decodeURIComponent(value);
                break;

            case 'username':
                if (usernameAllowed || (value && value !== 'default')) {
                    parsedUrl.username = decodeURIComponent(value);
                }
                break;

            case 'pathname': {
                let pathname = value.slice(1);
                if (pathname && !isNaN(pathname)) {
                    parsedUrl.db = Number(pathname);
                }
                break;
            }

            case 'protocol':
                if (value.toLowerCase() === 'rediss:') {
                    parsedUrl.tls = {};
                }
                break;
        }
    }

    return parsedUrl;
};

module.exports.applyRedisTlsSwitch = applyRedisTlsSwitch;
