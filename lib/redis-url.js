'use strict';

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
                parsedUrl.host = value;
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
