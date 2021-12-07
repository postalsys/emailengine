'use strict';

module.exports = redisConf => {
    let parsedRedisUrl = new URL(redisConf);
    let parsedUrl = {};

    for (let key of parsedRedisUrl.searchParams.keys()) {
        let value = parsedRedisUrl.searchParams.get(key);
        if (!value) {
            continue;
        }
        switch (key) {
            case 'password':
                parsedUrl.password = value;
                break;

            case 'db': {
                if (value && !isNaN(value)) {
                    parsedUrl.db = Number(value);
                }
                break;
            }
        }
    }

    for (let key of ['hostname', 'port', 'password', 'pathname', 'protocol']) {
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
                parsedUrl.password = value;
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
