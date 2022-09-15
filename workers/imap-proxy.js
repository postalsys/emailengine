'use strict';

const packageData = require('../package.json');
const logger = require('../lib/logger');

const { readEnvValue } = require('../lib/tools');

const { run } = require('../lib/imapproxy/imap-server');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'imapProxy', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'imapProxy', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'imapProxy', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'imapProxy', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
}

run()
    .then(imapServer => {
        let address = imapServer.server.address();
        logger.debug({
            msg: 'Started IMAP proxy server thread',
            address,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.error({ msg: 'Failed to initialize IMAP server', err });
        setImmediate(() => process.exit(3));
    });
