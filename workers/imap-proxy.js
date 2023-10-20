'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const logger = require('../lib/logger');

const { readEnvValue, threadStats } = require('../lib/tools');

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
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
        default:
            logger.debug({ msg: 'Unhandled command', command });
            return 999;
    }
}

parentPort.on('message', message => {
    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

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
        logger.flush(() => process.exit(3));
    });
