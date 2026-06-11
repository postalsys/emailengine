'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const logger = require('../lib/logger');

const { threadStats } = require('../lib/tools');

const { run } = require('../lib/imapproxy/imap-server');

const { initSentry } = require('../lib/sentry');
initSentry('imapProxy');

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
        default:
            logger.debug({ msg: 'Unhandled command', command });
            return 999;
    }
}

// Start sending heartbeats to main thread
setInterval(() => {
    try {
        parentPort.postMessage({ cmd: 'heartbeat' });
    } catch (err) {
        // Ignore errors, parent might be shutting down
    }
}, 10 * 1000).unref();

// Send initial ready signal
parentPort.postMessage({ cmd: 'ready' });

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
