'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const logger = require('../lib/logger');

const { threadStats } = require('../lib/tools');

const { run, reloadCertificates } = require('../lib/imapproxy/imap-server');
const { respond, isCall } = require('../lib/worker-rpc');

const { initSentry } = require('../lib/sentry');
initSentry('imapProxy');

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();

        case 'imapProxyReloadCertificates':
            return await reloadCertificates();
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

// Responses to this worker's own calls are settled by lib/imapproxy/imap-server.js, which owns the
// calling half
parentPort.on('message', message => {
    if (isCall(message)) {
        return respond(parentPort, message, onCommand, { logger });
    }
});

run()
    .then(imapServer => {
        let address = imapServer.server.address();
        logger.info({
            msg: 'Started IMAP proxy server thread',
            address,
            version: packageData.version
        });
    })
    .catch(err => {
        logger.fatal({ msg: 'Failed to initialize IMAP proxy server', err });
        logger.flush(() => process.exit(3));
    });
