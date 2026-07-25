'use strict';

/**
 * Strips EmailEngine's handlers from an ImapFlow client that is being abandoned and
 * leaves a permanent 'error' sink behind.
 *
 * ImapFlow reports connection failures with a bare `emit('error')`, so an instance
 * left without an 'error' listener turns the next socket failure into an
 * uncaughtException that takes the whole worker thread down with it. An abandoned
 * client is closed but not yet dead: `close()` returns before the socket teardown
 * finishes, so a reset can still surface a few ticks later. The sink therefore has
 * to outlive `close()` - a `once()` handler only covers the first error and a
 * handler removed right after `close()` covers none at all.
 *
 * @param {EventEmitter} imapClient - Client being abandoned
 * @param {Object} logger - Logger the sink reports through
 * @param {Object} [meta] - Extra fields to log with a sunk error
 */
function detachImapClient(imapClient, logger, meta) {
    imapClient.removeAllListeners();

    imapClient.on('error', err => {
        logger.warn({ msg: 'IMAP connection error', ...meta, err });
    });
}

module.exports = { detachImapClient };
