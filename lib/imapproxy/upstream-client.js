'use strict';

const { ImapFlow } = require('imapflow');

/**
 * Creates the upstream ImapFlow client of a proxied session with a permanent 'error' sink.
 *
 * ImapFlow reports connection failures with a bare `emit('error')`, so an instance left
 * without an 'error' listener turns the next socket failure into an uncaughtException that
 * takes the whole IMAP proxy worker down with it. Two windows are only covered by a sink
 * attached here:
 *
 *   - `connect()` resolving and `unbind()` detaching ImapFlow's socket handlers are separated
 *     by an await, and a reset landing in between has nowhere else to go. (While `connect()`
 *     is still pending ImapFlow rejects the promise instead of emitting, so that part is safe
 *     on its own.)
 *   - after the handoff the caller wires teardown onto the sockets rather than the client, and
 *     `close()` on an already-dead connection can still surface an error on the instance.
 *
 * The sink therefore has to live for as long as the client does - it is attached before
 * `connect()` and never removed.
 *
 * @param {Object} imapConfig - ImapFlow options for the upstream connection
 * @returns {ImapFlow} Client with an error sink attached
 */
function createUpstreamClient(imapConfig) {
    let imapClient = new ImapFlow(imapConfig);

    // reads the id off the client so the sink does not keep the config (credentials
    // included) alive through the closure for as long as the connection lives
    imapClient.on('error', err => {
        imapClient.log.warn({ msg: 'Upstream IMAP connection error', cid: imapClient.id, err });
    });

    return imapClient;
}

module.exports = { createUpstreamClient };
