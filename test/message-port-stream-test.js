'use strict';

// Regression tests for lib/message-port-stream.js used to bridge message/attachment
// downloads from the IMAP worker to the API worker over a MessageChannel.
//
// Commit 2: a mid-download error on the IMAP source stream must NOT become an
// unhandled 'error' that crashes the worker. pipeToMessagePort() wires error
// propagation so the source error tears the transfer down cleanly.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable } = require('node:stream');
const { MessageChannel } = require('node:worker_threads');

const { MessagePortWritable, pipeToMessagePort } = require('../lib/message-port-stream');

test('pipeToMessagePort() handles a source error without throwing', async () => {
    const { port1, port2 } = new MessageChannel();
    // Drain anything the writer posts so the channel does not buffer.
    port1.on('message', () => {});

    try {
        const writable = new MessagePortWritable(port2);
        const source = new Readable({ read() {} });

        let loggedError = null;
        pipeToMessagePort(source, writable, {
            error(entry) {
                loggedError = entry;
            }
        });

        source.push('partial chunk');

        // Mid-download failure on the IMAP side.
        const boom = new Error('IMAP connection dropped mid-download');
        await new Promise(resolve => {
            writable.on('close', resolve);
            source.destroy(boom);
        });

        assert.strictEqual(writable.destroyed, true, 'writable should be destroyed when the source errors');
        assert.ok(loggedError && loggedError.err === boom, 'the source error should be logged, not thrown');
    } finally {
        port1.close();
        port2.close();
    }
});
