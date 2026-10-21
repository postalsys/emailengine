'use strict';

// Unit tests for lib/redis-reconnect.js, the ioredis reconnectOnError decision. A Redis that
// refuses writes under maxmemory used to make every client reconnect on every refused command,
// and the IMAP worker restarts on each reconnect, so one full Redis became a restart loop.

const test = require('node:test');
const assert = require('node:assert').strict;

const { reconnectOnErrorReply, RESEND_AFTER_RECONNECT } = require('../lib/redis-reconnect');
const { redis, REDIS_CONF } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const replyError = message => {
    let err = new Error(message);
    err.name = 'ReplyError';
    return err;
};

test('reconnectOnErrorReply', async t => {
    await t.test('reconnects and resends after a failover demoted the node', () => {
        assert.strictEqual(reconnectOnErrorReply(replyError("READONLY You can't write against a read only replica.")), RESEND_AFTER_RECONNECT);
    });

    await t.test('keeps the connection on a refused write under maxmemory', () => {
        assert.strictEqual(reconnectOnErrorReply(replyError("OOM command not allowed when used memory > 'maxmemory'.")), false);
    });

    await t.test('keeps the connection on ordinary command errors', () => {
        for (let message of [
            'WRONGTYPE Operation against a key holding the wrong kind of value',
            'NOSCRIPT No matching script. Please use EVAL.',
            'ERR Error running script: Missing lock for job 1',
            'LOADING Redis is loading the dataset in memory',
            'EXECABORT Transaction discarded because of previous errors.'
        ]) {
            assert.strictEqual(reconnectOnErrorReply(replyError(message)), false, message);
        }
    });

    await t.test('only matches READONLY at the start of the reply', () => {
        assert.strictEqual(reconnectOnErrorReply(replyError('ERR key READONLY is missing')), false);
        assert.strictEqual(reconnectOnErrorReply(replyError('READONLYX')), false);
    });

    await t.test('tolerates a missing or malformed error', () => {
        assert.strictEqual(reconnectOnErrorReply(), false);
        assert.strictEqual(reconnectOnErrorReply(null), false);
        assert.strictEqual(reconnectOnErrorReply({ message: 42 }), false);
    });
});

test('the shared Redis configuration uses the decision', () => {
    assert.strictEqual(REDIS_CONF.reconnectOnError(replyError("OOM command not allowed when used memory > 'maxmemory'.")), false);
    assert.strictEqual(REDIS_CONF.reconnectOnError(replyError('READONLY demoted')), RESEND_AFTER_RECONNECT);
});
