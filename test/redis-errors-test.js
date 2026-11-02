'use strict';

// lib/utils/redis-errors.js: which Redis replies a caller holding work durably may retry later

const test = require('node:test');
const assert = require('node:assert').strict;

const { isTransientRedisError } = require('../lib/utils/redis-errors');

const reply = (message, extra) => Object.assign(new Error(message), { name: 'ReplyError' }, extra);

test('replies that clear up on their own are transient', () => {
    for (const message of [
        "OOM command not allowed when used memory > 'maxmemory'.",
        'LOADING Redis is loading the dataset in memory',
        'BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSAVE.',
        "READONLY You can't write against a read only replica.",
        'MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to no.',
        'MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk.',
        'TRYAGAIN Multiple keys request during rehashing of slot',
        'CLUSTERDOWN The cluster is down',
        'NOREPLICAS Not enough good replicas to write.'
    ]) {
        assert.equal(isTransientRedisError(reply(message)), true, message);
    }
});

test('a reply that fails the same way every time is not', () => {
    assert.equal(isTransientRedisError(reply('WRONGTYPE Operation against a key holding the wrong kind of value')), false);
    assert.equal(isTransientRedisError(reply("ERR unknown command 'FOO'")), false);
    assert.equal(isTransientRedisError(reply('NOSCRIPT No matching script')), false);
    // Only a reply from Redis: an application error that happens to start with the word is not one
    assert.equal(isTransientRedisError(new Error('LOADING the page failed')), false);
    assert.equal(isTransientRedisError(null), false);
});

test('an aborted transaction is transient only when everything that failed in it was', () => {
    const oom = reply("OOM command not allowed when used memory > 'maxmemory'.");
    const syntax = reply("ERR wrong number of arguments for 'hset' command");
    const abort = previousErrors => reply('EXECABORT Transaction discarded because of previous errors.', { previousErrors });
    assert.equal(isTransientRedisError(abort([oom, oom])), true);
    assert.equal(isTransientRedisError(abort([oom, syntax])), false);
    assert.equal(isTransientRedisError(abort([])), false);
    assert.equal(isTransientRedisError(abort(undefined)), false);
});

test('an error wrapping a transient reply counts too', () => {
    const loading = reply('LOADING Redis is loading the dataset in memory');
    assert.equal(isTransientRedisError(new Error('Sync failed', { cause: loading })), true);
    assert.equal(isTransientRedisError(new Error('Sync failed', { cause: new Error('Sync failed', { cause: loading }) })), true);
    assert.equal(isTransientRedisError(new Error('Sync failed', { cause: new Error('parse failure') })), false);
    const abort = reply('EXECABORT Transaction discarded because of previous errors.');
    abort.previousErrors = [abort];
    assert.equal(isTransientRedisError(abort), false, 'an abort that lists itself ends too');
    const loop = new Error('loop');
    loop.cause = loop;
    assert.equal(isTransientRedisError(loop), false, 'a cause chain that loops ends');
});

test('an aborted transaction with many failed commands is still transient', () => {
    // every() handed the index in as the depth argument, so from the seventh failed command on the
    // depth limit read the abort as permanent and the work was dropped
    const oom = reply("OOM command not allowed when used memory > 'maxmemory'.");
    const previousErrors = Array.from({ length: 50 }, () => oom);
    assert.equal(isTransientRedisError(reply('EXECABORT Transaction discarded because of previous errors.', { previousErrors })), true);
});
