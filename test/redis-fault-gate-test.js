'use strict';

// test/helpers/redis-fault-gate.js, the Redis fault injection the chaos runs and the failure-path
// tests rely on. A gate that answered a reply out of order, or let a transaction half apply, would
// make those runs report EmailEngine bugs that are really bugs of the gate.

const test = require('node:test');
const assert = require('node:assert').strict;
const Redis = require('ioredis');

const { startLatencyProxy } = require('./helpers/latency-proxy');
const { frameEnd, commandName } = require('./helpers/redis-fault-gate');
const exitWhenStandalone = require('./helpers/exit-standalone');

const PREFIX = `fault-gate-${process.pid}:`;

exitWhenStandalone();

test('frameEnd() finds the end of every RESP 3 type, and waits for an incomplete one', () => {
    const frames = [
        '+OK\r\n',
        '-ERR x\r\n',
        ':5\r\n',
        '_\r\n',
        '#t\r\n',
        ',1.5\r\n',
        '(12\r\n',
        '$3\r\nabc\r\n',
        '$-1\r\n',
        '*-1\r\n',
        '!3\r\nerr\r\n',
        '=7\r\ntxt:abc\r\n',
        '*2\r\n$1\r\na\r\n:1\r\n',
        '%1\r\n+k\r\n+v\r\n',
        '~1\r\n+a\r\n',
        '>2\r\n+message\r\n$1\r\nx\r\n',
        '|1\r\n+ttl\r\n:3\r\n'
    ];
    for (const frame of frames) {
        const buf = Buffer.from(frame + '+NEXT\r\n');
        assert.equal(frameEnd(buf, 0), frame.length, frame);
        assert.equal(frameEnd(Buffer.from(frame.slice(0, -1)), 0), -1, `${frame} cut short`);
    }
    assert.equal(commandName(Buffer.from('*2\r\n$3\r\nget\r\n$1\r\nk\r\n')), 'GET');
    assert.throws(() => frameEnd(Buffer.from('$?\r\n'), 0));
});

test('the fault gate in front of a real Redis', async t => {
    const proxy = await startLatencyProxy({ port: 6379, resp: true });
    const direct = new Redis({ db: 13, lazyConnect: true });
    const client = new Redis({ port: proxy.port, db: 13, maxRetriesPerRequest: null, lazyConnect: true });
    await direct.connect();
    await client.connect();
    client.defineCommand('faultGateScript', { numberOfKeys: 1, lua: 'return redis.call("SET", KEYS[1], ARGV[1])' });

    t.after(async () => {
        const keys = await direct.keys(`${PREFIX}*`);
        if (keys.length) {
            await direct.del(keys);
        }
        client.disconnect();
        direct.disconnect();
        await proxy.stop();
    });
    t.afterEach(() => proxy.setFaults({ rate: 0 }));

    await t.test('passes everything through while no faults are set', async () => {
        const big = 'x'.repeat(3 * 1024 * 1024);
        await client.set(`${PREFIX}big`, big);
        assert.equal(await client.get(`${PREFIX}big`), big, 'a value spread over many chunks arrives whole');
        assert.deepEqual(await client.hgetall(`${PREFIX}missing`), {});
    });

    await t.test('fails a write with OOM and a read with LOADING, and keeps pipelined replies in order', async () => {
        await direct.set(`${PREFIX}a`, '1');
        proxy.setFaults({ rate: 1, kind: 'any', only: new Set(['SET', 'HGET']) });
        const results = await client.pipeline().get(`${PREFIX}a`).set(`${PREFIX}a`, '2').hget(`${PREFIX}h`, 'f').get(`${PREFIX}a`).exec();
        assert.deepEqual(results[0], [null, '1']);
        assert.match(results[1][0].message, /^OOM /);
        assert.match(results[2][0].message, /^LOADING /);
        assert.deepEqual(results[3], [null, '1'], 'the refused write was never sent');
        assert.equal(proxy.setFaults({ rate: 0 }), 2, 'counts what it injected');
    });

    await t.test('the oom kind fails only what a full Redis refuses', async () => {
        await direct.set(`${PREFIX}o`, '1');
        proxy.setFaults({ rate: 1 });
        await assert.rejects(client.set(`${PREFIX}o`, '2'), /^ReplyError: OOM /);
        await assert.rejects(client.hset(`${PREFIX}oh`, 'f', 'v'), /^ReplyError: OOM /);
        assert.equal(await client.get(`${PREFIX}o`), '1', 'reads still work');
        assert.equal(await client.del(`${PREFIX}o`), 1, 'and so do deletes, which free memory');
    });

    await t.test('fails a script with OOM before it runs', async () => {
        proxy.setFaults({ rate: 1, only: new Set(['EVALSHA', 'EVAL']) });
        await assert.rejects(client.faultGateScript(`${PREFIX}s`, 'v'), /^ReplyError: OOM /);
        proxy.setFaults({ rate: 0 });
        assert.equal(await direct.exists(`${PREFIX}s`), 0);
        assert.equal(await client.faultGateScript(`${PREFIX}s`, 'v'), 'OK');
    });

    await t.test('a command failed inside a transaction aborts all of it, as Redis does', async () => {
        proxy.setFaults({ rate: 1, only: new Set(['INCR']) });
        await assert.rejects(client.multi().set(`${PREFIX}t1`, '1').incr(`${PREFIX}t2`).exec(), err => {
            assert.match(err.message, /EXECABORT/);
            assert.match(err.previousErrors[0].message, /^OOM /, 'ioredis names the refused command');
            return true;
        });
        assert.equal(await direct.exists(`${PREFIX}t1`, `${PREFIX}t2`), 0, 'nothing of it was applied');
        proxy.setFaults({ rate: 0 });
        assert.deepEqual(await client.multi().set(`${PREFIX}t1`, '1').get(`${PREFIX}t1`).exec(), [
            [null, 'OK'],
            [null, '1']
        ]);
    });

    await t.test('a subscriber connection is passed through untouched', async () => {
        const subscriber = new Redis({ port: proxy.port, db: 13, lazyConnect: true });
        await subscriber.connect();
        try {
            proxy.setFaults({ rate: 1, kind: 'any' });
            const received = new Promise(resolve => subscriber.on('message', (channel, message) => resolve(message)));
            await subscriber.subscribe(`${PREFIX}channel`);
            await direct.publish(`${PREFIX}channel`, 'hello');
            assert.equal(await received, 'hello');
        } finally {
            subscriber.disconnect();
        }
    });

    await t.test('connection setup is never failed, so a client can always reconnect', async () => {
        proxy.setFaults({ rate: 1, kind: 'any', only: null });
        const fresh = new Redis({ port: proxy.port, db: 13, lazyConnect: true });
        try {
            await fresh.connect();
            assert.equal(fresh.status, 'ready');
            await assert.rejects(fresh.get(`${PREFIX}a`), /^ReplyError: LOADING /);
        } finally {
            fresh.disconnect();
        }
    });
});
