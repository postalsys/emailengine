'use strict';

// threadStats.usage() is what every thread answers the metrics collector with, and its event loop
// delay is what the Workers page, the Prometheus thread gauges and the heartbeat log lines report.
// A reading covers the time since the previous one, so a block shows up in the next reading and is
// gone from the one after it.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { threadStats } = require('../lib/tools');

const tick = ms => new Promise(resolve => setTimeout(resolve, ms));

function blockFor(ms) {
    let until = Date.now() + ms;
    while (Date.now() < until) {
        // a synchronous stretch the event loop cannot interrupt
    }
}

test('threadStats event loop delay', async t => {
    await t.test('the first reading starts the measurement', () => {
        assert.equal(threadStats.usage().eventLoopDelay, null);
    });

    await t.test('a synchronous block shows up in the next reading', async () => {
        await tick(50);
        blockFor(200);
        await tick(50);

        let reading = threadStats.usage().eventLoopDelay;
        assert.ok(reading, 'a reading is reported');
        assert.ok(reading.max >= 150, `max ${reading.max}ms covers the block`);
        assert.ok(reading.p99 <= reading.max);
    });

    await t.test('and is gone from the reading after it', async () => {
        await tick(100);
        let reading = threadStats.usage().eventLoopDelay;
        assert.ok(!reading || reading.max < 150, 'the previous window was reset');
    });
});
