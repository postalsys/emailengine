'use strict';

// lib/metrics-collector.js, the background reader behind /metrics thread gauges and the admin
// dashboard's thread table, driven with stand-in workers so a thread that answers, one that times
// out and one that errors can be told apart without starting any.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const MetricsCollector = require('../lib/metrics-collector');
const { createMockLogger } = require('./helpers/mock-logger');

registerRedisTeardown(redis);

function createCollector({ workers, answers, metadata = {}, ...options }) {
    const asked = [];
    const collector = new MetricsCollector({
        logger: createMockLogger(),
        delayBetweenWorkers: 0,
        startTime: 12345,
        getWorkers: () => workers,
        getWorkerMetadata: worker => metadata[worker.threadId] || {},
        callWorker: async (worker, message) => {
            asked.push({ threadId: worker.threadId, message });
            const answer = answers[worker.threadId];
            if (answer instanceof Error) {
                throw answer;
            }
            return answer;
        },
        ...options
    });
    return { collector, asked };
}

const timeoutError = () => Object.assign(new Error('Timeout waiting for response'), { code: 'Timeout' });

test('MetricsCollector.collectInBackground()', async t => {
    await t.test('reports the main thread first, then every worker with its reading and metadata', async () => {
        const workers = new Map([
            ['imap', new Set([{ threadId: 3, resourceLimits: { maxOldGenerationSizeMb: 512 } }])],
            ['webhooks', new Set([{ threadId: 5 }])]
        ]);
        const { collector, asked } = createCollector({
            workers,
            answers: { 3: { heapUsed: 100, heapTotal: 200 }, 5: { heapUsed: 10, heapTotal: 20 } },
            metadata: { 3: { accounts: 42 } }
        });

        const threads = await collector.collectInBackground();

        assert.equal(threads[0].type, 'main');
        assert.equal(threads[0].isMain, true);
        assert.equal(threads[0].online, 12345);
        assert.ok(Number.isFinite(threads[0].heapUsed), 'the main thread reads its own usage');

        assert.deepEqual(threads.slice(1), [
            { type: 'imap', threadId: 3, resourceLimits: { maxOldGenerationSizeMb: 512 }, heapUsed: 100, heapTotal: 200, accounts: 42 },
            { type: 'webhooks', threadId: 5, resourceLimits: undefined, heapUsed: 10, heapTotal: 20 }
        ]);
        assert.deepEqual(
            asked.map(entry => entry.message.cmd),
            ['resource-usage', 'resource-usage']
        );
        assert.ok(
            asked.every(entry => entry.message.timeout === 500),
            'each worker gets the per-worker timeout'
        );
    });

    await t.test('a worker that times out is reported unresponsive, one that errors is not', async () => {
        const workers = new Map([['imap', new Set([{ threadId: 3 }, { threadId: 4 }])]]);
        const { collector } = createCollector({
            workers,
            answers: { 3: timeoutError(), 4: Object.assign(new Error('Worker exited'), { code: 'WorkerExit' }) }
        });

        const threads = await collector.collectInBackground();

        assert.deepEqual(threads[1].resourceUsageError, { error: 'Timeout waiting for response', code: 'Timeout', unresponsive: true });
        assert.deepEqual(threads[2].resourceUsageError, { error: 'Worker exited', code: 'WorkerExit', unresponsive: false });
    });

    await t.test('an empty or missing worker set contributes nothing', async () => {
        const { collector } = createCollector({
            workers: new Map([
                ['api', new Set()],
                ['smtp', null]
            ]),
            answers: {}
        });
        const threads = await collector.collectInBackground();
        assert.deepEqual(
            threads.map(thread => thread.type),
            ['main']
        );
    });
});

test('MetricsCollector.getThreadsInfo()', async t => {
    await t.test('serves the cached collection until a refresh is forced', async () => {
        const workers = new Map([['imap', new Set([{ threadId: 3 }])]]);
        const answers = { 3: { heapUsed: 1 } };
        const { collector, asked } = createCollector({ workers, answers });

        const first = await collector.getThreadsInfo();
        answers[3] = { heapUsed: 2 };
        const cached = await collector.getThreadsInfo();
        assert.equal(cached, first, 'the same collection is returned');
        assert.equal(asked.length, 1);

        const refreshed = await collector.getThreadsInfo(true);
        assert.equal(refreshed[1].heapUsed, 2);
        assert.equal(asked.length, 2);
    });

    await t.test('getStats() reflects the cache', async () => {
        const { collector } = createCollector({ workers: new Map(), answers: {} });
        assert.equal(collector.getStats().hasCachedData, false);
        await collector.getThreadsInfo();
        const stats = collector.getStats();
        assert.equal(stats.hasCachedData, true);
        assert.equal(stats.cachedWorkerCount, 1);
        assert.equal(stats.collectorRunning, false);
    });
});

test('MetricsCollector.start() and stop()', async () => {
    const { collector, asked } = createCollector({
        workers: new Map([['imap', new Set([{ threadId: 3 }])]]),
        answers: { 3: {} },
        cacheInterval: 10
    });

    collector.start();
    assert.equal(collector.getStats().collectorRunning, true);
    // the first collection runs immediately, later ones on the interval
    await new Promise(resolve => setTimeout(resolve, 60));
    collector.stop();
    assert.equal(collector.getStats().collectorRunning, false);

    const collected = asked.length;
    assert.ok(collected >= 2, `collected ${collected} times`);
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.equal(asked.length, collected, 'nothing runs after stop()');
});
