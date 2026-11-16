'use strict';

// The /metrics surface: names, types, help texts, label names and histogram buckets are what
// dashboards and alerts are written against, so test/fixtures/metrics-golden.json records them.
// Re-record with UPDATE_METRICS_GOLDEN=true after a deliberate change and review the diff.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const pathlib = require('node:path');

const { promClient, setupMetrics, connectionCounts } = require('../lib/metrics');

const GOLDEN = pathlib.join(__dirname, 'fixtures', 'metrics-golden.json');

const metrics = setupMetrics();

async function describeMetrics() {
    const custom = {};
    for (const [key, metric] of Object.entries(metrics)) {
        const [json] = (await promClient.register.getMetricsAsJSON()).filter(entry => entry.name === metric.name);
        custom[key] = {
            name: metric.name,
            type: json.type,
            help: metric.help,
            labelNames: [...(metric.labelNames || [])],
            ...(metric.upperBounds ? { buckets: metric.upperBounds.filter(bound => bound !== Infinity) } : {})
        };
    }
    const customNames = new Set(Object.values(custom).map(entry => entry.name));
    const defaults = (await promClient.register.getMetricsAsJSON())
        .filter(entry => !customNames.has(entry.name))
        .map(entry => `${entry.name} ${entry.type}`)
        .sort();
    return { custom, defaults };
}

test('the metrics keep their names, types, help texts, labels and buckets', async () => {
    const actual = await describeMetrics();
    if (process.env.UPDATE_METRICS_GOLDEN === 'true') {
        fs.writeFileSync(GOLDEN, JSON.stringify(actual, null, 4) + '\n');
    }
    assert.deepEqual(actual, JSON.parse(fs.readFileSync(GOLDEN, 'utf8')));
});

test('the exposition text names and types every metric', async () => {
    const text = await promClient.register.metrics();
    assert.match(promClient.register.contentType, /^text\/plain; version=0\.0\.4/);
    for (const metric of Object.values(metrics)) {
        assert.ok(text.includes(`# HELP ${metric.name} `), metric.name);
        assert.ok(text.includes(`# TYPE ${metric.name} `), metric.name);
    }
    assert.match(text, /^process_cpu_user_seconds_total \d/m);
});

test('a gauge reset to rebuild its series drops the old ones', async () => {
    metrics.threadHeapUsed.set({ thread: '1', type: 'imap' }, 10);
    metrics.threadHeapUsed.reset();
    metrics.threadHeapUsed.set({ thread: '2', type: 'imap' }, 20);
    const { values } = await metrics.threadHeapUsed.get();
    assert.deepEqual(
        values.map(({ labels, value }) => ({ labels, value })),
        [{ labels: { thread: '2', type: 'imap' }, value: 20 }]
    );
});

test('connectionCounts reads the IMAP connection gauge by status', async () => {
    metrics.imapConnections.reset();
    assert.deepEqual(await connectionCounts(metrics.imapConnections), {});
    metrics.imapConnections.set({ status: 'connected' }, 3);
    metrics.imapConnections.set({ status: 'authenticationError' }, 1);
    metrics.imapConnections.inc({ status: 'connected' });
    assert.deepEqual(await connectionCounts(metrics.imapConnections), { connected: 4, authenticationError: 1 });
});
