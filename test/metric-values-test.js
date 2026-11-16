'use strict';

// lib/metric-values.js: the license and thread gauge values updateQueueCounters() in server.js
// publishes, computed without the gauges.

const test = require('node:test');
const assert = require('node:assert').strict;

const { licenseDaysRemaining, countThreads } = require('../lib/metric-values');

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-11-16T12:00:00.000Z');

test('licenseDaysRemaining', async t => {
    await t.test('no active license is 0', () => {
        assert.equal(licenseDaysRemaining({ active: false, details: { expires: new Date(NOW + 10 * DAY).toISOString() } }, NOW), 0);
        assert.equal(licenseDaysRemaining({ active: true }, NOW), 0);
        assert.equal(licenseDaysRemaining({ active: true, details: null }, NOW), 0);
    });

    await t.test('a lifetime license is -1, even with an expiry', () => {
        assert.equal(licenseDaysRemaining({ active: true, details: { lt: true, expires: new Date(NOW + DAY).toISOString() } }, NOW), -1);
    });

    await t.test('a subscription license without a fixed expiry is -1', () => {
        assert.equal(licenseDaysRemaining({ active: true, details: {} }, NOW), -1);
    });

    await t.test('a time-limited license counts whole days, rounding up', () => {
        const expiresIn = ms => ({ active: true, details: { expires: new Date(NOW + ms).toISOString() } });
        assert.equal(licenseDaysRemaining(expiresIn(10 * DAY), NOW), 10);
        assert.equal(licenseDaysRemaining(expiresIn(10 * DAY - 1000), NOW), 10);
        assert.equal(licenseDaysRemaining(expiresIn(10 * DAY + 1000), NOW), 11);
        assert.equal(licenseDaysRemaining(expiresIn(1000), NOW), 1);
    });

    await t.test('an expired license is 0, never negative', () => {
        assert.equal(licenseDaysRemaining({ active: true, details: { expires: new Date(NOW - 5 * DAY).toISOString() } }, NOW), 0);
    });
});

test('countThreads', async t => {
    const RECENT = 10 * 60 * 1000;

    await t.test('splits each type by whether it came online within the window, in first-seen order', () => {
        const { threadCounts, unresponsiveCount } = countThreads(
            [
                { type: 'imap', online: NOW - RECENT - 1 },
                { type: 'imap', online: NOW - 1000 },
                { type: 'api', online: NOW - 2 * RECENT },
                { type: 'imap', online: NOW - RECENT },
                { type: 'imap', online: NOW - 5000 }
            ],
            NOW,
            RECENT
        );
        assert.deepEqual(
            [...threadCounts.entries()],
            [
                ['imap_total', 2],
                ['imap_recent', 2],
                ['api_total', 1]
            ]
        );
        assert.equal(unresponsiveCount, 0);
    });

    await t.test('counts the threads that did not answer a resource reading', () => {
        const { unresponsiveCount } = countThreads(
            [
                { type: 'imap', online: 0, resourceUsageError: { unresponsive: true } },
                { type: 'imap', online: 0, resourceUsageError: { unresponsive: false } },
                { type: 'api', online: 0, resourceUsageError: {} },
                { type: 'webhooks', online: 0, resourceUsageError: { unresponsive: 1 } }
            ],
            NOW,
            RECENT
        );
        assert.equal(unresponsiveCount, 2);
    });

    await t.test('no readings count nothing', () => {
        for (const threadsInfo of [[], null, undefined]) {
            const { threadCounts, unresponsiveCount } = countThreads(threadsInfo, NOW, RECENT);
            assert.equal(threadCounts.size, 0);
            assert.equal(unresponsiveCount, 0);
        }
    });
});
