'use strict';

// How the two provider poll intervals read their environment values. They share a name pattern but
// not semantics: the Outlook pass can be switched off with 0 and has a floor, the Gmail poller has
// neither. What they now share is the duration form, which the Gmail variable used to ignore.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { parseGmailFallbackPollInterval, DEFAULT_FALLBACK_POLL_INTERVAL } = require('../lib/email-client/gmail-fallback-poll');
const { parseFallbackPollInterval } = require('../lib/email-client/outlook-fallback-poll');

registerRedisTeardown(redis);

test('EENGINE_GMAIL_FALLBACK_POLL_INTERVAL', async t => {
    await t.test('takes a duration', () => {
        assert.equal(parseGmailFallbackPollInterval('10m'), 10 * 60 * 1000);
        assert.equal(parseGmailFallbackPollInterval('30s'), 30 * 1000);
        assert.equal(parseGmailFallbackPollInterval('1h'), 60 * 60 * 1000);
    });

    await t.test('still takes bare milliseconds, the form the integration tier sets', () => {
        assert.equal(parseGmailFallbackPollInterval('15000'), 15000);
        assert.equal(parseGmailFallbackPollInterval(' 15000 '), 15000);
        assert.equal(parseGmailFallbackPollInterval(15000), 15000);
    });

    await t.test('unset, zero and unreadable values get the default', () => {
        for (const value of [undefined, null, '', '   ', '0', 0, 'soon', '-5s']) {
            assert.equal(parseGmailFallbackPollInterval(value), DEFAULT_FALLBACK_POLL_INTERVAL, JSON.stringify(value));
        }
    });
});

test('EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL', async t => {
    await t.test('takes a duration and bare milliseconds', () => {
        assert.equal(parseFallbackPollInterval('10m'), 10 * 60 * 1000);
        assert.equal(parseFallbackPollInterval('60000'), 60000);
    });

    await t.test('0 switches the pass off', () => {
        assert.equal(parseFallbackPollInterval('0'), 0);
    });

    await t.test('a positive value is never shorter than ten seconds', () => {
        assert.equal(parseFallbackPollInterval('1s'), 10 * 1000);
        assert.equal(parseFallbackPollInterval('500'), 10 * 1000);
    });

    await t.test('unset or unreadable values get the default', () => {
        assert.equal(parseFallbackPollInterval(undefined), 10 * 60 * 1000);
        assert.equal(parseFallbackPollInterval(''), 10 * 60 * 1000);
        assert.equal(parseFallbackPollInterval('soon'), 10 * 60 * 1000);
    });
});
