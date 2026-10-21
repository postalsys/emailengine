'use strict';

// webhookRetryPolicy() in lib/webhook-routing.js: the attempts and backoff every webhook delivery
// job is queued with, from the webhooksDeliveryAttempts and webhooksRetryDelay settings. They used
// to be fixed at 10 attempts and a 5 second first delay.

const test = require('node:test');
const assert = require('node:assert').strict;

const { webhookRetryPolicy } = require('../lib/webhook-routing');
const {
    DEFAULT_WEBHOOK_ATTEMPTS,
    MAX_WEBHOOK_ATTEMPTS,
    DEFAULT_WEBHOOK_RETRY_DELAY,
    MIN_WEBHOOK_RETRY_DELAY,
    MAX_WEBHOOK_RETRY_DELAY
} = require('../lib/consts');
const { settingsSchema } = require('../lib/schemas');
const { forAll, gen } = require('./helpers/property');

test('webhookRetryPolicy', async t => {
    await t.test('without settings it is the policy deliveries always had', () => {
        assert.deepEqual(webhookRetryPolicy(), {
            attempts: 10,
            backoff: { type: 'exponential', delay: 5000, jitter: 0.2 }
        });
        assert.equal(DEFAULT_WEBHOOK_ATTEMPTS, 10);
        assert.equal(DEFAULT_WEBHOOK_RETRY_DELAY, 5000);
    });

    await t.test('the settings decide attempts and the first delay', () => {
        const policy = webhookRetryPolicy({ webhooksDeliveryAttempts: 3, webhooksRetryDelay: 60000 });
        assert.equal(policy.attempts, 3);
        assert.equal(policy.backoff.delay, 60000);
        assert.equal(policy.backoff.type, 'exponential');
    });

    await t.test('an unset or cleared setting falls back to the default', () => {
        for (const value of [null, undefined, '', 'abc', 2.5, NaN]) {
            const policy = webhookRetryPolicy({ webhooksDeliveryAttempts: value, webhooksRetryDelay: value });
            assert.equal(policy.attempts, DEFAULT_WEBHOOK_ATTEMPTS, String(value));
            assert.equal(policy.backoff.delay, DEFAULT_WEBHOOK_RETRY_DELAY, String(value));
        }
    });

    await t.test('property: any stored value gives a policy inside the bounds the schema allows', () => {
        // anything a setting could hold: in and out of range, fractions, numeric strings, junk
        const stored = gen.withEdges(
            random => {
                const int = (min, max) => gen.integer(min, max)(random);
                const kind = int(0, 4);
                if (kind === 0) {
                    return int(-1000, 1000);
                }
                if (kind === 1) {
                    return int(0, 10 * MAX_WEBHOOK_RETRY_DELAY);
                }
                if (kind === 2) {
                    return int(-1000, 1000) / 7;
                }
                if (kind === 3) {
                    return String(int(-50, 500));
                }
                return gen.string('abcdefghijklmnopqrstuvwxyz0123456789', 0, 4)(random);
            },
            [null, undefined, Number.MAX_SAFE_INTEGER, -0]
        );
        forAll(
            gen.record({ webhooksDeliveryAttempts: stored, webhooksRetryDelay: stored }),
            values => {
                const { attempts, backoff } = webhookRetryPolicy(values);
                assert.ok(Number.isInteger(attempts) && attempts >= 1 && attempts <= MAX_WEBHOOK_ATTEMPTS, `attempts ${attempts}`);
                assert.ok(
                    Number.isInteger(backoff.delay) && backoff.delay >= MIN_WEBHOOK_RETRY_DELAY && backoff.delay <= MAX_WEBHOOK_RETRY_DELAY,
                    `delay ${backoff.delay}`
                );

                // A value the settings schema accepts is used as it is, never clamped or replaced
                for (const [key, picked] of [
                    ['webhooksDeliveryAttempts', attempts],
                    ['webhooksRetryDelay', backoff.delay]
                ]) {
                    const { error, value } = settingsSchema[key].validate(values[key]);
                    if (!error && typeof value === 'number') {
                        assert.equal(picked, value, `${key} ${values[key]} passes the schema, so it is used as it is`);
                    }
                }
            },
            { seed: 20261021, runs: 2000 }
        );
    });
});
