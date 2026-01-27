'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const Joi = require('joi');

// Reconstruct a minimal version of the batch submit validation schema
// to test Joi validation rules independently of the running server
const MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024;

const addressSchema = Joi.object({
    name: Joi.string().max(256),
    address: Joi.string().email().required()
});

const batchMessageSchema = Joi.object({
    from: Joi.object({
        name: Joi.string().max(256),
        address: Joi.string().email().required()
    }),

    to: Joi.array().items(addressSchema).single(),

    cc: Joi.array().items(addressSchema).single(),

    bcc: Joi.array().items(addressSchema).single(),

    subject: Joi.string().max(10240),
    text: Joi.string().max(5 * 1024 * 1024),
    html: Joi.string().max(5 * 1024 * 1024),

    raw: Joi.string().base64().max(MAX_ATTACHMENT_SIZE),

    attachments: Joi.array().items(
        Joi.object({
            filename: Joi.string().max(256),
            content: Joi.string().base64().max(MAX_ATTACHMENT_SIZE).required(),
            contentType: Joi.string().lowercase().max(256),
            encoding: Joi.string().valid('base64').default('base64')
        })
    ),

    messageId: Joi.string().max(996),
    headers: Joi.object().unknown(),

    sendAt: Joi.date().iso(),
    deliveryAttempts: Joi.number().integer(),
    gateway: Joi.string().max(256)
})
    .oxor('raw', 'html')
    .oxor('raw', 'text')
    .oxor('raw', 'attachments');

const batchPayloadSchema = Joi.object({
    messages: Joi.array().items(batchMessageSchema).min(1).max(50).required()
});

// Simulate the batch handler logic
async function simulateBatchHandler(messages, queueMessageFn) {
    let results = await Promise.allSettled(
        messages.map(async (msg, index) => {
            let response = await queueMessageFn(msg, index);
            return { index, response };
        })
    );

    let successCount = 0;
    let failureCount = 0;
    let entries = [];

    for (let i = 0; i < results.length; i++) {
        let result = results[i];
        if (result.status === 'fulfilled') {
            successCount++;
            entries.push({
                index: result.value.index,
                success: true,
                queueId: result.value.response.queueId || null,
                messageId: result.value.response.messageId || null,
                sendAt: result.value.response.sendAt || null
            });
        } else {
            failureCount++;
            let err = result.reason;
            entries.push({
                index: i,
                success: false,
                error: {
                    message: err.message,
                    code: err.code || null
                }
            });
        }
    }

    return {
        totalMessages: messages.length,
        successCount,
        failureCount,
        results: entries
    };
}

test('Batch submit validation tests', async t => {
    await t.test('accepts a valid batch payload', async () => {
        let payload = {
            messages: [
                {
                    to: [{ address: 'recipient@example.com' }],
                    subject: 'Test 1',
                    text: 'Hello 1'
                },
                {
                    to: [{ address: 'another@example.com' }],
                    subject: 'Test 2',
                    html: '<p>Hello 2</p>'
                }
            ]
        };

        let result = batchPayloadSchema.validate(payload);
        assert.strictEqual(result.error, undefined, 'Should accept valid batch payload');
        assert.strictEqual(result.value.messages.length, 2);
    });

    await t.test('rejects empty messages array', async () => {
        let payload = {
            messages: []
        };

        let result = batchPayloadSchema.validate(payload);
        assert.ok(result.error, 'Should reject empty messages array');
        assert.ok(result.error.message.includes('at least'), 'Error should mention minimum');
    });

    await t.test('rejects batch exceeding max size of 50', async () => {
        let messages = [];
        for (let i = 0; i < 51; i++) {
            messages.push({
                to: [{ address: `recipient${i}@example.com` }],
                subject: `Test ${i}`,
                text: `Hello ${i}`
            });
        }

        let result = batchPayloadSchema.validate({ messages });
        assert.ok(result.error, 'Should reject batch exceeding 50 messages');
        assert.ok(result.error.message.includes('50') || result.error.message.includes('less'), 'Error should mention the limit');
    });

    await t.test('rejects message with both raw and html', async () => {
        let payload = {
            messages: [
                {
                    to: [{ address: 'recipient@example.com' }],
                    raw: 'dGVzdA==',
                    html: '<p>conflict</p>'
                }
            ]
        };

        let result = batchPayloadSchema.validate(payload);
        assert.ok(result.error, 'Should reject message with both raw and html');
    });

    await t.test('rejects missing messages field', async () => {
        let result = batchPayloadSchema.validate({});
        assert.ok(result.error, 'Should reject missing messages field');
    });

    await t.test('accepts batch at exactly max size of 50', async () => {
        let messages = [];
        for (let i = 0; i < 50; i++) {
            messages.push({
                to: [{ address: `recipient${i}@example.com` }],
                subject: `Test ${i}`,
                text: `Hello ${i}`
            });
        }

        let result = batchPayloadSchema.validate({ messages });
        assert.strictEqual(result.error, undefined, 'Should accept exactly 50 messages');
    });
});

test('Batch submit handler tests', async t => {
    await t.test('all messages succeed', async () => {
        let messages = [
            { to: [{ address: 'a@example.com' }], subject: 'A', text: 'A' },
            { to: [{ address: 'b@example.com' }], subject: 'B', text: 'B' },
            { to: [{ address: 'c@example.com' }], subject: 'C', text: 'C' }
        ];

        let response = await simulateBatchHandler(messages, async (msg, index) => ({
            queueId: `queue-${index}`,
            messageId: `<msg-${index}@example.com>`,
            sendAt: '2021-07-08T07:06:34.336Z'
        }));

        assert.strictEqual(response.totalMessages, 3);
        assert.strictEqual(response.successCount, 3);
        assert.strictEqual(response.failureCount, 0);
        assert.strictEqual(response.results.length, 3);

        for (let i = 0; i < 3; i++) {
            assert.strictEqual(response.results[i].index, i);
            assert.strictEqual(response.results[i].success, true);
            assert.strictEqual(response.results[i].queueId, `queue-${i}`);
            assert.strictEqual(response.results[i].messageId, `<msg-${i}@example.com>`);
        }
    });

    await t.test('partial failure - mix of success and error', async () => {
        let messages = [
            { to: [{ address: 'a@example.com' }], subject: 'A', text: 'A' },
            { to: [{ address: 'invalid' }], subject: 'B', text: 'B' },
            { to: [{ address: 'c@example.com' }], subject: 'C', text: 'C' }
        ];

        let response = await simulateBatchHandler(messages, async (msg, index) => {
            if (index === 1) {
                let err = new Error('Invalid recipient');
                err.code = 'InputValidationError';
                throw err;
            }
            return {
                queueId: `queue-${index}`,
                messageId: `<msg-${index}@example.com>`
            };
        });

        assert.strictEqual(response.totalMessages, 3);
        assert.strictEqual(response.successCount, 2);
        assert.strictEqual(response.failureCount, 1);
        assert.strictEqual(response.results.length, 3);

        // First message succeeds
        assert.strictEqual(response.results[0].success, true);
        assert.strictEqual(response.results[0].queueId, 'queue-0');

        // Second message fails
        assert.strictEqual(response.results[1].success, false);
        assert.strictEqual(response.results[1].error.message, 'Invalid recipient');
        assert.strictEqual(response.results[1].error.code, 'InputValidationError');

        // Third message succeeds
        assert.strictEqual(response.results[2].success, true);
        assert.strictEqual(response.results[2].queueId, 'queue-2');
    });

    await t.test('all messages fail', async () => {
        let messages = [
            { to: [{ address: 'a@example.com' }], subject: 'A', text: 'A' },
            { to: [{ address: 'b@example.com' }], subject: 'B', text: 'B' }
        ];

        let response = await simulateBatchHandler(messages, async () => {
            let err = new Error('Service unavailable');
            err.code = 'WorkerNotAvailable';
            throw err;
        });

        assert.strictEqual(response.totalMessages, 2);
        assert.strictEqual(response.successCount, 0);
        assert.strictEqual(response.failureCount, 2);

        for (let result of response.results) {
            assert.strictEqual(result.success, false);
            assert.strictEqual(result.error.code, 'WorkerNotAvailable');
        }
    });

    await t.test('handles messages with no queueId or messageId gracefully', async () => {
        let messages = [{ to: [{ address: 'a@example.com' }], subject: 'A', text: 'A' }];

        let response = await simulateBatchHandler(messages, async () => ({
            response: 'Queued for delivery'
        }));

        assert.strictEqual(response.successCount, 1);
        assert.strictEqual(response.results[0].success, true);
        assert.strictEqual(response.results[0].queueId, null);
        assert.strictEqual(response.results[0].messageId, null);
    });

    await t.test('handles errors without code property', async () => {
        let messages = [{ to: [{ address: 'a@example.com' }], subject: 'A', text: 'A' }];

        let response = await simulateBatchHandler(messages, async () => {
            throw new Error('Something went wrong');
        });

        assert.strictEqual(response.failureCount, 1);
        assert.strictEqual(response.results[0].success, false);
        assert.strictEqual(response.results[0].error.message, 'Something went wrong');
        assert.strictEqual(response.results[0].error.code, null);
    });
});
