'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_llm_summary';

const { llmPreProcess, buildSummaryInput, SUMMARY_HEADERS } = require('../lib/llm-pre-process');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX, AI_REQUEST_TIMEOUT } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length > 0) {
        await redis.del(keys);
    }
});

const noopLogger = { info() {}, error() {}, trace() {} };

test('buildSummaryInput', async t => {
    await t.test('passes the decoded fields, every fetched header and the attachment list without content', () => {
        const input = buildSummaryInput({
            subject: 'Täna',
            from: { name: 'Andris', address: 'andris@example.com' },
            date: '2026-10-01T10:00:00.000Z',
            headers: {
                subject: ['=?UTF-8?Q?T=C3=A4na?='],
                'authentication-results': ['mx.example.com; spf=pass', 'relay; spf=none'],
                'in-reply-to': '<parent@example.com>'
            },
            attachments: [{ id: 'a1', filename: 'doc.pdf', contentType: 'application/pdf', content: Buffer.from('x'), encodedSize: 1 }],
            text: { plain: 'Tere', html: '<p>Tere</p>', encodedSize: { plain: 4, html: 11 } }
        });

        assert.deepEqual(input, {
            subject: 'Täna',
            from: { name: 'Andris', address: 'andris@example.com' },
            date: '2026-10-01T10:00:00.000Z',
            headers: [
                { key: 'subject', value: ['=?UTF-8?Q?T=C3=A4na?='] },
                { key: 'authentication-results', value: ['mx.example.com; spf=pass', 'relay; spf=none'] },
                { key: 'in-reply-to', value: ['<parent@example.com>'] }
            ],
            attachments: [{ filename: 'doc.pdf', contentType: 'application/pdf' }],
            text: 'Tere',
            html: '<p>Tere</p>'
        });
    });

    await t.test('copes with a message that has no headers, attachments or text', () => {
        assert.deepEqual(buildSummaryInput({ subject: 'x' }), {
            subject: 'x',
            from: undefined,
            date: undefined,
            headers: [],
            attachments: [],
            text: undefined,
            html: undefined
        });
    });

    await t.test('the always-fetched header set carries the authentication results', () => {
        for (const key of ['authentication-results', 'arc-authentication-results', 'date', 'subject', 'from', 'in-reply-to', 'references']) {
            assert.ok(SUMMARY_HEADERS.includes(key), key);
        }
    });
});

test('summarize', async t => {
    const env = calls => ({
        call: async req => {
            calls.push(req);
            return {
                result: {
                    summary: 'A greeting.',
                    sentiment: 'positive',
                    shouldReply: false,
                    riskAssessment: { risk: 2, assessment: 'Unknown sender.' },
                    language: 'et'
                },
                usage: { id: 'chatcmpl-1', model: 'gpt-6-luna', tokens: 100, promptTokens: 90, completionTokens: 10, time: 12, charactersRemoved: 0 }
            };
        },
        redis: { set: async () => 'OK', del: async () => 1 },
        account: 'acc-1',
        logger: noopLogger
    });

    await t.test('attaches the model output as it came and nothing else', async () => {
        const calls = [];
        const messageData = { id: 'm1', subject: 'Hi', text: { plain: 'Hello' } };

        await llmPreProcess.summarize(messageData, env(calls));

        assert.equal(calls.length, 1);
        assert.equal(calls[0].cmd, 'generateSummary');
        assert.equal(calls[0].timeout, AI_REQUEST_TIMEOUT);
        assert.equal(calls[0].data.account, 'acc-1');
        assert.deepEqual(calls[0].data.message, buildSummaryInput(messageData));

        assert.deepEqual(messageData.summary, {
            summary: 'A greeting.',
            sentiment: 'positive',
            shouldReply: false,
            riskAssessment: { risk: 2, assessment: 'Unknown sender.' },
            language: 'et'
        });
        assert.ok(!('riskAssessment' in messageData), 'the risk assessment is not lifted out of the summary');
        assert.ok(
            !('id' in messageData.summary) && !('tokens' in messageData.summary) && !('model' in messageData.summary),
            'request usage stays out of the payload'
        );
    });

    await t.test('logs the usage with the message', async () => {
        const logged = [];
        const messageData = { id: 'm2', text: { plain: 'Hello' } };
        const testEnv = env([]);
        testEnv.logger = { info: entry => logged.push(entry), error() {}, trace() {} };

        await llmPreProcess.summarize(messageData, testEnv);

        assert.equal(logged.length, 1);
        assert.equal(logged[0].id, 'm2');
        assert.equal(logged[0].usage.tokens, 100);
        assert.equal(logged[0].usage.model, 'gpt-6-luna');
    });

    await t.test('records a failure for the configuration page and leaves the message unenriched', async () => {
        const stored = [];
        const messageData = { id: 'm3', text: { plain: 'Hello' } };
        const testEnv = env([]);
        testEnv.call = async () => {
            throw Object.assign(new Error('Rate limited'), { statusCode: 429, code: 'rate_limit' });
        };
        testEnv.redis = { set: async (key, value) => stored.push({ key, value: JSON.parse(value) }), del: async () => 1 };

        await llmPreProcess.summarize(messageData, testEnv);

        assert.ok(!('summary' in messageData));
        assert.equal(stored.length, 1);
        assert.equal(stored[0].value.message, 'Rate limited');
        assert.equal(stored[0].value.statusCode, 429);
    });
});

test('filter handler', async t => {
    await t.test('an empty filter script passes every message', async () => {
        await settings.set('openAiAPIKey', 'test-key');
        await settings.set('generateEmailSummary', true);
        await settings.set('openAiPreProcessingFn', '');

        assert.equal(await llmPreProcess.run({ account: 'acc-1', subject: 'x' }), true);
    });

    await t.test('a filter script decides', async () => {
        await settings.set('openAiPreProcessingFn', 'return payload.subject === "yes";');

        assert.equal(await llmPreProcess.run({ account: 'acc-1', subject: 'yes' }), true);
        assert.equal(await llmPreProcess.run({ account: 'acc-1', subject: 'no' }), false);
    });

    await t.test('a script that does not compile passes nothing', async () => {
        await settings.set('openAiPreProcessingFn', 'return (;');

        assert.equal(await llmPreProcess.run({ account: 'acc-1', subject: 'yes' }), false);
        const log = await llmPreProcess.getErrorLog();
        assert.ok(log.length >= 1);
        assert.equal(log[0].type, 'filter');
    });

    await t.test('summaries off means no handler', async () => {
        await settings.set('openAiPreProcessingFn', 'return true;');
        await settings.set('generateEmailSummary', false);

        assert.equal(await llmPreProcess.run({ account: 'acc-1', subject: 'yes' }), false);
    });
});
