'use strict';

// BaseClient pieces shared by every backend that the other suites only stub:
//
// - submitMessage() over SMTP (IMAP-2). Everything after transporter.sendMail() used to sit in the
//   same try as the send, so a Redis or queue hiccup while recording the success (the EHLO copy, the
//   messageSent notification, the feedback key) ran the delivery-error path and rethrew: the submit
//   worker retried, and so delivered a second time, a message the server had already accepted.
// - getDelegatedAccount() (IMAP-7) built every hop from the original account, so a valid A->B->C
//   chain reloaded B forever and was reported as a loop.
// - buildReferences() (CONTENT-7): the References header of a reply or forward.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

// base-client destructures getMailTransport at load, so the stub has to be in place first
const sent = [];
let sendError = null;
const smtpPool = require('../lib/email-client/smtp-pool-manager');
smtpPool.getMailTransport = () => ({
    sendMail: async message => {
        if (sendError) {
            throw sendError;
        }
        sent.push(message);
        return { response: '250 Accepted', messageId: message.messageId, ehlo: ['PIPELINING'] };
    }
});

const { SmtpConfigBuilder } = require('../lib/email-client/message-builder');
const { BaseClient, buildReferences, isFailedDelivery } = require('../lib/email-client/base-client');
const { Account } = require('../lib/account');
const { EMAIL_SENT_NOTIFY, EMAIL_DELIVERY_ERROR_NOTIFY } = require('../lib/consts');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

test.mock.method(SmtpConfigBuilder.prototype, 'loadGateway', async () => ({ gatewayData: null, gatewayObject: null }));
test.mock.method(SmtpConfigBuilder.prototype, 'buildConnectionConfig', async () => ({}));
test.mock.method(SmtpConfigBuilder.prototype, 'resolveAuthServer', async () => null);
test.mock.method(SmtpConfigBuilder.prototype, 'buildSmtpSettings', async () => ({ host: 'smtp.example.com', port: 587 }));

function createSubmitClient({ failingNotify = false, failingRedis = false } = {}) {
    const notifications = [];
    const ctx = Object.assign(Object.create(BaseClient.prototype), {
        account: 'test-account',
        logger: noopLogger,
        accountObject: { loadAccountData: async () => ({ account: 'test-account', smtp: { host: 'smtp.example.com' } }) },
        submitQueue: { getJob: async () => ({ updateProgress: async () => {} }) },
        redis: {
            hSetExists: async () => {
                if (failingRedis) {
                    throw new Error('READONLY You can not write against a read only replica');
                }
            },
            hset: async () => 1
        },
        getAccountKey: () => 'iad:test-account',
        uploadToSentFolder: async () => false,
        updateFeedbackKey: async () => {
            if (failingRedis) {
                throw new Error('READONLY You can not write against a read only replica');
            }
        },
        notify: async (mailbox, event, data) => {
            notifications.push(event);
            if (failingNotify && event === EMAIL_SENT_NOTIFY) {
                throw new Error('Queue unavailable');
            }
        }
    });
    return { ctx, notifications };
}

const submission = () => ({
    raw: Buffer.from('Subject: test\r\n\r\nHello\r\n'),
    hasBcc: false,
    envelope: { from: 'sender@example.com', to: ['rcpt@example.com'] },
    messageId: '<test@example.com>',
    queueId: 'queue-1',
    feedbackKey: 'feedback:1',
    job: { id: 'job-1' }
});

test('BaseClient.submitMessage() after the server accepted the message', async t => {
    t.beforeEach(() => {
        sent.length = 0;
        sendError = null;
    });

    await t.test('a failing messageSent notification does not fail the job', async () => {
        const { ctx, notifications } = createSubmitClient({ failingNotify: true });

        const result = await ctx.submitMessage(submission());

        assert.deepEqual(result, { response: '250 Accepted', messageId: '<test@example.com>' });
        assert.equal(sent.length, 1);
        assert.ok(!notifications.includes(EMAIL_DELIVERY_ERROR_NOTIFY), 'a delivered message is not reported as a delivery error');
    });

    await t.test('failing Redis bookkeeping does not fail the job', async () => {
        const { ctx, notifications } = createSubmitClient({ failingRedis: true });

        const result = await ctx.submitMessage(submission());

        assert.equal(result.response, '250 Accepted');
        assert.deepEqual(notifications, [EMAIL_SENT_NOTIFY]);
    });

    await t.test('a failed send is still reported and rethrown', async () => {
        sendError = Object.assign(new Error('Recipient rejected'), { responseCode: 550, code: 'EENVELOPE' });
        const { ctx, notifications } = createSubmitClient();

        await assert.rejects(() => ctx.submitMessage(submission()), /Recipient rejected/);

        assert.deepEqual(notifications, [EMAIL_DELIVERY_ERROR_NOTIFY]);
    });
});

test('BaseClient.getDelegatedAccount()', async t => {
    function withAccounts(records) {
        const loads = [];
        t.mock.method(Account.prototype, 'loadAccountData', async function () {
            loads.push(this.account);
            const record = records[this.account];
            if (!record) {
                throw new Error(`unknown account ${this.account}`);
            }
            return record;
        });
        const ctx = Object.assign(Object.create(BaseClient.prototype), {
            accountObject: { redis: {}, call: async () => {}, secret: null, timeout: 1000 }
        });
        return { ctx, loads };
    }

    const delegating = (account, next) => ({ account, oauth2: { auth: { delegatedUser: `${account}@example.com`, delegatedAccount: next } } });
    const owner = account => ({ account, oauth2: { auth: { user: `${account}@example.com` } } });

    await t.test('follows a chain of more than one hop', async () => {
        const { ctx, loads } = withAccounts({ B: delegating('B', 'C'), C: owner('C') });

        const resolved = await ctx.getDelegatedAccount(delegating('A', 'B'));

        assert.equal(resolved.account, 'C');
        assert.deepEqual(loads, ['B', 'C']);
        t.mock.restoreAll();
    });

    await t.test('detects a real loop', async () => {
        const { ctx } = withAccounts({ B: delegating('B', 'A'), A: delegating('A', 'B') });

        await assert.rejects(() => ctx.getDelegatedAccount(delegating('A', 'B')), /Delegation looping detected/);
        t.mock.restoreAll();
    });

    await t.test('a chain resolving exactly at the hop limit resolves', async () => {
        const records = {};
        for (let i = 1; i < 20; i++) {
            records[`N${i}`] = delegating(`N${i}`, `N${i + 1}`);
        }
        records.N20 = owner('N20');
        const { ctx, loads } = withAccounts(records);

        const resolved = await ctx.getDelegatedAccount(delegating('N0', 'N1'));

        assert.equal(resolved.account, 'N20');
        assert.equal(loads.length, 20);
        t.mock.restoreAll();
    });

    await t.test('a chain longer than the hop limit is refused', async () => {
        const records = {};
        for (let i = 1; i <= 21; i++) {
            records[`N${i}`] = delegating(`N${i}`, `N${i + 1}`);
        }
        records.N22 = owner('N22');
        const { ctx } = withAccounts(records);

        await assert.rejects(() => ctx.getDelegatedAccount(delegating('N0', 'N1')), /Too many delegation hops/);
        t.mock.restoreAll();
    });
});

test('buildReferences()', async t => {
    await t.test("puts the parent's own Message-ID last, after its References", () => {
        const references = buildReferences({
            messageId: '<parent@x>',
            inReplyTo: '<grandparent@x>',
            headers: { references: ['<root@x> <grandparent@x>'] }
        });

        assert.deepEqual(references, ['<root@x>', '<grandparent@x>', '<parent@x>']);
    });

    await t.test('falls back to In-Reply-To when the parent has no References', () => {
        assert.deepEqual(buildReferences({ messageId: '<parent@x>', inReplyTo: '<grandparent@x>' }), ['<grandparent@x>', '<parent@x>']);
    });

    await t.test('a repeated id keeps its last position', () => {
        const references = buildReferences({
            messageId: '<parent@x>',
            headers: { references: ['<root@x> <parent@x> <other@x>'] }
        });

        assert.deepEqual(references, ['<root@x>', '<other@x>', '<parent@x>']);
    });

    await t.test('adds the missing angle brackets', () => {
        assert.deepEqual(buildReferences({ messageId: 'parent@x', headers: { references: 'root@x' } }), ['<root@x>', '<parent@x>']);
    });

    // The dedupe used to unshift() per entry, quadratic in a header the sender controls
    await t.test('a very long References header is processed in linear time', () => {
        const chain = Array.from({ length: 200000 }, (v, i) => `<m${i}@x>`).join(' ');
        const started = process.hrtime.bigint();
        const references = buildReferences({ messageId: '<parent@x>', headers: { references: [chain] } });
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

        assert.equal(references.length, 21);
        assert.equal(references[0], '<m0@x>');
        assert.equal(references.at(-1), '<parent@x>');
        assert.ok(elapsedMs < 3000, `took ${elapsedMs} ms`);
    });

    await t.test('keeps the thread root and the most recent entries of a long chain', () => {
        const chain = Array.from({ length: 50 }, (v, i) => `<m${i}@x>`);
        const references = buildReferences({ messageId: '<parent@x>', headers: { references: [chain.join(' ')] } });

        assert.equal(references.length, 21);
        assert.equal(references[0], '<m0@x>', 'the root');
        assert.equal(references.at(-1), '<parent@x>', 'the direct parent last');
        assert.equal(references.at(-2), '<m49@x>');
    });

    await t.test('a message with no ids yields nothing', () => {
        assert.deepEqual(buildReferences({}), []);
    });
});

test('isFailedDelivery()', () => {
    const bounce = action => ({ action, recipient: 'user@example.com', messageId: '<m@x>' });

    assert.equal(isFailedDelivery(bounce('failed')), true);
    assert.equal(isFailedDelivery(bounce('Failed ')), true);
    for (const action of ['delayed', 'delivered', 'relayed', 'expanded', undefined]) {
        assert.equal(isFailedDelivery(bounce(action)), false, String(action));
    }
    assert.equal(isFailedDelivery({ action: 'failed', recipient: 'user@example.com' }), false, 'needs the original message id');
    assert.equal(isFailedDelivery(null), false);
});
