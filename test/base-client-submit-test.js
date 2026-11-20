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

// sendWithDeadline() reaches the transport through the module export, so the stub is in place for it
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
const { BaseClient, buildReferences, needsReferenceFlagUpdate } = require('../lib/email-client/base-client');
const { isFailedDelivery } = require('../lib/email-client/new-message-steps');
const { Account } = require('../lib/account');
const { EMAIL_SENT_NOTIFY, EMAIL_DELIVERY_ERROR_NOTIFY } = require('../lib/consts');
const { submitPenaltyKey, SUBMIT_PENALTY_MS } = require('../lib/submit-penalty');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

// a test that sends through a gateway sets this
let gatewayStub = null;
test.mock.method(SmtpConfigBuilder.prototype, 'loadGateway', async () => gatewayStub || { gatewayData: null, gatewayObject: null });
test.mock.method(SmtpConfigBuilder.prototype, 'buildConnectionConfig', async () => ({}));
test.mock.method(SmtpConfigBuilder.prototype, 'resolveAuthServer', async () => null);
test.mock.method(SmtpConfigBuilder.prototype, 'buildSmtpSettings', async () => ({ host: 'smtp.example.com', port: 587 }));

function createSubmitClient({ failingNotify = false, failingRedis = false } = {}) {
    const notifications = [];
    const penalties = [];
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
            hset: async () => 1,
            set: async (...args) => {
                penalties.push(args);
                return 'OK';
            }
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
    return { ctx, notifications, penalties };
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

    // The job's nextAttempt is set before the send, so a failure the worker will not retry used to
    // report a retry time in messageDeliveryError and never mark the feedback key failed
    await t.test('a permanent failure reports no next attempt and fails the feedback key', async () => {
        for (const [error, permanent] of [
            [Object.assign(new Error('Mailbox unavailable'), { responseCode: 550 }), true],
            [Object.assign(new Error('SMTP delivery did not complete'), { code: 'ETIMEDOUT', permanent: true }), true],
            [Object.assign(new Error('Try again later'), { responseCode: 451 }), false]
        ]) {
            sendError = error;
            const feedback = [];
            const payloads = [];
            const { ctx } = createSubmitClient();
            ctx.updateFeedbackKey = async (key, success) => feedback.push(success);
            ctx.notify = async (mailbox, event, data) => payloads.push(data);
            const job = { id: 'job-1', nextAttempt: '2026-11-07T12:00:00.000Z' };

            await assert.rejects(() => ctx.submitMessage(Object.assign(submission(), { job })));

            assert.deepEqual(feedback, permanent ? [false] : [], error.message);
            assert.equal(Boolean(payloads[0].job.nextAttempt), !permanent, error.message);
            assert.equal(job.nextAttempt, '2026-11-07T12:00:00.000Z', "the caller's job data is not changed");
        }
    });
});

test('BaseClient.submitMessage() around the send', async t => {
    t.beforeEach(() => {
        sent.length = 0;
        sendError = null;
        gatewayStub = null;
    });

    await t.test('a missing job resolves false without sending', async () => {
        const { ctx, notifications } = createSubmitClient();
        ctx.submitQueue = { getJob: async () => null };

        assert.equal(await ctx.submitMessage(submission()), false);
        assert.equal(sent.length, 0);
        assert.deepEqual(notifications, []);
    });

    await t.test('a send that ran into the deadline penalises the account', async () => {
        sendError = Object.assign(new Error('SMTP delivery did not complete within 300 seconds'), {
            code: 'ETIMEDOUT',
            deadlineExceeded: true,
            permanent: true
        });
        const { ctx, penalties } = createSubmitClient();

        await assert.rejects(() => ctx.submitMessage(submission()), /did not complete/);
        assert.deepEqual(penalties, [[submitPenaltyKey('test-account'), '1', 'PX', SUBMIT_PENALTY_MS]]);
    });

    await t.test('any other send failure does not', async () => {
        sendError = Object.assign(new Error('Connection refused'), { code: 'ECONNECTION' });
        const { ctx, penalties } = createSubmitClient();

        await assert.rejects(() => ctx.submitMessage(submission()), /Connection refused/);
        assert.deepEqual(penalties, []);
    });

    // A throw from any step after the server accepted the message would make the submit worker
    // retry, and so deliver the message a second time
    await t.test('every step after the send keeps its own failure', async t => {
        const boom = () => {
            throw new Error('step failed');
        };
        const rejecting = async () => boom();
        const steps = {
            'the EHLO copy and the SMTP status': ctx => {
                ctx.redis.hSetExists = rejecting;
            },
            'the job progress': ctx => {
                ctx.submitQueue = { getJob: async () => ({ updateProgress: rejecting }) };
            },
            'the messageSent notification': ctx => {
                ctx.notify = rejecting;
            },
            'the sent copy': ctx => {
                // only an account with IMAP gets a copy in its Sent Mail folder
                ctx.accountObject = {
                    loadAccountData: async () => ({ account: 'test-account', smtp: { host: 'smtp.example.com' }, imap: { host: 'imap.example.com' } })
                };
                delete ctx.uploadToSentFolder;
                ctx.checkIMAPConnection = boom;
            },
            'the draft cleanup': ctx => {
                ctx.deleteMessage = rejecting;
            },
            'the reference flags': ctx => {
                ctx.checkIMAPConnection = () => true;
                ctx.updateMessage = rejecting;
            },
            'the feedback key': ctx => {
                ctx.updateFeedbackKey = rejecting;
            },
            'the gateway stats': () => {
                gatewayStub = { gatewayData: { gateway: 'gw1' }, gatewayObject: { gateway: 'gw1', update: rejecting } };
            }
        };
        const message = () => Object.assign(submission(), { draft: { message: 'DRAFT1' }, reference: { message: 'REF1', update: true, action: 'reply' } });

        for (const [name, breakStep] of Object.entries(steps)) {
            await t.test(name, async () => {
                sent.length = 0;
                gatewayStub = null;
                const { ctx } = createSubmitClient();
                ctx.deleteMessage = async () => true;
                ctx.updateMessage = async () => true;
                breakStep(ctx);

                const result = await ctx.submitMessage(message());

                assert.deepEqual(result, { response: '250 Accepted', messageId: '<test@example.com>' });
                assert.equal(sent.length, 1);
            });
        }

        await t.test('all of them at once', async () => {
            sent.length = 0;
            gatewayStub = null;
            const { ctx } = createSubmitClient();
            for (const breakStep of Object.values(steps)) {
                breakStep(ctx);
            }

            const result = await ctx.submitMessage(message());

            assert.deepEqual(result, { response: '250 Accepted', messageId: '<test@example.com>' });
            assert.equal(sent.length, 1);
        });
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

// applyInlineReference() quoted the original into the text part only when the new text was
// non-empty, so a forward sent with no note of its own went out with an html part alone
test.describe('applyInlineReference', () => {
    const referencedMessage = {
        from: { name: 'Sender', address: 'sender@example.com' },
        to: [{ address: 'rcpt@example.com' }],
        subject: 'Original',
        date: '2026-11-19T10:00:00.000Z',
        text: { plain: 'The original body.', html: '<p>The original body.</p>' },
        attachments: []
    };
    const apply = data => BaseClient.prototype.applyInlineReference.call({ logger: noopLogger }, data, referencedMessage, { locale: 'en', tz: 'UTC' });

    test('an empty text still gets the quoted original', () => {
        const data = { text: '', reference: { action: 'forward', inline: true } };
        apply(data);
        assert.match(data.text, /Begin forwarded message/);
        assert.match(data.text, /The original body\./);
        assert.match(data.html, /The original body\./);
    });

    test('the new text comes before the quote', () => {
        const data = { text: 'My answer', reference: { action: 'reply', inline: true } };
        apply(data);
        assert.ok(data.text.startsWith('My answer'));
        assert.match(data.text, /> The original body\./);
    });

    test('a message given only html gets its text part from that html', () => {
        // the draft upload path has no html-to-text step of its own before this
        for (const text of [undefined, '']) {
            const data = { html: '<p>Only html</p>', text, reference: { action: 'reply', inline: true } };
            apply(data);
            assert.ok(data.text.startsWith('Only html'), data.text);
            assert.match(data.text, /> The original body\./);
            assert.match(data.html, /Only html/);
        }
    });

    test('an original with a text part alone is quoted into the html the caller writes', () => {
        const plainOriginal = { ...referencedMessage, text: { plain: 'Plain <original> body.' } };
        for (const action of ['reply', 'forward']) {
            const data = { text: 'My answer', html: '<p>My <b>answer</b></p>', reference: { action, inline: true } };
            BaseClient.prototype.applyInlineReference.call({ logger: noopLogger }, data, plainOriginal, { locale: 'en', tz: 'UTC' });
            assert.match(data.html, /My <b>answer<\/b>/, action);
            assert.match(data.html, /<blockquote/, action);
            // the text is escaped on its way into the html
            assert.match(data.html, /Plain &lt;original&gt; body\./, action);
            assert.match(data.text, /Plain <original> body\./, action);
        }
    });

    test('a text-only answer to a text-only original gets no html part', () => {
        const data = { text: 'Plain answer', reference: { action: 'reply', inline: true } };
        BaseClient.prototype.applyInlineReference.call(
            { logger: noopLogger },
            data,
            { ...referencedMessage, text: { plain: 'Plain original.' } },
            { locale: 'en', tz: 'UTC' }
        );
        assert.equal(data.html, undefined);
        assert.match(data.text, /> Plain original\./);
    });

    test('an original without a plain text part is still quoted', () => {
        const data = { text: 'Note', reference: { action: 'forward', inline: true } };
        BaseClient.prototype.applyInlineReference.call(
            { logger: noopLogger },
            data,
            { ...referencedMessage, text: { html: '<p>Html only original</p>' } },
            { locale: 'en', tz: 'UTC' }
        );
        assert.ok(data.text.startsWith('Note'));
        assert.match(data.html, /Html only original/);
    });
});

test('reference flags', async t => {
    await t.test('a reply sets \\Answered and a forward only $Forwarded, each once', () => {
        assert.equal(needsReferenceFlagUpdate('reply', []), true);
        assert.equal(needsReferenceFlagUpdate('reply-all', undefined), true);
        assert.equal(needsReferenceFlagUpdate('reply', ['\\Seen', '\\Answered']), false);
        assert.equal(needsReferenceFlagUpdate('forward', ['\\Seen']), true);
        assert.equal(needsReferenceFlagUpdate('forward', ['$Forwarded']), false);
        // an answered message forwarded later is still marked forwarded, a forwarded one replied to is still answered
        assert.equal(needsReferenceFlagUpdate('forward', ['\\Answered']), true);
        assert.equal(needsReferenceFlagUpdate('reply', ['$Forwarded']), true);
    });

    for (const [action, flag] of [
        ['reply', '\\Answered'],
        ['reply-all', '\\Answered'],
        ['forward', '$Forwarded']
    ]) {
        await t.test(`delivering a ${action} adds ${flag} alone`, async () => {
            const { ctx } = createSubmitClient();
            const updates = [];
            ctx.checkIMAPConnection = () => true;
            ctx.updateMessage = async (id, changes) => updates.push({ id, changes });

            await ctx.updateReferenceFlags({ message: 'REF1', action }, 'q1', '<m@example.com>', {});

            assert.deepEqual(updates, [{ id: 'REF1', changes: { flags: { add: [flag] } } }]);
        });
    }
});
