'use strict';

// BaseClient.queueMessageEntry(), the step that turns a submit request into a queued message:
// default sender, template rendering, list unsubscribe headers, the referenced message of a reply
// or forward, referenced attachments, dry runs and tracking. It had no direct test; only the
// applyReferenceRecipients() helper pulled out of it did. The provider round trips and the queue
// write are stubbed on a BaseClient stand-in, the MIME build is real.

const test = require('node:test');
const assert = require('node:assert').strict;

let unsubscribed = {};
require('./helpers/mock-db').installDbMock({
    redis: {
        hget: async (key, field) => (unsubscribed[`${key}:${field}`] ? JSON.stringify(unsubscribed[`${key}:${field}`]) : null)
    }
});

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];

const { BaseClient } = require('../lib/email-client/base-client');
const { REDIS_PREFIX } = require('../lib/consts');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

const SERVICE_URL = 'https://ee.example.com';

const ACCOUNT_DATA = {
    account: 'acc1',
    name: 'Andris Sender',
    email: 'sender@example.com',
    smtp: { host: 'smtp.example.com', port: 587 }
};

const REFERENCED = {
    id: 'MSG1',
    uid: 12,
    messageId: '<original@example.com>',
    subject: 'Quarterly numbers',
    flags: [],
    threadId: 'T1',
    from: { name: 'Original Author', address: 'author@example.com' },
    to: [{ address: 'sender@example.com' }],
    date: '2026-10-01T10:00:00.000Z',
    headers: { references: ['<older@example.com>'] },
    attachments: [{ id: 'ATT1', filename: 'report.pdf', contentType: 'application/pdf', content: Buffer.from('pdf-bytes').toString('base64') }]
};

function reset() {
    unsubscribed = {};
    for (const key of Object.keys(settingsValues)) {
        delete settingsValues[key];
    }
    Object.assign(settingsValues, { serviceSecret: 'a'.repeat(32), serviceUrl: SERVICE_URL });
}

function createClient(opts) {
    opts = opts || {};
    const queued = [];
    const fetched = [];
    const downloads = [];
    const client = Object.assign(Object.create(BaseClient.prototype), {
        account: 'acc1',
        logger: noopLogger,
        redis: require('../lib/db').redis,
        accountObject: { loadAccountData: async () => Object.assign({}, ACCOUNT_DATA, opts.accountData) },
        checkIMAPConnection: () => true,
        getMessage: async (id, options) => {
            fetched.push({ id, options });
            if (opts.getMessage) {
                return opts.getMessage(id, options);
            }
            return JSON.parse(JSON.stringify(REFERENCED));
        },
        getAttachmentContent: async id => {
            downloads.push(id);
            return opts.attachments && id in opts.attachments ? opts.attachments[id] : Buffer.from(`content-of-${id}`);
        },
        pushMessageToQueue: async params => {
            queued.push(params);
            return { response: 'Queued for delivery', messageId: params.messageId, queueId: 'Q1' };
        }
    });
    return { client, queued, fetched, downloads, run: data => client.queueMessageEntry(data, { source: 'test' }, {}, {}) };
}

// unfolded, so a long header matches on one line
const rawOf = queued => queued[0].raw.toString().replace(/\r\n[ \t]+/g, ' ');

test('queueMessageEntry', async t => {
    t.beforeEach(reset);

    await t.test('sends from the account address, renders the template and derives a text part', async () => {
        const { queued, run } = createClient();
        const result = await run({
            to: [{ address: 'rcpt@example.com' }],
            subject: 'Hello {{params.name}}',
            html: '<p>Welcome, {{params.name}} from {{account.name}}</p>',
            render: { params: { name: 'Juta' } }
        });

        assert.deepStrictEqual(result, { response: 'Queued for delivery', messageId: queued[0].messageId, queueId: 'Q1' });
        assert.strictEqual(queued.length, 1);
        assert.deepStrictEqual(queued[0].meta, { source: 'test' });
        assert.strictEqual(queued[0].subject, 'Hello Juta');

        const raw = rawOf(queued);
        assert.match(raw, /^From: Andris Sender <sender@example\.com>$/m);
        assert.match(raw, /^Subject: Hello Juta$/m);
        assert.match(raw, /Content-Type: text\/plain/);
        assert.match(raw, /Content-Type: text\/plain[\s\S]*Welcome, Juta from Andris Sender[\s\S]*Content-Type: text\/html/);
        assert.deepStrictEqual(queued[0].envelope, { from: 'sender@example.com', to: ['rcpt@example.com'] });
    });

    await t.test('refuses an account that has no way to send', async () => {
        const { queued, run } = createClient({ accountData: { smtp: null } });
        await assert.rejects(
            run({ to: [{ address: 'rcpt@example.com' }], subject: 'x', text: 'x' }),
            err => err.code === 'SMTPUnavailable' && err.statusCode === 404
        );
        assert.strictEqual(queued.length, 0);
    });

    await t.test('a dry run returns the message instead of queueing it', async () => {
        const { queued, run } = createClient();
        const result = await run({ to: [{ address: 'rcpt@example.com' }], subject: 'Dry', text: 'body', dryRun: true });
        assert.strictEqual(queued.length, 0);
        assert.strictEqual(result.response, 'Dry run');
        assert.match(Buffer.from(result.preview, 'base64').toString(), /^Subject: Dry$/m);
    });

    await t.test('list messages', async t => {
        await t.test('skip a recipient who unsubscribed from the list', async () => {
            const { queued, run } = createClient();
            unsubscribed[`${REDIS_PREFIX}lists:unsub:entries:news:rcpt@example.com`] = { reason: 'unsubscribe' };
            const result = await run({ to: [{ address: 'Rcpt@Example.com ' }], listId: 'news', subject: 'x', text: 'x' });
            assert.deepStrictEqual(result, { responseValue: { skipped: { reason: 'unsubscribe', listId: 'news' } } });
            assert.strictEqual(queued.length, 0);
        });

        await t.test('carry List-ID and one-click unsubscribe headers, and a Message-ID on the sender domain', async () => {
            const { queued, run } = createClient();
            await run({ to: [{ address: 'rcpt@example.com' }], listId: 'news', subject: 'News', text: 'Unsubscribe: {{rcpt.unsubscribeUrl}}' });
            const raw = rawOf(queued);
            assert.match(raw, /^List-ID: <news\.ee\.example\.com>$/m);
            assert.match(raw, /^List-Unsubscribe: <https:\/\/ee\.example\.com\/unsubscribe\?/m);
            assert.match(raw, /^List-Unsubscribe-Post: List-Unsubscribe=One-Click$/m);
            assert.match(queued[0].messageId, /@example\.com>$/);
            assert.match(raw, /Unsubscribe: https:\/\/ee\.example\.com\/unsubscribe\?/);
        });

        await t.test('are not list messages for more than one recipient', async () => {
            const { queued, run } = createClient();
            await run({ to: [{ address: 'a@example.com' }, { address: 'b@example.com' }], listId: 'news', subject: 'x', text: 'x' });
            assert.doesNotMatch(rawOf(queued), /List-ID/);
        });
    });

    await t.test('replies', async t => {
        await t.test('thread to the referenced message and address its author', async () => {
            const { queued, fetched, run } = createClient();
            const result = await run({ text: 'Thanks', reference: { message: 'MSG1', action: 'reply' } });

            // only the headers are needed for a plain reply
            assert.strictEqual(fetched[0].id, 'MSG1');
            assert.strictEqual(fetched[0].options.textType, false);
            assert.ok(fetched[0].options.fields.envelope);

            const raw = rawOf(queued);
            assert.match(raw, /^Subject: Re: Quarterly numbers$/m);
            assert.match(raw, /^In-Reply-To: <original@example\.com>$/m);
            assert.match(raw, /^References: <older@example\.com> <original@example\.com>$/m);
            assert.deepStrictEqual(queued[0].envelope.to, ['author@example.com']);

            // no \Answered flag yet, so the delivery sets it; the thread id is carried along
            assert.strictEqual(queued[0].data.reference.update, true);
            assert.strictEqual(queued[0].data.reference.threadId, 'T1');
            assert.deepStrictEqual(result.reference, { message: 'MSG1', success: true, threadId: 'T1' });
        });

        await t.test('do not prefix a subject that already has Re:, and keep a caller-supplied thread id', async () => {
            const { queued, run } = createClient({ getMessage: () => Object.assign({}, REFERENCED, { subject: 'RE: Quarterly', flags: ['\\Answered'] }) });
            await run({ text: 'x', reference: { message: 'MSG1', action: 'reply', threadId: 'MINE' } });
            assert.match(rawOf(queued), /^Subject: RE: Quarterly$/m);
            assert.strictEqual(queued[0].data.reference.update, undefined);
            assert.strictEqual(queued[0].data.reference.threadId, 'MINE');
        });

        await t.test('fail when the referenced message is gone', async () => {
            const notFound = () => {
                throw Object.assign(new Error('Not found'), { statusCode: 404 });
            };
            const { queued, run } = createClient({ getMessage: notFound });
            await assert.rejects(
                run({ text: 'x', to: [{ address: 'r@example.com' }], reference: { message: 'MSG1', action: 'reply' } }),
                err => err.code === 'ReferenceNotFound'
            );
            assert.strictEqual(queued.length, 0);
        });

        await t.test('go out unthreaded with ignoreMissing, and say so', async () => {
            const { queued, run } = createClient({ getMessage: () => null });
            const result = await run({
                text: 'x',
                subject: 'Own',
                to: [{ address: 'r@example.com' }],
                reference: { message: 'MSG1', action: 'reply', ignoreMissing: true }
            });
            assert.doesNotMatch(rawOf(queued), /In-Reply-To/);
            assert.deepStrictEqual(result.reference, { message: 'MSG1', success: false, error: 'Referenced message was not found' });
        });

        await t.test('fail when the referenced message has another Message-ID than expected', async () => {
            const { run } = createClient();
            await assert.rejects(
                run({ text: 'x', reference: { message: 'MSG1', action: 'reply', messageId: '<other@example.com>' } }),
                err => err.code === 'MessageNotFound'
            );
        });

        await t.test('quote the original inline when asked to', async () => {
            const { queued, fetched, run } = createClient({
                getMessage: () => Object.assign({}, REFERENCED, { text: { plain: 'Original text', html: '<p>Original html</p>' } })
            });
            await run({ text: 'My answer', html: '<p>My answer</p>', reference: { message: 'MSG1', action: 'reply', inline: true } });
            assert.strictEqual(fetched[0].options.textType, '*');
            const raw = rawOf(queued);
            assert.match(raw, /Original html/);
            assert.match(raw, /Original text/);
        });
    });

    await t.test('forwards', async t => {
        await t.test('prefix the subject and carry the original attachments', async () => {
            const { queued, downloads, run } = createClient();
            await run({ to: [{ address: 'fwd@example.com' }], text: 'FYI', reference: { message: 'MSG1', action: 'forward', forwardAttachments: true } });
            const raw = rawOf(queued);
            assert.match(raw, /^Subject: Fwd: Quarterly numbers$/m);
            assert.match(raw, /filename=report\.pdf/);
            assert.match(raw, new RegExp(Buffer.from('pdf-bytes').toString('base64')));
            // the cached attachment content was used, nothing downloaded
            assert.deepStrictEqual(downloads, []);
            // a forward is marked $Forwarded as well as \Answered
            assert.strictEqual(queued[0].data.reference.update, true);
        });

        await t.test('download an attachment that has no cached content', async () => {
            const { queued, downloads, run } = createClient({
                getMessage: () => Object.assign({}, REFERENCED, { attachments: [{ id: 'ATT2', filename: 'big.bin', contentType: 'application/octet-stream' }] })
            });
            await run({ to: [{ address: 'fwd@example.com' }], text: 'FYI', reference: { message: 'MSG1', action: 'forward', forwardAttachments: true } });
            assert.deepStrictEqual(downloads, ['ATT2']);
            assert.match(rawOf(queued), /filename=big\.bin/);
        });
    });

    await t.test('attachments referenced by id', async t => {
        await t.test('are downloaded into the message', async () => {
            const { queued, downloads, run } = createClient();
            await run({ to: [{ address: 'r@example.com' }], text: 'x', attachments: [{ filename: 'a.txt', reference: 'ATT9' }] });
            assert.deepStrictEqual(downloads, ['ATT9']);
            assert.match(rawOf(queued), new RegExp(Buffer.from('content-of-ATT9').toString('base64')));
        });

        await t.test('fail the submission when they are gone', async () => {
            const { queued, run } = createClient({ attachments: { ATT9: null } });
            await assert.rejects(
                run({ to: [{ address: 'r@example.com' }], text: 'x', attachments: [{ filename: 'a.txt', reference: 'ATT9' }] }),
                err => err.code === 'ReferenceNotFound'
            );
            assert.strictEqual(queued.length, 0);
        });
    });

    await t.test('tracking', async t => {
        const html = '<p>Read <a href="https://example.org/page">this</a></p>';

        await t.test('is off unless enabled', async () => {
            const { queued, run } = createClient();
            await run({ to: [{ address: 'r@example.com' }], subject: 'x', html });
            assert.doesNotMatch(rawOf(queued), /ee\.example\.com/);
        });

        await t.test('follows trackSentMessages for both opens and clicks', async () => {
            settingsValues.trackSentMessages = true;
            const { queued, run } = createClient();
            await run({ to: [{ address: 'r@example.com' }], subject: 'x', html });
            const raw = rawOf(queued).replace(/[=]\r\n/g, '');
            assert.match(raw, /ee\.example\.com\/open\.gif/);
            assert.match(raw, /ee\.example\.com\/redirect/);
        });

        await t.test('the per-kind settings override trackSentMessages', async () => {
            Object.assign(settingsValues, { trackSentMessages: true, trackClicks: false });
            const { queued, run } = createClient();
            await run({ to: [{ address: 'r@example.com' }], subject: 'x', html });
            const raw = rawOf(queued).replace(/[=]\r\n/g, '');
            assert.match(raw, /open\.gif/);
            assert.doesNotMatch(raw, /ee\.example\.com\/redirect/);
        });

        await t.test('needs a service URL to point at', async () => {
            Object.assign(settingsValues, { trackSentMessages: true, serviceUrl: null });
            const { queued, run } = createClient();
            await run({ to: [{ address: 'r@example.com' }], subject: 'x', html });
            assert.doesNotMatch(rawOf(queued), /open\.gif/);
        });
    });
});
