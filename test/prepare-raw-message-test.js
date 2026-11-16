'use strict';

// BaseClient.prepareRawMessage(), the step that builds the MIME source of a message that is uploaded
// to a folder (IMAP APPEND, Gmail insert, Graph draft creation) rather than queued for delivery. Every
// other test stubs it. Here the real method runs against stubbed collaborators (account data, the
// OAuth2 app lookup, the referenced message and attachment downloads) and the MIME build is real.
// It shares the reference handling with queueMessageEntry() but differs from it in three ways that
// are pinned below: it refuses reference actions on a send-only account, defaults the sender only for
// a reference action (and without the _default marker), and never marks the referenced message for a
// flag update or copies its thread id.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];

const { BaseClient } = require('../lib/email-client/base-client');
const { noopLogger } = require('./helpers/auth-failure');

const ACCOUNT_DATA = {
    account: 'acc1',
    name: 'Andris Sender',
    email: 'sender@example.com',
    imap: { host: 'imap.example.com', port: 993 },
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

function createClient(opts) {
    opts = opts || {};
    const calls = [];
    const client = Object.assign(Object.create(BaseClient.prototype), {
        account: 'acc1',
        logger: noopLogger,
        accountObject: {
            loadAccountData: async () => Object.assign({}, ACCOUNT_DATA, opts.accountData),
            getOauth2App: async () => {
                calls.push(['getOauth2App']);
                if (opts.oauth2AppError) {
                    throw opts.oauth2AppError;
                }
                return opts.oauth2App || null;
            },
            isSendOnlyAccount: (accountData, app) => {
                calls.push(['isSendOnlyAccount', app]);
                return !!opts.sendOnly;
            }
        },
        checkIMAPConnection: connectionOptions => {
            calls.push(['checkIMAPConnection', connectionOptions]);
            return true;
        },
        getMessage: async (id, options, connectionOptions) => {
            calls.push(['getMessage', id, options, connectionOptions]);
            if (opts.getMessage) {
                return opts.getMessage(id, options);
            }
            return JSON.parse(JSON.stringify(REFERENCED));
        },
        getAttachmentContent: async (id, options, connectionOptions) => {
            calls.push(['getAttachmentContent', id, options, connectionOptions]);
            return opts.attachments && id in opts.attachments ? opts.attachments[id] : Buffer.from(`content-of-${id}`);
        }
    });
    return { client, calls };
}

// The generated values (Message-ID, Date, MIME boundaries) replaced with fixed tokens, headers unfolded
function normalizeMime(raw) {
    let text = raw.toString();
    const boundaries = new Set();
    text.replace(/boundary="?([^";\r\n]+)"?/g, (m, boundary) => boundaries.add(boundary));
    let i = 0;
    for (const boundary of boundaries) {
        text = text.split(boundary).join(`BOUNDARY${++i}`);
    }
    return text
        .replace(/\r\n[ \t]+/g, ' ')
        .replace(/^Message-ID: <[^>]+>$/m, 'Message-ID: <MESSAGE-ID>')
        .replace(/^Date: .+$/m, 'Date: DATE');
}

const CONNECTION = { connectionClient: 'C' };

test('prepareRawMessage', async t => {
    t.beforeEach(() => {
        for (const key of Object.keys(settingsValues)) {
            delete settingsValues[key];
        }
    });

    await t.test('builds a reply to the referenced message and returns it', async () => {
        const { client, calls } = createClient();
        const data = { text: 'Thanks', reference: { message: 'MSG1', action: 'reply' } };
        const result = await client.prepareRawMessage(data, null, CONNECTION);

        assert.deepStrictEqual(Object.keys(result), ['raw', 'emailObject', 'messageId', 'referencedMessage']);
        assert.strictEqual(result.emailObject, undefined);
        assert.match(result.messageId, /^<[^>]+@example\.com>$/);
        assert.deepStrictEqual(result.referencedMessage, REFERENCED);

        assert.strictEqual(
            normalizeMime(result.raw),
            [
                'References: <older@example.com> <original@example.com>',
                'In-Reply-To: <original@example.com>',
                'From: Andris Sender <sender@example.com>',
                'To: Original Author <author@example.com>',
                'Subject: Re: Quarterly numbers',
                'Message-ID: <MESSAGE-ID>',
                'Content-Transfer-Encoding: 7bit',
                'Date: DATE',
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=utf-8',
                '',
                'Thanks',
                ''
            ].join('\r\n')
        );

        // the plain reply fetched only the headers, and nothing checked the connection up front
        assert.deepStrictEqual(calls, [
            ['isSendOnlyAccount', undefined],
            ['getMessage', 'MSG1', { fields: { uid: true, flags: true, envelope: true, headers: ['references'] }, textType: false }, CONNECTION]
        ]);

        // unlike a queued message, the upload neither marks the original for a flag update nor copies its thread
        assert.deepStrictEqual(data.reference, { message: 'MSG1', action: 'reply' });
        // the sender defaulted for a reference action carries no _default marker
        assert.deepStrictEqual(data.from, { name: 'Andris Sender', address: 'sender@example.com' });
    });

    await t.test('returns the composer options as an object when asked to', async () => {
        const { client } = createClient();
        const result = await client.prepareRawMessage(
            { from: { address: 'own@example.com' }, to: [{ address: 'r@example.com' }], subject: 'Obj', text: 'x', messageId: '<fixed@example.com>' },
            { returnObject: true }
        );
        assert.strictEqual(result.raw, undefined);
        assert.strictEqual(result.messageId, '<fixed@example.com>');
        assert.strictEqual(result.referencedMessage, undefined);
        const emailObject = Object.assign({}, result.emailObject, { baseBoundary: 'B' });
        assert.deepStrictEqual(emailObject, {
            date: undefined,
            disableUrlAccess: true,
            disableFileAccess: true,
            newline: '\r\n',
            boundaryPrefix: emailObject.boundaryPrefix,
            baseBoundary: 'B',
            from: { address: 'own@example.com' },
            to: [{ address: 'r@example.com' }],
            subject: 'Obj',
            text: 'x',
            messageId: '<fixed@example.com>',
            headers: {},
            html: null,
            sendAt: null,
            deliveryAttempts: null,
            gateway: null,
            trackingEnabled: null,
            trackClicks: null,
            trackOpens: null,
            previewText: null
        });
        assert.ok(emailObject.boundaryPrefix);
    });

    await t.test('the sender', async t => {
        await t.test('is not defaulted without a reference action', async () => {
            const { client } = createClient();
            const data = { to: [{ address: 'r@example.com' }], subject: 'Draft', text: 'x' };
            const result = await client.prepareRawMessage(data);
            assert.strictEqual(data.from, undefined);
            assert.doesNotMatch(result.raw.toString(), /^From:/m);
        });

        await t.test('is not defaulted for a reference without an action', async () => {
            const { client } = createClient();
            const data = { to: [{ address: 'r@example.com' }], text: 'x', reference: { message: 'MSG1' } };
            await client.prepareRawMessage(data);
            assert.strictEqual(data.from, undefined);
        });

        await t.test('a caller-supplied sender is kept', async () => {
            const { client } = createClient();
            const data = { from: { address: 'own@example.com' }, text: 'x', reference: { message: 'MSG1', action: 'reply' } };
            await client.prepareRawMessage(data);
            assert.deepStrictEqual(data.from, { address: 'own@example.com' });
        });
    });

    await t.test('send-only accounts', async t => {
        await t.test('refuse a reference action', async () => {
            const { client, calls } = createClient({ sendOnly: true, accountData: { oauth2: { provider: 'gmail' } }, oauth2App: { id: 'app' } });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply' } }), err => {
                assert.strictEqual(err.message, 'Reference actions (reply, forward) are not supported for send-only accounts');
                assert.strictEqual(err.code, 'ReferenceNotSupported');
                assert.strictEqual(err.statusCode, 400);
                return true;
            });
            assert.deepStrictEqual(calls, [['getOauth2App'], ['isSendOnlyAccount', { id: 'app' }]]);
        });

        await t.test('an app that cannot be loaded is ignored', async () => {
            const { client, calls } = createClient({ sendOnly: true, accountData: { oauth2: { provider: 'gmail' } }, oauth2AppError: new Error('gone') });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'forward' } }), { code: 'ReferenceNotSupported' });
            assert.deepStrictEqual(calls, [['getOauth2App'], ['isSendOnlyAccount', undefined]]);
        });

        await t.test('no app lookup for an account without OAuth2', async () => {
            const { client, calls } = createClient({ sendOnly: true });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply' } }), { code: 'ReferenceNotSupported' });
            assert.deepStrictEqual(calls, [['isSendOnlyAccount', undefined]]);
        });

        await t.test('may still upload a message with a reference but no action', async () => {
            const { client, calls } = createClient({ sendOnly: true });
            await client.prepareRawMessage({ to: [{ address: 'r@example.com' }], text: 'x', reference: { message: 'MSG1' } });
            assert.strictEqual(calls[0][0], 'getMessage');
        });
    });

    await t.test('reference failures', async t => {
        await t.test('a missing message is ReferenceNotFound', async () => {
            const { client } = createClient({ getMessage: () => null });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply' } }), {
                message: 'Referenced message was not found',
                code: 'ReferenceNotFound',
                statusCode: 404
            });
        });

        await t.test('a permanent 404 is ReferenceNotFound', async () => {
            const { client } = createClient({
                getMessage: () => {
                    throw Object.assign(new Error('Nope'), { statusCode: 404 });
                }
            });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply' } }), {
                message: 'Referenced message was not found',
                code: 'ReferenceNotFound',
                statusCode: 404
            });
        });

        await t.test('any other permanent error is thrown as is', async () => {
            const failure = Object.assign(new Error('Forbidden'), { statusCode: 403 });
            const { client } = createClient({
                getMessage: () => {
                    throw failure;
                }
            });
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply' } }), err => err === failure);
        });

        await t.test('ignoreMissing uploads without threading', async () => {
            const { client } = createClient({ getMessage: () => null });
            const data = {
                from: { address: 'own@example.com' },
                subject: 'Own',
                text: 'x',
                reference: { message: 'MSG1', action: 'reply', ignoreMissing: true }
            };
            const result = await client.prepareRawMessage(data);
            assert.strictEqual(result.referencedMessage, null);
            assert.doesNotMatch(result.raw.toString(), /In-Reply-To|References/);
        });

        await t.test('a Message-ID mismatch is MessageNotFound', async () => {
            const { client } = createClient();
            await assert.rejects(client.prepareRawMessage({ text: 'x', reference: { message: 'MSG1', action: 'reply', messageId: '<other@example.com>' } }), {
                message: 'The referenced message was found, but its Message-ID does not match the expected value',
                code: 'MessageNotFound',
                statusCode: 404
            });
        });
    });

    await t.test('attachments', async t => {
        await t.test('a forward carries the cached attachments and checks the connection before using them', async () => {
            const { client, calls } = createClient();
            const data = { to: [{ address: 'fwd@example.com' }], text: 'FYI', reference: { message: 'MSG1', action: 'forward', forwardAttachments: true } };
            const result = await client.prepareRawMessage(data, null, CONNECTION);
            assert.deepStrictEqual(
                calls.map(call => call[0]),
                ['isSendOnlyAccount', 'getMessage', 'checkIMAPConnection']
            );
            assert.strictEqual(calls[1][2].textType, '*');
            assert.strictEqual(calls[1][2].fields, false);
            const raw = normalizeMime(result.raw);
            assert.match(raw, /^Subject: Fwd: Quarterly numbers$/m);
            assert.match(
                raw,
                /Content-Type: application\/pdf; name=report\.pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=report\.pdf/
            );
            assert.ok(raw.includes(Buffer.from('pdf-bytes').toString('base64')));
            assert.deepStrictEqual(
                data.attachments.map(a => Object.assign({}, a, { content: a.content.toString() })),
                [{ filename: 'report.pdf', content: 'pdf-bytes', contentType: 'application/pdf', contentDisposition: 'attachment', cid: null }]
            );
        });

        await t.test('an inline reply downloads the images its HTML references', async () => {
            const { client, calls } = createClient({
                getMessage: () =>
                    Object.assign({}, REFERENCED, {
                        text: { plain: 'Original', html: '<p>Original <img src="cid:logo@x"></p>' },
                        attachments: [
                            { id: 'IMG1', filename: 'logo.png', contentType: 'image/png', contentId: '<logo@x>', inline: true },
                            { id: 'ATT2', filename: 'other.pdf', contentType: 'application/pdf' }
                        ]
                    })
            });
            const data = { html: '<p>Answer</p>', reference: { message: 'MSG1', action: 'reply', inline: true } };
            await client.prepareRawMessage(data, null, CONNECTION);
            assert.deepStrictEqual(calls.slice(2), [
                ['checkIMAPConnection', CONNECTION],
                ['getAttachmentContent', 'IMG1', { chunkSize: calls[3][2].chunkSize, contentOnly: true }, CONNECTION]
            ]);
            assert.ok(calls[3][2].chunkSize >= 2 * 1024 * 1024);
            assert.deepStrictEqual(
                data.attachments.map(a => Object.assign({}, a, { content: a.content.toString() })),
                [{ filename: 'logo.png', content: 'content-of-IMG1', contentType: 'image/png', contentDisposition: 'inline', cid: '<logo@x>' }]
            );
            assert.match(data.html, /Answer/);
            assert.match(data.html, /Original/);
        });

        await t.test('a referenced attachment that downloads empty is skipped', async () => {
            const { client } = createClient({
                attachments: { ATT2: null },
                getMessage: () =>
                    Object.assign({}, REFERENCED, { attachments: [{ id: 'ATT2', filename: 'gone.bin', contentType: 'application/octet-stream' }] })
            });
            const data = { to: [{ address: 'fwd@example.com' }], text: 'FYI', reference: { message: 'MSG1', action: 'forward', forwardAttachments: true } };
            await client.prepareRawMessage(data);
            assert.deepStrictEqual(data.attachments, []);
        });

        await t.test('an attachment referenced by id is downloaded', async () => {
            const { client, calls } = createClient();
            const data = { to: [{ address: 'r@example.com' }], text: 'x', attachments: [{ filename: 'a.txt', reference: 'ATT9' }] };
            const result = await client.prepareRawMessage(data, null, CONNECTION);
            assert.deepStrictEqual(
                calls.map(call => call.slice(0, 2)),
                [
                    ['checkIMAPConnection', CONNECTION],
                    ['getAttachmentContent', 'ATT9']
                ]
            );
            assert.strictEqual(data.attachments[0].content.toString(), 'content-of-ATT9');
            assert.ok(result.raw.toString().includes(Buffer.from('content-of-ATT9').toString('base64')));
        });

        await t.test('an attachment with content of its own is not downloaded', async () => {
            const { client, calls } = createClient();
            await client.prepareRawMessage({
                to: [{ address: 'r@example.com' }],
                text: 'x',
                attachments: [{ filename: 'a.txt', reference: 'ATT9', content: 'own' }]
            });
            assert.deepStrictEqual(calls, []);
        });

        await t.test('an attachment referenced by id that is gone fails the upload', async () => {
            const { client } = createClient({ attachments: { ATT9: null } });
            await assert.rejects(
                client.prepareRawMessage({ to: [{ address: 'r@example.com' }], text: 'x', attachments: [{ filename: 'a.txt', reference: 'ATT9' }] }),
                { message: 'Referenced attachment was not found', code: 'ReferenceNotFound', statusCode: 404 }
            );
        });
    });

    await t.test('final defaults', async t => {
        await t.test('internalDate sets the Date header when no date is given', async () => {
            const { client } = createClient();
            const data = { to: [{ address: 'r@example.com' }], text: 'x', internalDate: '2026-05-01T08:09:10.000Z' };
            const result = await client.prepareRawMessage(data);
            assert.deepStrictEqual(data.date, new Date('2026-05-01T08:09:10.000Z'));
            assert.match(result.raw.toString(), /^Date: Fri, 01 May 2026 08:09:10 \+0000$/m);
        });

        await t.test('an explicit date wins over internalDate', async () => {
            const { client } = createClient();
            const data = { to: [{ address: 'r@example.com' }], text: 'x', date: '2026-01-02T03:04:05.000Z', internalDate: '2026-05-01T08:09:10.000Z' };
            await client.prepareRawMessage(data);
            assert.strictEqual(data.date, '2026-01-02T03:04:05.000Z');
        });

        await t.test('the composer options are forced and locale and tz are consumed', async () => {
            const { client } = createClient();
            const data = {
                to: [{ address: 'r@example.com' }],
                text: 'x',
                locale: 'et',
                tz: 'Europe/Tallinn',
                disableFileAccess: false,
                disableUrlAccess: false
            };
            await client.prepareRawMessage(data);
            assert.strictEqual(data.disableFileAccess, true);
            assert.strictEqual(data.disableUrlAccess, true);
            assert.strictEqual(data.newline, '\r\n');
            assert.ok(data.boundaryPrefix);
            assert.ok(data.baseBoundary);
            assert.strictEqual('locale' in data, false);
            assert.strictEqual('tz' in data, false);
        });

        await t.test('a data: URI image becomes an inline attachment', async () => {
            const { client } = createClient();
            const data = { to: [{ address: 'r@example.com' }], html: '<img src="data:image/png;base64,iVBORw0KGgo=">' };
            await client.prepareRawMessage(data);
            assert.strictEqual(data.attachments.length, 1);
            assert.match(data.html, /src="cid:/);
        });
    });
});
