'use strict';

// Mailbox.getMessage() after the FETCH: which text parts it reads for each textType, the web-safe
// conversion, and the inline image embedding, which downloads under a second mailbox lock of its
// own. The lock of the FETCH is released before any of that, every way out of the FETCH included,
// and the image download must not run unlocked: another task could select a different folder on
// the connection in between, and the UID would then address another message.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const webSafeModule = require('../lib/web-safe-html');
webSafeModule.messageWebSafeHtml = async messageInfo => `<safe>${messageInfo.text.html || messageInfo.text.plain}</safe>`;

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

const partId = part => Buffer.concat([Buffer.alloc(8), Buffer.from(part)]).toString('base64url');

function createContext({ fetchResult = { uid: 42, flags: new Set() }, messageInfo, textContent, downloadMany, lockFails = false } = {}) {
    const steps = [];
    const logger = createMockLogger();

    const connectionClient = {
        fetchOne: async uid => {
            steps.push(`fetch:${uid}`);
            return fetchResult;
        },
        downloadMany:
            downloadMany ||
            (async (uid, parts) => {
                steps.push(`downloadMany:${parts.join(',')}`);
                return Object.fromEntries(parts.map(part => [part, { content: Buffer.from(`img-${part}`) }]));
            })
    };

    const lockFor = name => ({
        release: () => steps.push(`release:${name}`)
    });

    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        logger,
        connection: {
            account: 'test-account',
            getImapConnection: async () => connectionClient,
            getMessageTextPaths: async textId => {
                steps.push(`textPaths:${textId}`);
                return { textParts: [['1'], ['2']] };
            }
        },
        lockForMessage: async (client, message, opts) => {
            steps.push(`lock:message${opts.skipLock ? ':skip' : ''}`);
            return lockFails ? null : lockFor('message');
        },
        getMailboxLock: async (client, opts) => {
            steps.push(`lock:${opts.description}`);
            return lockFor('images');
        },
        getMessageInfo: async () => {
            steps.push('info');
            return messageInfo === undefined ? { id: 'AAAAAQAAAAI', uid: 42, text: { id: 'text-1' } } : messageInfo && structuredClone(messageInfo);
        },
        getText: async (message, textParts, options, connectionOptions) => {
            steps.push(`getText:${JSON.stringify(textParts)}`);
            assert.equal(connectionOptions.connectionClient, connectionClient, 'the text is read on the same connection');
            return Object.assign({ plain: 'plain text', html: '<p>html</p>', hasMore: false }, textContent);
        }
    });

    return { ctx, steps, logger };
}

const get = (ctx, options) => ctx.getMessage({ uid: 42 }, options);

test('Mailbox.getMessage() text', async t => {
    await t.test('plain reads the plain parts only and returns only that type', async () => {
        const { ctx, steps } = createContext();

        const message = await get(ctx, { textType: 'plain' });

        assert.deepEqual(steps, ['lock:message', 'fetch:42', 'info', 'release:message', 'textPaths:text-1', 'getText:["1"]']);
        assert.deepEqual(message.text, { id: 'text-1', plain: 'plain text', hasMore: false });
    });

    await t.test('html reads the html parts only', async () => {
        const { ctx, steps } = createContext({ textContent: { plain: undefined, hasMore: true } });

        const message = await get(ctx, { textType: 'html' });

        assert.ok(steps.includes('getText:["2"]'));
        assert.deepEqual(message.text, { id: 'text-1', html: '<p>html</p>', hasMore: true });
    });

    await t.test('a type the message lacks comes back empty', async () => {
        const { ctx } = createContext({ textContent: { html: undefined } });

        const message = await get(ctx, { textType: 'html' });

        assert.deepEqual(message.text, { id: 'text-1', html: '', hasMore: false });
    });

    await t.test('* reads every part and keeps everything the read returned', async () => {
        const { ctx, steps } = createContext();

        const message = await get(ctx, { textType: '*' });

        assert.ok(steps.includes('getText:["1","2"]'));
        assert.deepEqual(message.text, { id: 'text-1', plain: 'plain text', html: '<p>html</p>', hasMore: false });
    });

    await t.test('no textType, or a message without a text id, reads no text', async () => {
        const none = createContext();
        await get(none.ctx, {});
        assert.ok(!none.steps.some(step => step.startsWith('getText')));

        const noId = createContext({ messageInfo: { id: 'AAAAAQAAAAI', uid: 42, text: {} } });
        await get(noId.ctx, { textType: '*' });
        assert.ok(!noId.steps.some(step => step.startsWith('textPaths')));
    });

    await t.test('preProcessHtml replaces the html with its web-safe copy', async () => {
        const { ctx } = createContext();

        const message = await get(ctx, { textType: '*', preProcessHtml: true });

        assert.equal(message.text.html, '<safe><p>html</p></safe>');
        assert.equal(message.text.webSafe, true);
    });

    await t.test('preProcessHtml renders a plain-only message too', async () => {
        const { ctx } = createContext({ textContent: { html: undefined } });

        const message = await get(ctx, { textType: 'plain', preProcessHtml: true });

        assert.equal(message.text.html, '<safe>plain text</safe>');
        assert.equal(message.text.webSafe, true);
    });

    await t.test('without text preProcessHtml does nothing', async () => {
        const { ctx } = createContext({ messageInfo: { id: 'AAAAAQAAAAI', uid: 42 } });

        const message = await get(ctx, { preProcessHtml: true });

        assert.equal(message.text, undefined);
    });
});

test('Mailbox.getMessage() FETCH lock', async t => {
    await t.test('a lock for a previous incarnation of the folder answers false without a FETCH', async () => {
        const { ctx, steps } = createContext({ lockFails: true });

        assert.equal(await get(ctx, {}), false);
        assert.deepEqual(steps, ['lock:message']);
    });

    await t.test('a partial FETCH answers false and still releases the lock', async () => {
        const { ctx, steps } = createContext({ fetchResult: { flags: new Set() } });

        assert.equal(await get(ctx, { textType: '*' }), false);
        assert.deepEqual(steps, ['lock:message', 'fetch:42', 'release:message']);
    });

    await t.test('a failed FETCH releases the lock', async () => {
        const { ctx, steps } = createContext();
        ctx.connection.getImapConnection = async () => ({
            fetchOne: async () => {
                throw new Error('Command failed');
            }
        });

        await assert.rejects(get(ctx, {}), /Command failed/);
        assert.deepEqual(steps, ['lock:message', 'release:message']);
    });

    await t.test('no message info answers false after the release', async () => {
        const { ctx, steps } = createContext({ messageInfo: null });

        assert.equal(await get(ctx, { textType: '*' }), false);
        assert.deepEqual(steps, ['lock:message', 'fetch:42', 'info', 'release:message']);
    });

    await t.test('skipLock is passed on to the FETCH lock', async () => {
        const { ctx, steps } = createContext();

        await get(ctx, { skipLock: true });

        assert.equal(steps[0], 'lock:message:skip');
    });
});

test('Mailbox.getMessage() inline images', async t => {
    const embedded = () => ({
        id: 'AAAAAQAAAAI',
        uid: 42,
        text: { id: 'text-1' },
        attachments: [
            { id: partId('3'), contentId: '<img@x>', contentType: 'image/png' },
            { id: partId('4'), contentId: '<unused@x>', contentType: 'image/png' }
        ]
    });
    const html = '<p><img src="cid:img@x"></p>';

    await t.test('referenced images are downloaded under a second lock and embedded', async () => {
        const { ctx, steps } = createContext({ messageInfo: embedded(), textContent: { html } });

        const message = await get(ctx, { textType: 'html', embedAttachedImages: true });

        assert.deepEqual(steps.slice(steps.indexOf('release:message')), [
            'release:message',
            'textPaths:text-1',
            'getText:["2"]',
            'lock:Download inline images: 42',
            'downloadMany:3',
            'release:images'
        ]);
        assert.equal(message.text.html, `<p><img src="data:image/png;base64,${Buffer.from('img-3').toString('base64')}"></p>`);
        assert.ok(!Object.keys(message.attachments[0]).includes('content'), 'the downloaded content stays off the payload');
        assert.ok(Buffer.isBuffer(message.attachments[0].content));
    });

    await t.test('with skipLock the caller holds the lock and none is taken', async () => {
        const { ctx, steps } = createContext({ messageInfo: embedded(), textContent: { html } });

        await get(ctx, { textType: 'html', embedAttachedImages: true, skipLock: true });

        assert.ok(!steps.some(step => step.startsWith('lock:Download')));
        assert.ok(steps.includes('downloadMany:3'));
        assert.ok(!steps.includes('release:images'));
    });

    await t.test('a failed download is logged, the lock released and the message returned as is', async () => {
        const { ctx, steps, logger } = createContext({
            messageInfo: embedded(),
            textContent: { html },
            downloadMany: async () => {
                throw Object.assign(new Error('Gone'), { code: 'NoConnection' });
            }
        });

        const message = await get(ctx, { textType: 'html', embedAttachedImages: true });

        assert.equal(message.text.html, html);
        assert.equal(steps.at(-1), 'release:images');
        assert.deepEqual(
            logger.entries.filter(entry => entry.level === 'error').map(entry => entry.msg),
            ['Failed to download attachments']
        );
    });

    await t.test('nothing referenced, nothing downloaded and no lock taken', async () => {
        const { ctx, steps } = createContext({ messageInfo: embedded(), textContent: { html: '<p>no images</p>' } });

        await get(ctx, { textType: 'html', embedAttachedImages: true });

        assert.ok(!steps.some(step => step.startsWith('lock:Download') || step.startsWith('downloadMany')));
    });

    await t.test('an empty answer leaves the html alone', async () => {
        const { ctx, steps } = createContext({
            messageInfo: embedded(),
            textContent: { html },
            downloadMany: async () => null
        });

        const message = await get(ctx, { textType: 'html', embedAttachedImages: true });

        assert.equal(message.text.html, html);
        assert.equal(steps.at(-1), 'release:images');
    });

    await t.test('the web-safe copy is made before the images are embedded', async () => {
        const { ctx } = createContext({ messageInfo: embedded(), textContent: { html } });

        const message = await get(ctx, { textType: 'html', embedAttachedImages: true, preProcessHtml: true });

        assert.ok(message.text.html.startsWith('<safe><p><img src="data:image/png;base64,'));
    });
});
