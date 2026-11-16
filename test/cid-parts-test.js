'use strict';

// collectCidParts(), the CID collection that Mailbox.getMessage() (embedAttachedImages) and
// Mailbox.processNew() (the web-safe copy) shared as copies of one loop.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { collectCidParts } = require('../lib/email-client/imap/cid-parts');
const { MAX_INLINE_ATTACHMENT_SIZE } = require('../lib/consts');

// An IMAP attachment id: 8 bytes of prefix, then the body part
const attachmentId = part => Buffer.concat([Buffer.alloc(8, 1), Buffer.from(part)]).toString('base64url');

function message() {
    return {
        text: { html: '<img src="cid:a@x"><img src="cid:b@x"><img src="cid:big@x"><img src="cid:dup@x">' },
        attachments: [
            { id: attachmentId('2'), contentId: '<a@x>' },
            { id: attachmentId('3'), contentId: 'b@x', content: 'bG9hZGVk' },
            { id: attachmentId('4'), contentId: '<big@x>', encodedSize: MAX_INLINE_ATTACHMENT_SIZE + 1 },
            { id: attachmentId('5'), contentId: '<unused@x>' },
            { id: attachmentId('6'), contentId: '<dup@x>' },
            { id: attachmentId('6'), contentId: '<dup@x>' },
            { id: attachmentId('7') }
        ]
    };
}

test('collectCidParts', async t => {
    await t.test('collects every referenced attachment and its body part', () => {
        const info = message();
        const { attachmentList, partList } = collectCidParts(info);
        assert.deepStrictEqual([...attachmentList.keys()], ['a@x', 'b@x', 'big@x', 'dup@x']);
        // the last attachment with a content id wins the entry; its part is only listed once
        assert.strictEqual(attachmentList.get('dup@x').attachment, info.attachments[5]);
        assert.deepStrictEqual(partList, ['2', '3', '4', '6']);
        for (const entry of attachmentList.values()) {
            assert.strictEqual(entry.content, null);
        }
    });

    await t.test('the part is not enumerable, so it never reaches a serialized message', () => {
        const info = message();
        collectCidParts(info);
        const attachment = info.attachments[0];
        assert.strictEqual(attachment.part, '2');
        assert.deepStrictEqual(Object.getOwnPropertyDescriptor(attachment, 'part'), { value: '2', writable: false, enumerable: false, configurable: false });
        assert.strictEqual(JSON.stringify(attachment).includes('part'), false);
        // an unreferenced attachment is left alone
        assert.strictEqual('part' in info.attachments[3], false);
    });

    await t.test('reuseLoaded keeps loaded content and skips loaded or oversized parts', () => {
        const info = message();
        const { attachmentList, partList } = collectCidParts(info, { reuseLoaded: true });
        assert.deepStrictEqual(partList, ['2', '6']);
        assert.strictEqual(attachmentList.get('b@x').content, 'bG9hZGVk');
        assert.strictEqual(attachmentList.get('a@x').content, null);
        assert.strictEqual('part' in info.attachments[1], false);
        assert.strictEqual('part' in info.attachments[2], false);
        assert.strictEqual(attachmentList.has('big@x'), true);
    });

    await t.test('without reuseLoaded, content an attachment carries is not used', () => {
        const { attachmentList } = collectCidParts(message());
        assert.strictEqual(attachmentList.get('b@x').content, null);
    });
});
