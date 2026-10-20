'use strict';

// formatPayload() decides which loaded attachment contents stay in a messageNew payload. It has to
// measure an attachment the way processNew() does before downloading it (the encoded size from the
// message structure), or an inline image that the web-safe embed loaded can stay in the payload
// although the notifyAttachments download skipped it as too large.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];

const { webhooks: Webhooks } = require('../lib/webhooks');
const { MESSAGE_NEW_NOTIFY } = require('../lib/consts');

// 600 decoded bytes, 800 as base64, around 820 encoded in the message with line breaks
const CONTENT = Buffer.alloc(600, 1).toString('base64');

async function keptContents(attachments) {
    let payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, { data: { attachments } });
    return payload.data.attachments.map(attachment => !!attachment.content);
}

test('formatPayload() measures attachments by their encoded size', async t => {
    t.beforeEach(() => {
        for (const key of Object.keys(settingsValues)) {
            delete settingsValues[key];
        }
    });

    await t.test('drops contents when notifyAttachments is off', async () => {
        assert.deepEqual(await keptContents([{ encodedSize: 820, content: CONTENT }]), [false]);
    });

    await t.test('keeps every content without a size limit', async () => {
        settingsValues.notifyAttachments = true;
        assert.deepEqual(await keptContents([{ encodedSize: 820, content: CONTENT }]), [true]);
    });

    await t.test('an encoded size above the limit is dropped even when the decoded size fits', async () => {
        settingsValues.notifyAttachments = true;
        settingsValues.notifyAttachmentSize = 700;
        assert.deepEqual(await keptContents([{ encodedSize: 820, content: CONTENT }]), [false]);
    });

    await t.test('an encoded size at the limit is kept, as processNew() downloads it', async () => {
        settingsValues.notifyAttachments = true;
        settingsValues.notifyAttachmentSize = 820;
        assert.deepEqual(await keptContents([{ encodedSize: 820, content: CONTENT }]), [true]);
    });

    await t.test('without an encoded size the decoded size counts', async () => {
        settingsValues.notifyAttachments = true;
        settingsValues.notifyAttachmentSize = 700;
        assert.deepEqual(await keptContents([{ content: CONTENT }]), [true]);
        settingsValues.notifyAttachmentSize = 500;
        assert.deepEqual(await keptContents([{ content: CONTENT }]), [false]);
    });
});
