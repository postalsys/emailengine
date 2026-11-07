'use strict';

// The web-safe copy of a message replaces its HTML in the messageNew payload after notifyTextSize
// was applied to the HTML, so with inline images embedded the delivered html ignored the limit:
// 689 bytes of HTML became a 3.5 MB payload under a 1 KB notifyTextSize.

const test = require('node:test');
const assert = require('node:assert').strict;

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];
settings.getMulti = async (...keys) => Object.fromEntries(keys.map(key => [key, settingsValues[key]]));

const { webhooks: Webhooks } = require('../lib/webhooks');
const { MESSAGE_NEW_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const message = () => ({
    data: {
        text: { id: 't1', html: '<img src="cid:a">', plain: 'hi', _generatedHtml: `<img src="data:image/png;base64,${'A'.repeat(50000)}">`, webSafe: true }
    }
});

test('notifyTextSize applies to the web-safe copy that replaces the HTML', async () => {
    Object.assign(settingsValues, { notifyText: true, notifyTextSize: 1024 });
    const payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, message());
    assert.equal(payload.data.text.html.length, 1024);
    assert.equal(payload.data.text.hasMore, true);
    assert.equal('_generatedHtml' in payload.data.text, false);
});

test('without a size limit the web-safe copy is delivered whole', async () => {
    Object.assign(settingsValues, { notifyText: true, notifyTextSize: 0 });
    const payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, message());
    assert.ok(payload.data.text.html.length > 50000);
});

test('with text notifications off the web-safe copy goes too', async () => {
    Object.assign(settingsValues, { notifyText: false, notifyTextSize: 1024 });
    const payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, message());
    assert.equal(payload.data.text.html, undefined);
});

test('a calendar event in the payload is held to the attachment and text limits', async () => {
    Object.assign(settingsValues, { notifyText: true, notifyTextSize: 100, notifyAttachmentSize: 1000 });
    const payload = await Webhooks.formatPayload(MESSAGE_NEW_NOTIFY, {
        data: {
            calendarEvents: [
                { eventId: 'big', content: 'A'.repeat(4000), description: 'd'.repeat(500) },
                { eventId: 'small', content: 'QUJD', description: 'short' }
            ]
        }
    });
    const [big, small] = payload.data.calendarEvents;
    assert.equal(big.content, undefined);
    assert.equal(big.description.length, 100);
    assert.equal(small.content, 'QUJD');
    assert.equal(small.description, 'short');
});
