'use strict';

// lib/email-client/new-message-steps.js: the new-message decisions the IMAP and API pipelines share

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const {
    isFailedDelivery,
    isOwnSent,
    classifyBounce,
    bounceNotification,
    complaintNotification,
    embedInlineImages,
    markWebSafe,
    notifyNewMessage
} = require('../lib/email-client/new-message-steps');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createMockLogger } = require('./helpers/mock-logger');

const logger = createMockLogger();

test('new-message steps', async t => {
    await t.test('isOwnSent() recognises the account own mail however the backend marks it', () => {
        assert.equal(isOwnSent({}, '\\Sent'), true, 'listed in a Sent folder');
        assert.equal(isOwnSent({ messageSpecialUse: '\\Sent' }), true, 'resolved to Sent');
        assert.equal(isOwnSent({ labels: ['\\Inbox', '\\Sent'] }, '\\All'), true, 'a Sent label next to Inbox');
        assert.equal(isOwnSent({ labels: ['\\Inbox'], messageSpecialUse: '\\Inbox' }, '\\All'), false);
        assert.equal(isOwnSent({}, '\\Inbox'), false);
        assert.equal(isOwnSent({ labels: 'not a list' }), false);
    });

    await t.test('classifyBounce() adds the classifier verdict', async () => {
        const calls = [];
        const bounce = { response: { message: '550 5.1.1 user unknown' } };
        await classifyBounce(
            bounce,
            async command => {
                calls.push(command);
                return { label: 'unknown_user', action: 'remove', blocklist: { name: 'x' }, retryAfter: 60 };
            },
            logger
        );
        assert.equal(calls[0].cmd, 'bounceClassify');
        assert.equal(calls[0].data.message, '550 5.1.1 user unknown');
        assert.deepEqual(bounce.response, {
            message: '550 5.1.1 user unknown',
            category: 'unknown_user',
            recommendedAction: 'remove',
            blocklist: { name: 'x' },
            retryAfter: 60
        });
    });

    await t.test('classifyBounce() leaves the bounce alone when the classifier fails or there is no response', async () => {
        const warnLogger = createMockLogger();
        const bounce = { response: { message: 'x' } };
        await classifyBounce(
            bounce,
            async () => {
                throw new Error('down');
            },
            warnLogger
        );
        assert.deepEqual(bounce.response, { message: 'x' });
        assert.equal(warnLogger.entries.filter(entry => entry.level === 'warn').length, 1);

        let called = false;
        await classifyBounce(
            {},
            async () => {
                called = true;
            },
            logger
        );
        await classifyBounce(null, async () => (called = true), logger);
        assert.equal(called, false);
    });

    await t.test('bounceNotification() marks only a failed delivery', () => {
        const failed = { action: 'failed', recipient: 'a@example.com', messageId: '<orig@example.com>' };
        const messageData = { id: 'm1' };
        assert.deepEqual(bounceNotification(failed, messageData), Object.assign({ bounceMessage: 'm1' }, failed));
        assert.equal(messageData.isBounce, true);
        assert.equal(messageData.relatedMessageId, '<orig@example.com>');

        const delayed = { id: 'm2' };
        assert.equal(bounceNotification({ action: 'delayed', recipient: 'a@example.com', messageId: '<x>' }, delayed), undefined);
        assert.deepEqual(delayed, { id: 'm2' });
        assert.equal(isFailedDelivery(null), false);
        assert.equal(isFailedDelivery({ action: ' Failed ', recipient: 'a', messageId: 'b' }), true);
    });

    await t.test('complaintNotification() needs a report naming the original recipient', () => {
        const messageData = { id: 'm1' };
        assert.equal(complaintNotification({ arf: { 'original-rcpt-to': [] } }, messageData), undefined);
        assert.equal(complaintNotification(null, messageData), undefined);
        assert.equal(messageData.isComplaint, undefined);

        const report = {
            arf: { 'feedback-type': 'abuse', 'original-rcpt-to': ['user@example.com'] },
            headers: { 'message-id': '<orig@example.com>' }
        };
        const info = complaintNotification(report, messageData);
        assert.equal(info.complaintMessage, 'm1');
        assert.equal(messageData.isComplaint, true);
        assert.equal(messageData.relatedMessageId, info.headers && info.headers.messageId);
    });

    await t.test('embedInlineImages() embeds in the HTML and its web-safe copy', () => {
        const text = {
            html: '<img src="cid:logo@x">',
            _generatedHtml: '<div><img src="cid:logo@x"></div>'
        };
        embedInlineImages(text, new Map([['logo@x', { attachment: { contentType: 'image/png' }, content: 'AAAA' }]]));
        assert.match(text.html, /src="data:image\/png;base64,AAAA"/);
        assert.match(text._generatedHtml, /src="data:image\/png;base64,AAAA"/);
    });

    await t.test('embedInlineImages() keeps a reference it has no content for', () => {
        const text = { html: '<img src="cid:logo@x">' };
        embedInlineImages(text, new Map([['logo@x', { attachment: { contentType: 'image/png' }, content: null }]]));
        assert.equal(text.html, '<img src="cid:logo@x">');
        embedInlineImages(text, new Map());
        assert.equal(text.html, '<img src="cid:logo@x">');
    });

    await t.test('markWebSafe() flags only text that has a web-safe copy', () => {
        const without = { html: '<script>x</script>' };
        markWebSafe(without);
        assert.equal(without.webSafe, undefined);

        const empty = { html: '<b>x</b>', _generatedHtml: '' };
        markWebSafe(empty);
        assert.equal(empty.webSafe, undefined);

        const withCopy = { html: '<b>x</b>', _generatedHtml: '<div><b>x</b></div>' };
        markWebSafe(withCopy);
        assert.equal(withCopy.webSafe, true);
    });

    await t.test('notifyNewMessage() sends the message before the events about it', async () => {
        const sent = [];
        const notify = async (target, event, data) => sent.push({ target, event, data });
        const target = { path: 'INBOX' };
        await notifyNewMessage(notify, target, { id: 'm1' }, { bounceNotifyInfo: { b: 1 }, complaintNotifyInfo: { c: 1 } });
        assert.deepEqual(
            sent.map(entry => [entry.target, entry.event]),
            [
                [target, 'messageNew'],
                [false, 'messageBounce'],
                [false, 'messageComplaint']
            ]
        );

        sent.length = 0;
        await notifyNewMessage(notify, target, { id: 'm2' });
        assert.equal(sent.length, 1);
    });
});

registerRedisTeardown(redis);
