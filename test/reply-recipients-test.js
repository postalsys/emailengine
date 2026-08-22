'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { applyReferenceRecipients } = require('../lib/email-client/base-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

// Recipient derivation for reply and reply-all, shared by prepareRawMessage() and
// queueMessageEntry() (both used to carry a byte-identical copy of it).
//
// An address entry can carry a display name and no address at all: RFC 9051 7.5.2 group
// markers look like that, and so does a server that answered FETCH ENVELOPE after failing
// to parse a malformed address header. Those entries used to travel on as recipients with
// an empty address.

const GROUP_MARKER = { name: 'undisclosed-recipients', address: '' };
const MANGLED = { name: 'user@example.com user@', address: '' };

test('reply recipients', async t => {
    await t.test('answers the Reply-To address when the message names one', () => {
        const data = { reference: { action: 'reply' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            replyTo: [{ name: 'Desk', address: 'desk@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Desk', address: 'desk@example.com' }]);
    });

    await t.test('answers the sender when there is no Reply-To', () => {
        const data = { reference: { action: 'reply' } };

        applyReferenceRecipients(data, { from: { name: 'Sender', address: 'sender@example.com' } });

        // A list, not the bare `from` entry: getRawEmail() maps over the address fields when
        // it builds the envelope for a structured submission, which is the Outlook path
        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }]);
    });

    await t.test('ignores a Reply-To that carries no address', () => {
        const data = { reference: { action: 'reply' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            replyTo: [GROUP_MARKER]
        });

        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }], 'a group name is not something a reply can be delivered to');
    });

    await t.test('keeps only the usable entries of a mixed Reply-To', () => {
        const data = { reference: { action: 'reply' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            replyTo: [GROUP_MARKER, { name: 'Desk', address: 'desk@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Desk', address: 'desk@example.com' }]);
    });

    await t.test('reports no recipient when nothing is addressable', () => {
        const data = { reference: { action: 'reply' } };

        applyReferenceRecipients(data, { from: MANGLED, replyTo: [GROUP_MARKER] });

        assert.equal(data.to, false, 'an empty address must not reach the submission as a recipient');
    });

    await t.test('does not overwrite a recipient the caller supplied', () => {
        const data = { reference: { action: 'reply' }, to: [{ address: 'chosen@example.com' }] };

        applyReferenceRecipients(data, { from: { name: 'Sender', address: 'sender@example.com' } });

        assert.deepEqual(data.to, [{ address: 'chosen@example.com' }]);
    });
});

test('reply-all recipients', async t => {
    await t.test('collects the other recipients and drops the group marker', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [GROUP_MARKER, { name: 'Colleague', address: 'colleague@example.com' }],
            cc: [{ name: 'Watcher', address: 'watcher@example.com' }]
        });

        assert.deepEqual(data.to, [
            { name: 'Sender', address: 'sender@example.com' },
            { name: 'Colleague', address: 'colleague@example.com' }
        ]);
        assert.deepEqual(data.cc, [{ name: 'Watcher', address: 'watcher@example.com' }]);
    });

    await t.test('leaves cc alone when it holds nothing addressable', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            cc: [GROUP_MARKER]
        });

        assert.equal(data.cc, undefined);
    });

    await t.test('never addresses the reply back to the account itself', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'me@example.com' }, { address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }]);
    });

    await t.test('deduplicates a recipient that appears twice', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'sender@example.com' }, { address: 'colleague@example.com' }],
            cc: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }]);
        assert.equal(data.cc, undefined, 'a recipient already on the To line is not repeated on Cc');
    });

    await t.test('deduplicates a caller recipient against the referenced one on the same field', () => {
        const data = {
            reference: { action: 'reply-all' },
            from: { address: 'me@example.com' },
            to: [{ address: 'colleague@example.com' }]
        };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }]);
    });

    await t.test('keeps the recipients the caller supplied, after the referenced ones', () => {
        const data = {
            reference: { action: 'reply-all' },
            from: { address: 'me@example.com' },
            to: [{ address: 'extra@example.com' }]
        };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }, { address: 'extra@example.com' }]);
    });

    await t.test('prefers Reply-To over the sender', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            replyTo: [{ name: 'Desk', address: 'desk@example.com' }],
            to: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ name: 'Desk', address: 'desk@example.com' }, { address: 'colleague@example.com' }]);
    });

    await t.test('does not mutate the referenced message', () => {
        const referencedMessage = {
            from: { name: 'Sender', address: 'sender@example.com' },
            replyTo: [{ name: 'Desk', address: 'desk@example.com' }],
            to: [{ address: 'colleague@example.com' }]
        };
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, referencedMessage);

        assert.deepEqual(
            referencedMessage.replyTo,
            [{ name: 'Desk', address: 'desk@example.com' }],
            'the reply-all envelope must not grow the cached replyTo list'
        );
    });

    await t.test('never carries the referenced message Bcc into the reply', () => {
        // A Bcc header is stripped by the sender's own client, so one that survives on a
        // received message was put there by whoever sent it. Copying it added a recipient
        // of their choosing to the reply envelope, and removeBcc() then kept it out of the
        // sent copy, so nothing recorded where the reply had gone.
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'colleague@example.com' }],
            bcc: [{ address: 'harvest@evil.example.com' }]
        });

        assert.equal(data.bcc, undefined, 'a Bcc on the referenced message is not a reply-all recipient');
        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }]);
    });

    await t.test('still honors a Bcc the caller asked for', () => {
        const data = {
            reference: { action: 'reply-all' },
            from: { address: 'me@example.com' },
            bcc: [{ address: 'archive@example.com' }]
        };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            bcc: [{ address: 'harvest@evil.example.com' }]
        });

        assert.deepEqual(data.bcc, [{ address: 'archive@example.com' }]);
    });

    await t.test('leaves a fully deduplicated bcc as the caller supplied it', () => {
        // Every caller Bcc is already a visible recipient, so envelope.bcc stays empty and
        // the assignment is skipped. The address is delivered once, from the To line, and
        // removeBcc() drops the header on the way out
        const data = {
            reference: { action: 'reply-all' },
            from: { address: 'me@example.com' },
            bcc: [{ address: 'colleague@example.com' }]
        };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.bcc, [{ address: 'colleague@example.com' }]);
        assert.deepEqual(data.to, [{ name: 'Sender', address: 'sender@example.com' }, { address: 'colleague@example.com' }]);
    });

    await t.test('leaves the recipients untouched when nothing is addressable', () => {
        const data = { reference: { action: 'reply-all' }, from: { address: 'me@example.com' } };

        applyReferenceRecipients(data, { from: MANGLED, to: [GROUP_MARKER], cc: [GROUP_MARKER] });

        // Unlike the reply branch, reply-all leaves an absent recipient absent rather than
        // marking it false - the submission fails the same way either route
        assert.equal(data.to, undefined);
        assert.equal(data.cc, undefined);
    });
});

test('other reference actions', async t => {
    await t.test('a forward keeps the recipients as they were', () => {
        const data = { reference: { action: 'forward' }, to: [{ address: 'target@example.com' }] };

        applyReferenceRecipients(data, {
            from: { name: 'Sender', address: 'sender@example.com' },
            to: [{ address: 'colleague@example.com' }]
        });

        assert.deepEqual(data.to, [{ address: 'target@example.com' }]);
        assert.equal(data.cc, undefined);
    });

    await t.test('a forward with no recipient set is left for the caller to fill', () => {
        const data = { reference: { action: 'forward' } };

        applyReferenceRecipients(data, { from: { name: 'Sender', address: 'sender@example.com' } });

        assert.equal(data.to, undefined);
    });
});
