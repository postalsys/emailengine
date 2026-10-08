'use strict';

// Bounds on the JSON submission payloads, checked against the real route schemas:
//   - per-message deliveryAttempts (audit API-7): negative and huge values used to be accepted, and
//     the uncapped exponential retry backoff then kept a failing message queued indefinitely
//   - the attachment list (audit DELIV-3): each attachment is a MIME node, and a message with more
//     nodes than the MIME splitter accepts could be queued but never delivered
//   - sender and recipient addresses: no 64 octet local part limit, only the overall cap (see mailboxAddressSchema)

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { MAX_MESSAGE_ATTACHMENTS } = require('../lib/schemas');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const OPTIONS = { abortEarly: false, convert: true, stripUnknown: false };

function errorsAt(schema, payload, key) {
    const { error } = schema.validate(payload, OPTIONS);
    return error ? error.details.filter(detail => detail.path[0] === key) : [];
}

test('submission payload bounds', async t => {
    const { routes } = await captureApiRoutes();
    const payloadOf = key => {
        const route = routes.find(r => r.route === key);
        assert.ok(route, key);
        return route.payload;
    };

    const submit = payloadOf('POST /v1/account/{account}/submit');
    const draftSubmit = payloadOf('POST /v1/account/{account}/message/{message}/submit');
    const upload = payloadOf('POST /v1/account/{account}/message');

    await t.test('deliveryAttempts stays within 0..100', () => {
        for (const schema of [submit, draftSubmit]) {
            assert.equal(errorsAt(schema, { deliveryAttempts: 0 }, 'deliveryAttempts').length, 0);
            assert.equal(errorsAt(schema, { deliveryAttempts: 10 }, 'deliveryAttempts').length, 0);
            assert.equal(errorsAt(schema, { deliveryAttempts: 100 }, 'deliveryAttempts').length, 0);
            assert.equal(errorsAt(schema, { deliveryAttempts: -1 }, 'deliveryAttempts').length, 1);
            assert.equal(errorsAt(schema, { deliveryAttempts: 101 }, 'deliveryAttempts').length, 1);
        }
    });

    await t.test(`the attachment list is capped at ${MAX_MESSAGE_ATTACHMENTS}`, () => {
        const attachment = { filename: 'a.txt', content: 'aGVsbG8=' };
        const list = count => Array.from({ length: count }, () => attachment);

        for (const schema of [submit, upload]) {
            assert.equal(errorsAt(schema, { attachments: list(MAX_MESSAGE_ATTACHMENTS) }, 'attachments').length, 0);
            const over = errorsAt(schema, { attachments: list(MAX_MESSAGE_ATTACHMENTS + 1) }, 'attachments');
            assert.ok(over.some(detail => detail.type === 'array.max'));
        }
        assert.ok(MAX_MESSAGE_ATTACHMENTS < 1000, 'stays below the MIME splitter node limit');
    });

    // A client sending every documented field with its default passed forwardAttachments: false
    // on a reply and got "not allowed" back
    await t.test('reference.forwardAttachments is refused only when enabled outside a forward', () => {
        const reference = (action, forwardAttachments) => ({ reference: { message: 'AAAAAQAACnA', action, forwardAttachments } });

        for (const schema of [submit, upload]) {
            assert.equal(errorsAt(schema, reference('forward', true), 'reference').length, 0);
            assert.equal(errorsAt(schema, reference('forward', false), 'reference').length, 0);
            assert.equal(errorsAt(schema, reference('reply', false), 'reference').length, 0);
            assert.equal(errorsAt(schema, reference('reply-all', 'false'), 'reference').length, 0);

            const enabled = errorsAt(schema, reference('reply', true), 'reference');
            assert.equal(enabled.length, 1);
            assert.match(enabled[0].message, /can only be enabled when action is "forward"/);
        }
    });

    await t.test('addresses are not refused for a long local part', () => {
        // 65 octet local part
        const long = 'A.t.123456789012.u-123456789.00000000-0000-4000-8000-000000000000@tasks.clickup.com';
        const tooLong = `${'a'.repeat(250)}@example.com`;
        const malformed = 'name.@example.com';

        const removeQuery = routes.find(r => r.route === 'DELETE /v1/blocklist/{listId}').settings.validate.query;
        const cases = [
            [submit, 'to', address => ({ to: [{ address }] })],
            [submit, 'from', address => ({ from: { address } })],
            [submit, 'envelope', address => ({ envelope: { from: address, to: [address] } })],
            [submit, 'dsn', address => ({ dsn: { id: 'x', return: 'headers', notify: ['failure'], recipient: address } })],
            [draftSubmit, 'envelope', address => ({ envelope: { from: address, to: [address] } })],
            [upload, 'cc', address => ({ cc: [{ address }] })],
            [payloadOf('POST /v1/blocklist/{listId}'), 'recipient', recipient => ({ account: 'example', recipient })],
            [removeQuery, 'recipient', recipient => ({ recipient })]
        ];

        for (const [schema, key, build] of cases) {
            assert.equal(errorsAt(schema, build(long), key).length, 0, `${key} accepts a 65 octet local part`);
            assert.ok(errorsAt(schema, build(tooLong), key).length > 0, `${key} still caps the whole address`);
            assert.ok(errorsAt(schema, build(malformed), key).length > 0, `${key} still checks the syntax`);
        }
    });
});
