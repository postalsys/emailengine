'use strict';

// The account field of the admin token-mint payload, which two pages post by hand.
//
// This exists because of a shipped defect: the MCP page's connection generator sent
// `account: null` for "every account on the instance", the reading that any JSON author would
// pick - and joi refused it, so the feature's headline path answered 400 in its default
// configuration. views/tokens/new.hbs had always posted '' instead, which is what the schema
// accepts, but nothing recorded that the two spellings are not interchangeable.

const test = require('node:test');
const assert = require('node:assert').strict;

const Joi = require('joi');

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { accountIdSchema } = require('../lib/schemas');

// Requiring lib/schemas pulls in the Redis handles that keep the event loop alive.
registerRedisTeardown(redis);

// The shape both POST /admin/tokens/new and POST /v1/tokens declare for the field.
const schema = Joi.object({ account: accountIdSchema.default(null) });

test('admin token mint payload', async t => {
    await t.test('an empty string means "not bound to an account"', () => {
        // `.empty('')` converts it to undefined, which the default then fills in
        const { error, value } = schema.validate({ account: '' });
        assert.ifError(error);
        assert.equal(value.account, null);
    });

    await t.test('an omitted account means the same', () => {
        const { error, value } = schema.validate({});
        assert.ifError(error);
        assert.equal(value.account, null);
    });

    await t.test('an explicit null is refused, so no page may post one', () => {
        // `.default(null)` sets the value the handler sees; it does not make null valid INPUT.
        // Any page that posts JSON has to send '' (or omit the key) to mean unbound.
        const { error } = schema.validate({ account: null });
        assert.ok(error, 'account: null must not validate');
        assert.match(error.message, /must be a string/);
    });
});
