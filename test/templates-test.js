'use strict';

// Unit tests for lib/templates.js against the test Redis database (no live server).

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { templates } = require('../lib/templates');
const registerRedisTeardown = require('./helpers/redis-teardown');

const isNotFound = err => err.code === 'NotFound' && err.statusCode === 404;

test('Templates', async t => {
    registerRedisTeardown(redis);

    await t.test('unpackId() refuses an id shorter than the fixed header as not found', () => {
        // The documented example id decodes to 8 bytes, short of the 12-byte timestamp and
        // counter header the reads below assume; the rest are what a client can type into the path
        for (const id of ['AAAAAQAACnA', '', 'x', 'not-base64!']) {
            assert.throws(() => templates.unpackId(id), isNotFound, `id "${id}" should be refused`);
        }
    });

    await t.test('unpackId() round-trips a generated id', async () => {
        const id = await templates.generateId('tpl-account');
        const unpacked = templates.unpackId(id);

        assert.equal(unpacked.account, 'tpl-account');
        assert.ok(unpacked.counter > 0);
        assert.ok(!isNaN(new Date(unpacked.created).getTime()));
    });

    await t.test('get(), update() and del() report a malformed id as not found instead of failing', async () => {
        await assert.rejects(templates.get('AAAAAQAACnA'), isNotFound);
        await assert.rejects(templates.update('AAAAAQAACnA', { name: 'x' }), isNotFound);
        await assert.rejects(templates.del('AAAAAQAACnA'), isNotFound);
    });

    await t.test('update() keeps the stored format when the update does not name one', async () => {
        const account = 'tpl-format-account';
        const { id } = await templates.create(account, { name: 'Markdown template', format: 'markdown' }, { subject: 'Hello', text: 'Hello' });

        try {
            // A partial update: only the name changes
            await templates.update(id, { name: 'Renamed' });

            const stored = await templates.get(id);
            assert.equal(stored.name, 'Renamed');
            assert.equal(stored.format, 'markdown', 'a partial update must not reset the format');
            assert.equal(stored.content.subject, 'Hello', 'content is kept when the update carries none');

            // An explicit format still applies
            await templates.update(id, { format: 'html' }, { subject: 'Changed', text: 'Changed' });

            const changed = await templates.get(id);
            assert.equal(changed.format, 'html');
            assert.equal(changed.content.subject, 'Changed');
        } finally {
            await templates.flush(account);
        }
    });
});
