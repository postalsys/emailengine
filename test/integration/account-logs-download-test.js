'use strict';

// The account page's "Download stored logs" entry must reflect whether the account actually has
// stored log entries, because the download route answers with a placeholder line ("No logs found
// for ...") rather than a 404 when the list is empty - an operator who clicks it gets a file that
// says nothing.
//
// The gate is deliberately on the stored entries, NOT on the logging switch: entries survive
// logging being turned off, so an account with logging disabled can still have a log worth
// downloading. That distinction is what most of this test is about.
//
// Hermetic: a mock IMAP server on localhost stands in for the mail host (only so the account has
// an `imap` blob and nothing storms a closed port), and no external service is involved.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const supertest = require('supertest');
const config = require('@zone-eu/wild-config');

const { ACCESS_TOKEN, startMockImapServer, extractCrumbFromHtml } = require('./helpers');
const { redis } = require('../../lib/db');
const registerRedisTeardown = require('../helpers/redis-teardown');
const { Account } = require('../../lib/account');
const msgpack = require('../../lib/msgpack');

const baseUrl = `http://127.0.0.1:${config.api.port}`;
const server = supertest.agent(baseUrl).auth(ACCESS_TOKEN, { type: 'bearer' });

// The download entry, whichever attributes it carries
const downloadEntryOf = html => (/<a[^>]*id="download-logs"[^>]*>/.exec(html) || [])[0];

registerRedisTeardown(redis);

test('The account page gates the stored log download on there being stored logs', async t => {
    const account = `logs-${crypto.randomBytes(4).toString('hex')}`;
    const mock = await startMockImapServer();

    // The key the account logger writes to and the download route reads back, resolved through the
    // production helper so a renamed key fails this test instead of silently seeding a dead list.
    const logKey = new Account({ redis, account }).getLogKey();

    t.after(async () => {
        try {
            await server.delete(`/v1/account/${account}`);
        } catch (err) {
            // the account may not exist if the test failed early
        }
        await mock.close();
    });

    await server
        .post('/v1/account')
        .send({
            account,
            name: `Log download test (${account})`,
            email: `${account}@example.com`,
            imap: {
                host: '127.0.0.1',
                port: mock.port,
                secure: false,
                auth: { user: 'testuser', pass: 'pass' },
                resyncDelay: 3600
            }
        })
        .expect(200);

    // Minted once per run and reused from the cookie the agent carries
    let crumb;

    await t.test('a fresh account offers no download', async () => {
        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        crumb = extractCrumbFromHtml(response.text);
        assert.ok(crumb, 'the admin page must carry a CSRF crumb');

        const entry = downloadEntryOf(response.text);
        assert.ok(entry, 'the download entry must still be rendered');
        assert.match(entry, /dropdown-disabled/, 'but disabled while nothing is stored');
        assert.match(entry, /aria-disabled="true"/, 'and marked disabled for assistive tech');
        assert.doesNotMatch(entry, /href=/, 'a disabled entry must not stay clickable');
    });

    await t.test('stored entries enable it even while logging is switched off', async () => {
        await redis.rpush(logKey, msgpack.encode({ msg: 'stored log line', account, cid: 'test-cid' }));

        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        // Logging has never been enabled for this account, so this is the case the gate exists to
        // get right: the switch says nothing about whether entries are stored.
        assert.match(response.text, /id="toggle-logs"[^>]*>Enable logging</, 'logging must still be switched off');

        const entry = downloadEntryOf(response.text);
        assert.doesNotMatch(entry, /dropdown-disabled/, 'the entry must be enabled once entries exist');
        assert.match(entry, new RegExp(`href="/admin/accounts/${account}/logs\\.txt"`), 'and must point at the download route');
    });

    await t.test('and the download really does carry them', async () => {
        // Proves the seeded shape is the shape production reads back, so the gate above cannot
        // drift away from what the download actually serves.
        const response = await server.get(`/admin/accounts/${account}/logs.txt`).expect(200);
        assert.match(response.text, /stored log line/, 'the stored entry must be in the downloaded log');
    });

    await t.test('clearing the logs disables it again', async () => {
        const flushed = await server.post(`/admin/accounts/${account}/logs-flush`).send({ crumb }).expect(200);
        assert.strictEqual(flushed.body.success, true, `flush failed: ${JSON.stringify(flushed.body)}`);

        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        const entry = downloadEntryOf(response.text);
        assert.match(entry, /dropdown-disabled/, 'an emptied log must not be offered for download');
        assert.doesNotMatch(entry, /href=/, 'and must not stay clickable');
    });
});
