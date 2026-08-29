'use strict';

// The account page's "Download stored logs" and "Clear stored logs" entries must reflect whether
// the account actually has stored log entries. Neither route refuses an empty list: the download
// answers with a placeholder line ("No logs found for ...") rather than a 404, and the flush
// deletes a key that is not there. So an operator who clicks either gets a no-op dressed as work.
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

// The two log entries, whichever attributes they carry
const entryOf = (html, id) => (new RegExp(`<a[^>]*id="${id}"[^>]*>`).exec(html) || [])[0];
const downloadEntryOf = html => entryOf(html, 'download-logs');
const flushEntryOf = html => entryOf(html, 'flush-logs');

// The note that says why the two entries are inert. A disabled entry is out of hit testing, so it
// cannot carry a tooltip of its own, and this line is the only thing that explains the state.
const noteShown = html => {
    const note = (/<li[^>]*id="no-stored-logs"[^>]*>/.exec(html) || [])[0];
    assert.ok(note, 'the note must be rendered in both states');
    return !/\bhidden\b/.test(note);
};

// The whole "nothing stored" state of the menu, asserted the same way wherever it is reached from
const assertNoStoredLogs = (html, why) => {
    for (let [label, entry] of [
        ['download', downloadEntryOf(html)],
        ['clear', flushEntryOf(html)]
    ]) {
        assert.ok(entry, `the ${label} entry must still be rendered ${why}`);
        assert.match(entry, /dropdown-disabled/, `the ${label} entry must be disabled ${why}`);
        assert.match(entry, /aria-disabled="true"/, `the ${label} entry must be marked disabled for assistive tech ${why}`);
        assert.doesNotMatch(entry, /href=/, `the ${label} entry must not stay clickable ${why}`);
    }

    assert.ok(noteShown(html), `the menu must say why the entries are inert ${why}`);
};

registerRedisTeardown(redis);

test('The account page gates the stored log actions on there being stored logs', async t => {
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

    await t.test('a fresh account offers neither download nor clear', async () => {
        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        crumb = extractCrumbFromHtml(response.text);
        assert.ok(crumb, 'the admin page must carry a CSRF crumb');

        assertNoStoredLogs(response.text, 'on an account that never logged anything');
    });

    await t.test('stored entries enable it even while logging is switched off', async () => {
        await redis.rpush(logKey, msgpack.encode({ msg: 'stored log line', account, cid: 'test-cid' }));

        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        // Logging has never been enabled for this account, so this is the case the gate exists to
        // get right: the switch says nothing about whether entries are stored.
        assert.match(response.text, /id="toggle-logs"[^>]*>Enable logging</, 'logging must still be switched off');

        const entry = downloadEntryOf(response.text);
        assert.doesNotMatch(entry, /dropdown-disabled/, 'the download entry must be enabled once entries exist');
        assert.match(entry, new RegExp(`href="/admin/accounts/${account}/logs\\.txt"`), 'and must point at the download route');

        assert.doesNotMatch(flushEntryOf(response.text), /dropdown-disabled/, 'and so must the clear entry');
        assert.ok(!noteShown(response.text), 'and the note explaining the inert state is hidden');
    });

    await t.test('and the download really does carry them', async () => {
        // Proves the seeded shape is the shape production reads back, so the gate above cannot
        // drift away from what the download actually serves.
        const response = await server.get(`/admin/accounts/${account}/logs.txt`).expect(200);
        assert.match(response.text, /stored log line/, 'the stored entry must be in the downloaded log');
    });

    await t.test('clearing the logs disables them again', async () => {
        const flushed = await server.post(`/admin/accounts/${account}/logs-flush`).send({ crumb }).expect(200);
        assert.strictEqual(flushed.body.success, true, `flush failed: ${JSON.stringify(flushed.body)}`);

        const response = await server.get(`/admin/accounts/${account}`).expect(200);

        assertNoStoredLogs(response.text, 'once the stored entries are cleared');
    });
});
