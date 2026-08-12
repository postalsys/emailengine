'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { lists } = require('../lib/lists');

const LIST_ID = 'lists-test.example.com';

test('Suppression list handler tests', async t => {
    t.after(() => {
        // Force exit after tests to prevent hanging on Redis connections from loaded modules
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(async () => {
        await lists.deleteList(LIST_ID);
    });

    await t.test('add() registers the list and normalizes the entry key', async () => {
        let added = await lists.add(LIST_ID, 'User@Example.com', {
            source: 'api',
            reason: 'block'
        });
        assert.equal(added, 1, 'first add reports a new entry');

        assert.equal(await lists.exists(LIST_ID), true, 'list was registered');
        assert.equal(await lists.has(LIST_ID, 'user@example.com'), true, 'stored under the normalized key');
        assert.equal(await lists.has(LIST_ID, 'USER@EXAMPLE.COM'), true, 'lookup normalizes too');

        // same address again is an update, not a new entry
        let again = await lists.add(LIST_ID, 'user@example.com', { source: 'admin' });
        assert.equal(again, 0, 'duplicate add reports an update');

        let content = await lists.listContent(LIST_ID, 0, 20);
        assert.equal(content.total, 1);
        assert.equal(content.addresses[0].source, 'admin', 'duplicate add updated the record');
        assert.equal(content.addresses[0].recipient, 'user@example.com', 'record echoes the recipient');
        assert.ok(content.addresses[0].created, 'record was stamped with a created time');
    });

    await t.test('remove() drops the entry and the emptied list', async () => {
        await lists.add(LIST_ID, 'a@example.com', { source: 'api' });
        await lists.add(LIST_ID, 'b@example.com', { source: 'api' });

        assert.equal(await lists.remove(LIST_ID, 'A@Example.com'), 1, 'removal is key-normalized');
        assert.equal(await lists.remove(LIST_ID, 'a@example.com'), 0, 'second removal is a no-op');
        assert.equal(await lists.exists(LIST_ID), true, 'list stays while entries remain');

        assert.equal(await lists.remove(LIST_ID, 'b@example.com'), 1);
        assert.equal(await lists.exists(LIST_ID), false, 'removing the last entry drops the list');
    });

    await t.test('deleteList() removes the list with all entries', async () => {
        await lists.add(LIST_ID, 'a@example.com', { source: 'api' });
        await lists.add(LIST_ID, 'b@example.com', { source: 'api' });

        assert.equal(await lists.deleteList(LIST_ID), true, 'existing list reports deletion');
        assert.equal(await lists.exists(LIST_ID), false);
        assert.equal(await redis.exists(lists.getListsContentKey(LIST_ID)), 0, 'entries hash is gone');

        assert.equal(await lists.deleteList(LIST_ID), false, 'missing list reports false');
    });

    await t.test('list() includes the registered list', async () => {
        await lists.add(LIST_ID, 'a@example.com', { source: 'api' });

        let data = await lists.list(0, 100);
        let entry = data.blocklists.find(item => item.listId === LIST_ID);
        assert.ok(entry, 'list appears in the listing');
        assert.equal(entry.count, 1);

        await lists.deleteList(LIST_ID);
    });
});
