'use strict';

// Hermetic unit tests for the Outlook/Graph mailbox listing logic. No network, no
// Redis server: the OutlookClient instance is built via Object.create() and only the
// members getMailboxListing()/resolveFolder()/createMailbox()/renameMailbox() actually
// touch are stubbed (account, oauth2UserPath, logger, an in-memory redis, request()).
//
// These tests pin the fix for slash-named Graph folders: folders whose displayName
// contains "/" (or "%") must be listed, reachable, and round-trippable via a
// percent-encoded pathName, while folders without those characters keep an identical path.

const test = require('node:test');
const assert = require('node:assert').strict;

const { OutlookClient, encodeFolderSegment, decodeFolderSegment } = require('../lib/email-client/outlook-client');

const ROOT_URL = '/me/mailFolders';
const ROOT_PAGE2_URL = '/me/mailFolders?$skiptoken=PAGE2';

// Special-use well-known name -> folder object returned by Graph. Only inbox and
// sentitems map to folders that exist in the listing; the rest resolve to ids that
// match nothing (exercising the "no match" path without affecting results).
const SPECIAL_USE = {
    inbox: { id: 'id-inbox', displayName: 'Inbox' },
    sentitems: { id: 'id-sent', displayName: 'Sent Items' }
};

// Root listing, split across two pages to exercise @odata.nextLink pagination.
const ROOT_PAGE_1 = [
    { id: 'id-inbox', displayName: 'Inbox', childFolderCount: 0 },
    { id: 'id-sent', displayName: 'Sent Items', childFolderCount: 0 },
    { id: 'id-archive', displayName: 'Archive', childFolderCount: 1 },
    { id: 'id-invpaid', displayName: 'Invoices/Paid', childFolderCount: 1 },
    { id: 'id-50', displayName: '50% done', childFolderCount: 0 },
    // A search folder with a slash must still be dropped by the @odata.type guard.
    { id: 'id-search', displayName: 'Search/Folder', childFolderCount: 0, '@odata.type': 'microsoft.graph.mailSearchFolder' }
];

const ROOT_PAGE_2 = [
    { id: 'id-abc', displayName: 'A/B%C', childFolderCount: 0 },
    { id: 'id-reports', displayName: 'Reports', childFolderCount: 1 }
];

const CHILDREN = {
    'id-archive': [{ id: 'id-2024', displayName: '2024', childFolderCount: 0 }],
    'id-invpaid': [{ id: 'id-q1', displayName: 'Q1', childFolderCount: 0 }],
    'id-reports': [{ id: 'id-final', displayName: '2024/Final', childFolderCount: 0 }]
};

// Return a deep copy so getMailboxListing() (which mutates entries with pathName, etc.)
// cannot contaminate the shared fixtures across calls/tests.
function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

// Minimal in-memory Redis covering the hash ops getMailboxListing/resolveFolder use.
function makeRedis() {
    const store = new Map();
    return {
        store,
        async hget(key, field) {
            const hash = store.get(key);
            return hash && hash.has(field) ? hash.get(field) : null;
        },
        async hset(key, field, value) {
            if (!store.has(key)) {
                store.set(key, new Map());
            }
            store.get(key).set(field, value);
        },
        async hdel(key, field) {
            if (store.has(key)) {
                store.get(key).delete(field);
            }
        }
    };
}

// Build a client whose request() serves the fixture Graph tree. The optional `calls`
// array records every request for assertions on create/rename payloads.
function makeListingClient(options) {
    options = options || {};
    const calls = [];
    const client = Object.create(OutlookClient.prototype);
    client.account = 'testaccount';
    client.oauth2UserPath = 'me';
    client.logger = { error() {}, warn() {}, info() {}, debug() {}, trace() {} };
    client.redis = options.redis || makeRedis();
    client.calls = calls;

    client.request = async (url, method, payload) => {
        calls.push({ url, method, payload });

        // Special-use resolution: /me/mailFolders/<well-known-name>
        const special = url.match(/^\/me\/mailFolders\/(deleteditems|drafts|inbox|junkemail|sentitems)$/);
        if (special) {
            const key = special[1];
            return clone(SPECIAL_USE[key] || { id: `id-${key}`, displayName: key });
        }

        // Root listing page 1 (with a nextLink to page 2)
        if (url === ROOT_URL) {
            return { value: clone(ROOT_PAGE_1), '@odata.nextLink': ROOT_PAGE2_URL };
        }

        // Root listing page 2
        if (url === ROOT_PAGE2_URL) {
            return { value: clone(ROOT_PAGE_2) };
        }

        // Child folders: /me/mailFolders/<id>/childFolders
        const child = url.match(/^\/me\/mailFolders\/([^/]+)\/childFolders$/);
        if (child) {
            return { value: clone(CHILDREN[child[1]] || []) };
        }

        throw new Error(`Unexpected request URL in test stub: ${url}`);
    };

    return client;
}

// Index a listing by folder id for convenient assertions.
function byId(listing) {
    const map = new Map();
    for (const entry of listing) {
        map.set(entry.id, entry);
    }
    return map;
}

test('Outlook mailbox listing - slash/percent folder handling', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('lists slash-named and percent-named folders with encoded paths', async () => {
        const client = makeListingClient();
        const listing = await client.getMailboxListing();
        const map = byId(listing);

        // Normal folders are byte-for-byte unchanged (no-regression invariant).
        assert.strictEqual(map.get('id-archive').pathName, 'Archive');
        assert.strictEqual(map.get('id-2024').pathName, 'Archive/2024');
        assert.strictEqual(map.get('id-2024').parentPath, 'Archive');

        // Slash in the name is percent-encoded inside the segment.
        assert.strictEqual(map.get('id-invpaid').pathName, 'Invoices%2FPaid');

        // Children of a slash-named folder are reachable, with an encoded prefix.
        assert.strictEqual(map.get('id-q1').pathName, 'Invoices%2FPaid/Q1');
        assert.strictEqual(map.get('id-q1').parentPath, 'Invoices%2FPaid');

        // Percent in the name is encoded too.
        assert.strictEqual(map.get('id-50').pathName, '50%25 done');

        // Both percent and slash in one segment.
        assert.strictEqual(map.get('id-abc').pathName, 'A%2FB%25C');

        // A slash in a deep leaf under a normal parent.
        assert.strictEqual(map.get('id-final').pathName, 'Reports/2024%2FFinal');
        assert.strictEqual(map.get('id-final').parentPath, 'Reports');
    });

    await t.test('drops non-mailFolder types even when the name has a slash', async () => {
        const client = makeListingClient();
        const listing = await client.getMailboxListing();
        assert.strictEqual(
            listing.find(entry => entry.id === 'id-search'),
            undefined
        );
    });

    await t.test('paginated folders (page 2) are included', async () => {
        const client = makeListingClient();
        const listing = await client.getMailboxListing();
        const map = byId(listing);
        // id-abc and id-reports live on page 2 (returned via @odata.nextLink).
        assert.ok(map.has('id-abc'));
        assert.ok(map.has('id-reports'));
        // 10 real folders survive (6 page-1 + 2 page-2 + 3 children - 1 search folder).
        assert.strictEqual(listing.length, 10);
    });

    await t.test('special-use folders keep their tag and a normal path', async () => {
        const client = makeListingClient();
        const listing = await client.getMailboxListing();
        const map = byId(listing);
        assert.strictEqual(map.get('id-inbox').specialUse, '\\Inbox');
        assert.strictEqual(map.get('id-inbox').pathName, 'Inbox');
        assert.strictEqual(map.get('id-sent').specialUse, '\\Sent');
        assert.strictEqual(map.get('id-sent').pathName, 'Sent Items');
    });

    await t.test('resolveFolder round-trips every entry by pathName and by id', async () => {
        const client = makeListingClient();
        const listing = await client.getMailboxListing();

        for (const entry of listing) {
            const byPath = await client.resolveFolder(entry.pathName);
            assert.ok(byPath, `resolveFolder by pathName failed for ${entry.pathName}`);
            assert.strictEqual(byPath.id, entry.id, `wrong folder for pathName ${entry.pathName}`);

            const byIdResult = await client.resolveFolder(entry.id, { byId: true });
            assert.ok(byIdResult, `resolveFolder by id failed for ${entry.id}`);
            assert.strictEqual(byIdResult.id, entry.id);
        }
    });

    await t.test('resolveFolder reaches a child of a slash-named folder', async () => {
        const client = makeListingClient();
        const resolved = await client.resolveFolder('Invoices%2FPaid/Q1');
        assert.ok(resolved);
        assert.strictEqual(resolved.id, 'id-q1');
    });
});

test('Outlook mailbox createMailbox/renameMailbox - leaf decode at Graph boundary', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('createMailbox decodes the leaf for Graph and re-encodes the returned path', async () => {
        const client = makeListingClient();
        client.prepare = async () => {};
        // Avoid the fire-and-forget cache refresh hitting the stub after the test.
        client.listMailboxes = async () => {};
        // Graph echoes the literal display name it stored.
        client.request = async (url, method, payload) => {
            client.calls.push({ url, method, payload });
            if (method === 'post' && url === '/me/mailFolders') {
                return { id: 'id-new', displayName: payload.displayName };
            }
            throw new Error(`Unexpected request URL in test stub: ${url}`);
        };

        const result = await client.createMailbox('Invoices%2FPaid');

        const post = client.calls.find(c => c.method === 'post');
        assert.ok(post, 'expected a POST to create the folder');
        // Graph must receive the literal name, not the encoded one.
        assert.strictEqual(post.payload.displayName, 'Invoices/Paid');
        // The returned path is re-encoded, matching what the listing would report.
        assert.strictEqual(result.path, 'Invoices%2FPaid');
        assert.strictEqual(result.created, true);
    });

    await t.test('renameMailbox decodes the new leaf name for the Graph PATCH', async () => {
        const redis = makeRedis();
        // Seed the cached listing so resolveFolder() finds the source folder.
        await redis.hset('iac:testaccount', 'outlookMailboxListing', JSON.stringify([{ id: 'id-src', pathName: 'OldName', displayName: 'OldName' }]));

        const client = makeListingClient({ redis });
        client.prepare = async () => {};
        client.listMailboxes = async () => {};
        client.request = async (url, method, payload) => {
            client.calls.push({ url, method, payload });
            if (method === 'patch' && url === '/me/mailFolders/id-src') {
                return { id: 'id-src', displayName: payload.displayName };
            }
            throw new Error(`Unexpected request URL in test stub: ${url}`);
        };

        const result = await client.renameMailbox('OldName', 'New%2FName');

        const patch = client.calls.find(c => c.method === 'patch');
        assert.ok(patch, 'expected a PATCH to rename the folder');
        // Graph must receive the literal new name.
        assert.strictEqual(patch.payload.displayName, 'New/Name');
        // The returned newPath stays encoded.
        assert.strictEqual(result.newPath, 'New%2FName');
        assert.strictEqual(result.renamed, true);
    });
});

test('Outlook folder segment encode/decode helpers', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('encodes "%" and "/" in the documented order', async () => {
        assert.strictEqual(encodeFolderSegment('A/B'), 'A%2FB');
        assert.strictEqual(encodeFolderSegment('50% done'), '50%25 done');
        assert.strictEqual(encodeFolderSegment('A/B%C'), 'A%2FB%25C');
        assert.strictEqual(encodeFolderSegment('%2F'), '%252F');
        assert.strictEqual(encodeFolderSegment('plain'), 'plain');
        assert.strictEqual(encodeFolderSegment(''), '');
    });

    await t.test('decodes back to the literal name', async () => {
        assert.strictEqual(decodeFolderSegment('A%2FB'), 'A/B');
        assert.strictEqual(decodeFolderSegment('50%25 done'), '50% done');
        assert.strictEqual(decodeFolderSegment('A%2FB%25C'), 'A/B%C');
        assert.strictEqual(decodeFolderSegment('%252F'), '%2F');
    });

    await t.test('round-trips decode(encode(x)) === x for tricky names', async () => {
        const names = ['A/B', '50% done', '%2F', '%25', '%252F', 'a/b%c/d', '', 'plain', 'Invoices/Paid', '100%', '/', '%'];
        for (const name of names) {
            assert.strictEqual(decodeFolderSegment(encodeFolderSegment(name)), name, `round-trip failed for ${JSON.stringify(name)}`);
        }
    });

    await t.test('returns non-string input unchanged (exception safety)', async () => {
        for (const value of [null, undefined, 5, true, { a: 1 }]) {
            assert.strictEqual(encodeFolderSegment(value), value);
            assert.strictEqual(decodeFolderSegment(value), value);
        }
    });
});
