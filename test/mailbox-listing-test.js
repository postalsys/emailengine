'use strict';

// Mailbox listing tests.
//
// These used to be "simulate what getCurrentListing does" blocks that re-implemented the
// comparison, the Redis pipeline merge and the Gmail label cache inside the test file, so none
// of them could fail when the production code changed. They now drive the real code:
//
//   * lib/email-client/imap/listing-diff.js  - the pure new/changed/deleted comparison and the
//     stored-listing encode/decode that IMAPClient.getCurrentListing() runs on every sync pass
//   * IMAPClient.getCurrentListing()         - the sync pass itself, reached through the
//     prototype with the LIST call and the per-folder clear stubbed
//   * Account.getMailboxListing()            - the batched Redis read that backs
//     GET /v1/account/{account}/mailboxes and the admin folder pickers
//   * Mailbox.clear()                        - the folder teardown, whose removal of the stored
//     listing entry is also the claim to announce the deletion exactly once
//   * GmailClient.listMailboxes()            - the 60 second detailed-label cache that spares
//     one API call per label
//
// lib/db is stubbed out before any production import so nothing opens a real Redis connection.

const test = require('node:test');
const assert = require('node:assert').strict;
const msgpack = require('../lib/msgpack');

// --- Mock setup ---

let mockRedisData = {};
let pipelineCalls = [];
// Set to a path to make that key's pipeline entry come back as an error, the way ioredis
// reports a per-command failure inside an otherwise successful pipeline.
let pipelineErrorKeys = new Set();

// Writes hash fields the way a real round trip through Redis does. ioredis serializes an object
// argument with Object.keys() and rebuilds the reply with Object.defineProperty (see the hgetall
// reply transformer in node_modules/ioredis/built/Command.js), so a field literally named
// __proto__ survives. A plain assignment or Object.assign() here would silently drop it and hide
// the very bug these tests cover.
function assignHashFields(target, data) {
    for (const field of Object.keys(data)) {
        Object.defineProperty(target, field, { value: data[field], configurable: true, enumerable: true, writable: true });
    }
}

function createMockRedis() {
    return {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hset: async (key, field, value) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            assignHashFields(mockRedisData[key], { [field]: value });
        },
        hgetall: async key => mockRedisData[key] || null,
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async key => mockRedisData[key] || {},
        hgetBuffer: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            assignHashFields(mockRedisData[key], data);
        },
        multi: () => {
            const ops = [];
            return {
                hmset(key, data) {
                    ops.push({ cmd: 'hmset', key, data });
                    return this;
                },
                hset() {
                    return this;
                },
                hdel(key, field) {
                    ops.push({ cmd: 'hdel', key, field });
                    return this;
                },
                del(...keys) {
                    for (const key of keys) {
                        ops.push({ cmd: 'del', key });
                    }
                    return this;
                },
                expire() {
                    return this;
                },
                srem() {
                    return this;
                },
                zadd() {
                    return this;
                },
                hincrby() {
                    return this;
                },
                async exec() {
                    // Redis refuses an HMSET with no fields at queue time, and EXEC then
                    // discards the entire transaction: the DEL queued next to it does not run
                    // either, and ioredis rejects. Reproduced here so a caller that queues an
                    // empty write is caught by these tests rather than in production.
                    if (ops.some(op => op.cmd === 'hmset' && !Object.keys(op.data).length)) {
                        throw new Error('EXECABORT Transaction discarded because of previous errors.');
                    }

                    // Replies come back as ioredis reports them, one [err, result] pair per
                    // queued command in order. Mailbox.clear() reads the HDEL count out of
                    // position 0 as its claim to announce the deletion, so a stub returning
                    // an empty array would suppress every mailboxDeleted notification here.
                    const replies = [];
                    for (const op of ops) {
                        if (op.cmd === 'hmset') {
                            if (!mockRedisData[op.key]) mockRedisData[op.key] = {};
                            assignHashFields(mockRedisData[op.key], op.data);
                            replies.push([null, 'OK']);
                        } else if (op.cmd === 'del') {
                            replies.push([null, op.key in mockRedisData ? 1 : 0]);
                            delete mockRedisData[op.key];
                        } else if (op.cmd === 'hdel') {
                            const existed = !!mockRedisData[op.key] && op.field in mockRedisData[op.key];
                            if (existed) {
                                delete mockRedisData[op.key][op.field];
                            }
                            replies.push([null, existed ? 1 : 0]);
                        }
                    }
                    return replies;
                }
            };
        },
        pipeline: () => {
            const ops = [];
            pipelineCalls = [];
            return {
                hgetall(key) {
                    ops.push({ cmd: 'hgetall', key });
                    pipelineCalls.push(key);
                    return this;
                },
                async exec() {
                    let results = [];
                    for (const op of ops) {
                        if (op.cmd === 'hgetall') {
                            if (pipelineErrorKeys.has(op.key)) {
                                results.push([new Error('Redis error'), null]);
                            } else {
                                results.push([null, mockRedisData[op.key] || null]);
                            }
                        }
                    }
                    return results;
                }
            };
        },
        ttl: async () => 3600,
        eval: async () => 1,
        smembers: async () => [],
        srem: async () => {},
        exists: async key => (mockRedisData[key] ? 1 : 0),
        get: async () => null,
        set: async () => 'OK',
        scan: async () => ['0', []],
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate: function () {
            return createMockRedis();
        }
    };
}

const mockRedis = createMockRedis();
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {},
    getJob: async () => null
};

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: mockRedis,
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        documentsQueue: mockQueue,
        exportQueue: mockQueue,
        getFlowProducer: () => ({}),
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const getSecretPath = require.resolve('../lib/get-secret');
require.cache[getSecretPath] = {
    id: getSecretPath,
    filename: getSecretPath,
    loaded: true,
    parent: null,
    children: [],
    exports: async () => null
};

const registerRedisTeardown = require('./helpers/redis-teardown');
const { getMailboxStatusKey, normalizePath } = require('../lib/tools');
const { REDIS_PREFIX, MAILBOX_DELETED_NOTIFY } = require('../lib/consts');
const {
    decodeStoredListing,
    diffMailboxListing,
    buildStoredListingObject,
    matchesListingEntry,
    configuredPathIndex
} = require('../lib/email-client/imap/listing-diff');
const { samePath } = require('../lib/utils/mailbox-path');
const { Account } = require('../lib/account');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { Mailbox } = require('../lib/email-client/imap/mailbox');

// One ROOT after-hook for the whole file. Registering the force-exit on the first suite instead
// would arm a 1s process.exit() timer while the later suites are still running, so on a loaded
// runner they would vanish from a green report.
registerRedisTeardown();

const ACCOUNT = 'test-account';
const accountKey = `${REDIS_PREFIX}iad:${ACCOUNT}`;
const mailboxListKey = `${REDIS_PREFIX}ial:${ACCOUNT}`;

// Seeds the stored mailbox listing the way getCurrentListing() persists it
function seedStoredListing(entries) {
    mockRedisData[mailboxListKey] = buildStoredListingObject(entries);
}

// Seeds a plain IMAP account whose state keeps getMailboxListing() on the stored-listing path
// (no LIST round trip): not CONNECTED, not UNSET, not INIT, and the listing key exists.
function seedAccount(state = 'syncing') {
    mockRedisData[accountKey] = { account: ACCOUNT, state };
}

function createAccountObject(callImpl) {
    return new Account({
        redis: mockRedis,
        account: ACCOUNT,
        call: callImpl || (async () => ({})),
        secret: 'test-secret'
    });
}

test('Mailbox listing comparison (listing-diff)', async t => {
    await t.test('detects new, changed and deleted mailboxes in one pass', () => {
        const stored = [
            { path: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'OldFolder', delimiter: '/', specialUseSource: undefined, noInferiors: false }
        ];

        const listing = [
            // delimiter changed
            { path: 'INBOX', delimiter: '.', specialUseSource: 'extension', noInferiors: false },
            // unchanged
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            // new
            { path: 'NewFolder', delimiter: '/', specialUseSource: undefined, noInferiors: false }
        ];

        const { hasChanges, deletedEntries } = diffMailboxListing(listing, stored);

        assert.strictEqual(hasChanges, true);
        assert.deepStrictEqual(
            listing.filter(entry => entry.isNew).map(entry => entry.path),
            ['NewFolder'],
            'only the unseen folder carries the one-shot isNew flag that triggers mailboxNew'
        );
        assert.deepStrictEqual(
            deletedEntries.map(entry => entry.path),
            ['OldFolder']
        );
    });

    await t.test('identical listings report no changes and no isNew flags', () => {
        const entries = () => [
            { path: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false },
            { path: 'Archive/2024', delimiter: '/', specialUseSource: undefined, noInferiors: false }
        ];

        const listing = entries();
        const { hasChanges, deletedEntries } = diffMailboxListing(listing, entries());

        assert.strictEqual(hasChanges, false, 'a no-op sync must not rewrite the listing hash');
        assert.deepStrictEqual(deletedEntries, []);
        assert.ok(!listing.some(entry => entry.isNew));
    });

    await t.test('INBOX is matched case-insensitively so a re-cased server does not churn', () => {
        // Servers are inconsistent about "INBOX" vs "Inbox"; normalizePath() folds the case.
        // Without it every sync would report the folder as both deleted and new, re-emitting
        // mailboxNew and wiping the message index each pass.
        const listing = [{ path: 'Inbox', delimiter: '/', specialUseSource: 'extension', noInferiors: false }];
        const { hasChanges, deletedEntries } = diffMailboxListing(listing, [
            { path: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false }
        ]);

        assert.strictEqual(hasChanges, false);
        assert.deepStrictEqual(deletedEntries, []);
        assert.ok(!listing[0].isNew);
    });

    await t.test('case matters for every other folder name', () => {
        // Only INBOX is case-insensitive per RFC 3501; "Sent" and "sent" are distinct folders.
        const listing = [{ path: 'sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false }];
        const { hasChanges, deletedEntries } = diffMailboxListing(listing, [
            { path: 'Sent', delimiter: '/', specialUseSource: 'extension', noInferiors: false }
        ]);

        assert.strictEqual(hasChanges, true);
        assert.strictEqual(listing[0].isNew, true);
        assert.deepStrictEqual(
            deletedEntries.map(e => e.path),
            ['Sent']
        );
    });

    await t.test('every entry is new when nothing is stored yet (first sync)', () => {
        const listing = [
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'Sent', delimiter: '/', noInferiors: false },
            { path: 'Drafts', delimiter: '/', noInferiors: false }
        ];

        const { hasChanges, deletedEntries } = diffMailboxListing(listing, []);

        assert.strictEqual(hasChanges, true);
        assert.deepStrictEqual(deletedEntries, []);
        assert.strictEqual(listing.filter(entry => entry.isNew).length, 3);
    });

    await t.test('folder names that collide with Object.prototype keys are handled', () => {
        // The lookup is a Map, not a plain object, so "constructor"/"__proto__" folders can not
        // resolve to inherited properties and be mistaken for already-known folders.
        const listing = [
            { path: '__proto__', delimiter: '/', noInferiors: false },
            { path: 'constructor', delimiter: '/', noInferiors: false },
            { path: 'toString', delimiter: '/', noInferiors: false },
            { path: 'Folder with spaces & symbols!', delimiter: '/', noInferiors: false }
        ];

        const { hasChanges } = diffMailboxListing(listing, []);

        assert.strictEqual(hasChanges, true);
        assert.strictEqual(listing.filter(entry => entry.isNew).length, 4, 'every prototype-named folder must be reported as new exactly once');
    });

    await t.test('a change in any persisted field alone counts as a change', () => {
        // Everything buildStoredListingObject() persists has to be compared. The mailboxes API
        // answers from the stored hash, so a field that changes without setting hasChanges is
        // never written back and the stale value is served until an unrelated folder happens to
        // be created or deleted. `subscribed` is the one a client can move on demand: PUT
        // /v1/account/{account}/mailbox issues UNSUBSCRIBE and refreshes the listing expecting
        // exactly this to be picked up.
        const base = {
            path: 'Archive',
            name: 'Archive',
            delimiter: '/',
            specialUse: '\\Archive',
            specialUseSource: 'extension',
            listed: true,
            subscribed: true,
            noInferiors: false
        };

        for (let [field, changed] of [
            ['subscribed', false],
            ['listed', false],
            ['specialUse', '\\Junk'],
            ['name', 'Archived'],
            ['delimiter', '.'],
            ['specialUseSource', 'name'],
            ['noInferiors', true]
        ]) {
            const { hasChanges } = diffMailboxListing([Object.assign({}, base, { [field]: changed })], [Object.assign({}, base)]);
            assert.strictEqual(hasChanges, true, `a changed ${field} must be persisted`);
        }

        // and the same entry twice still must not churn
        assert.strictEqual(diffMailboxListing([Object.assign({}, base)], [Object.assign({}, base)]).hasChanges, false);
    });

    await t.test('deeply nested paths are compared by their full path', () => {
        const stored = [{ path: 'A/B/C/D/E', delimiter: '/', noInferiors: false }];

        const unchanged = diffMailboxListing([{ path: 'A/B/C/D/E', delimiter: '/', noInferiors: false }], stored);
        assert.strictEqual(unchanged.hasChanges, false);

        const moved = diffMailboxListing([{ path: 'A/B/C/D/F', delimiter: '/', noInferiors: false }], stored);
        assert.strictEqual(moved.hasChanges, true);
        assert.deepStrictEqual(
            moved.deletedEntries.map(e => e.path),
            ['A/B/C/D/E']
        );
    });

    await t.test('a large folder count is compared without a quadratic scan', () => {
        // Shared/public namespaces routinely list thousands of folders. The Map/Set lookups keep
        // this linear; a nested scan would take seconds here and stall the sync loop.
        const stored = [];
        const listing = [];
        for (let i = 0; i < 5000; i++) {
            stored.push({ path: `Folder${i}`, delimiter: '/', noInferiors: false });
            listing.push({ path: `Folder${i}`, delimiter: '/', noInferiors: false });
        }
        // one added, one removed
        listing.push({ path: 'BrandNew', delimiter: '/', noInferiors: false });
        listing.splice(0, 1);

        const started = process.hrtime.bigint();
        const { hasChanges, deletedEntries } = diffMailboxListing(listing, stored);
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

        assert.strictEqual(hasChanges, true);
        assert.deepStrictEqual(
            deletedEntries.map(e => e.path),
            ['Folder0']
        );
        assert.deepStrictEqual(
            listing.filter(e => e.isNew).map(e => e.path),
            ['BrandNew']
        );
        assert.ok(elapsedMs < 1000, `comparing 5000 folders took ${elapsedMs.toFixed(1)}ms, expected well under 1s`);
    });
});

// The comparisons that decide which listed folders an account watches. Account `path` and
// `subconnections` entries are stored exactly as the API received them, while the listing keeps
// whatever spelling the server answered with, so every one of these matches config against a
// server string and every one of them used to do it with a raw ===.
test('Configured path matching (listing-diff)', async t => {
    const inbox = { path: 'Inbox', specialUse: '\\Inbox' };
    const sent = { path: 'Sent', specialUse: '\\Sent' };

    await t.test('samePath folds the case of INBOX and nothing else', () => {
        assert.equal(samePath('INBOX', 'Inbox'), true);
        assert.equal(samePath('inbox', 'INBOX'), true);
        assert.equal(samePath('Sent', 'sent'), false, 'every other folder name is case sensitive on IMAP');
        assert.equal(samePath('INBOX/Sub', 'inbox/Sub'), false, 'only the bare name is folded, matching how the listing is keyed');
    });

    await t.test('samePath refuses to match a missing path against another missing path', () => {
        // normalizePath() hands back what it was given, so without the type guard two absent
        // paths would compare equal and every folder would look like every other one
        assert.equal(samePath(undefined, undefined), false);
        assert.equal(samePath('INBOX', undefined), false);
    });

    await t.test('a configured path selects the folder whatever case the server reports it in', () => {
        assert.equal(matchesListingEntry('INBOX', inbox), true, 'the operator typed INBOX, the server answered Inbox');
        assert.equal(matchesListingEntry('INBOX', sent), false);
    });

    await t.test('a special-use token is matched literally', () => {
        // Tokens are a fixed vocabulary, never a server spelling, so they must not be normalized
        assert.equal(matchesListingEntry('\\Sent', sent), true);
        assert.equal(matchesListingEntry('\\sent', sent), false);
        assert.equal(matchesListingEntry('\\Inbox', inbox), true);
    });

    await t.test('a folder with no special use can not be selected by an absent configuration entry', () => {
        assert.equal(matchesListingEntry('INBOX', { path: 'Archive' }), false);
        assert.equal(matchesListingEntry(undefined, { path: 'Archive' }), false, 'two absent values must not read as a token match');
    });

    await t.test('configuredPathIndex reports the position that orders the main folder', () => {
        assert.equal(configuredPathIndex(['Archive', 'INBOX'], inbox), 1);
        assert.equal(configuredPathIndex(['Archive'], inbox), -1, 'a folder nothing selects is not monitored');
        assert.equal(configuredPathIndex(['\\Sent'], sent), 0, 'a token selects by position too');
    });
});

test('Stored mailbox listing encode/decode (listing-diff)', async t => {
    await t.test('only the persisted field subset is stored, keyed by normalized path', () => {
        const stored = buildStoredListingObject([
            {
                path: 'Inbox',
                name: 'Inbox',
                delimiter: '/',
                specialUse: '\\Inbox',
                specialUseSource: 'extension',
                listed: true,
                subscribed: true,
                noInferiors: false,
                // derived state that must NOT be persisted in the listing hash
                flags: new Set(['\\HasNoChildren']),
                status: { messages: 12 },
                isNew: true
            }
        ]);

        const keys = Object.keys(stored);
        assert.deepStrictEqual(keys, ['INBOX'], 'the hash field is the normalized path');

        // Spelled out rather than compared against the production constant: asserting the
        // filter's output against the filter's own input list can never fail, and adding a
        // field to the constant would silently update the expectation.
        const decoded = msgpack.decode(stored.INBOX);
        assert.deepStrictEqual(
            Object.keys(decoded).sort(),
            ['delimiter', 'listed', 'name', 'noInferiors', 'path', 'specialUse', 'specialUseSource', 'subscribed'],
            'the persisted field set changed - confirm the new field is intended before updating this list'
        );
        assert.strictEqual(decoded.isNew, undefined, 'isNew is a one-shot in-memory flag and must never be persisted');
        assert.strictEqual(decoded.flags, undefined);
        assert.strictEqual(decoded.status, undefined);
        assert.strictEqual(decoded.specialUse, '\\Inbox');
    });

    await t.test('a round trip through decodeStoredListing preserves the compared fields', () => {
        const listing = [
            { path: 'INBOX', name: 'INBOX', delimiter: '/', specialUseSource: 'extension', noInferiors: false, listed: true, subscribed: true },
            { path: 'Archive/2024', name: '2024', delimiter: '/', specialUseSource: undefined, noInferiors: true, listed: true, subscribed: false }
        ];

        const { entries } = decodeStoredListing(buildStoredListingObject(listing));

        // A second sync against the round-tripped state must see no changes at all
        const { hasChanges, deletedEntries } = diffMailboxListing(structuredClone(listing), entries);
        assert.strictEqual(hasChanges, false, 'a persist-then-reload cycle must not look like a change');
        assert.deepStrictEqual(deletedEntries, []);
    });

    await t.test('an undecodable entry is dropped from the listing but reported as corrupt', () => {
        const stored = buildStoredListingObject([{ path: 'INBOX', delimiter: '/', noInferiors: false }]);
        stored.Broken = Buffer.from('not msgpack at all');

        const { entries, corruptPaths } = decodeStoredListing(stored);

        assert.deepStrictEqual(
            entries.map(entry => entry.path),
            ['INBOX'],
            'one corrupt hash field must not take down the listing for every other folder'
        );
        // A dropped entry is invisible to the comparison, so it can never show up as deleted
        // either. Unless the caller is told about it, the bad field survives every sync forever.
        assert.deepStrictEqual(corruptPaths, ['Broken']);
    });

    await t.test('a missing listing hash decodes to an empty array', () => {
        assert.deepStrictEqual(decodeStoredListing(null), { entries: [], corruptPaths: [] });
        assert.deepStrictEqual(decodeStoredListing(undefined), { entries: [], corruptPaths: [] });
        assert.deepStrictEqual(decodeStoredListing({}), { entries: [], corruptPaths: [] });
    });

    await t.test('a folder named __proto__ is actually persisted in the hash', () => {
        // Assigning to listingObject['__proto__'] on a plain object hits the Object.prototype
        // setter instead of creating an own property, so Object.keys() - which is how ioredis
        // serializes the hash - omitted the folder entirely. It then looked unseen on every
        // following sync: another mailboxNew plus a full initial sync of that folder, forever.
        const stored = buildStoredListingObject([
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: '__proto__', delimiter: '/', noInferiors: false },
            { path: 'constructor', delimiter: '/', noInferiors: false }
        ]);

        assert.deepStrictEqual(Object.keys(stored).sort(), ['INBOX', '__proto__', 'constructor'], 'every folder must reach the hash written to Redis');

        const { entries } = decodeStoredListing(stored);
        assert.deepStrictEqual(entries.map(entry => entry.path).sort(), ['INBOX', '__proto__', 'constructor'], 'and must be read back as an ordinary folder');

        // The round trip has to be stable, otherwise the folder churns on every sync pass.
        const { hasChanges } = diffMailboxListing(
            [
                { path: 'INBOX', delimiter: '/', noInferiors: false },
                { path: '__proto__', delimiter: '/', noInferiors: false },
                { path: 'constructor', delimiter: '/', noInferiors: false }
            ],
            entries
        );
        assert.strictEqual(hasChanges, false);
    });

    await t.test('an empty listing builds an empty hash', () => {
        // HMSET refuses an empty hash and that error aborts the surrounding MULTI, taking the
        // DEL down with it. getCurrentListing() must not queue the write in this state.
        assert.deepStrictEqual(Object.keys(buildStoredListingObject([])), []);
    });
});

test('Account.getMailboxListing', async t => {
    t.beforeEach(() => {
        mockRedisData = {};
        pipelineCalls = [];
        pipelineErrorKeys = new Set();
    });

    await t.test('reads every folder status hash in a single pipeline', async () => {
        // One Redis round trip regardless of folder count - a per-folder hgetall makes the
        // mailboxes endpoint scale with latency times folder count.
        seedAccount();
        const paths = ['INBOX', 'Sent', 'Drafts', 'Trash'];
        seedStoredListing(paths.map(path => ({ path, delimiter: '/', noInferiors: false })));

        const mailboxes = await createAccountObject().getMailboxListing({});

        assert.strictEqual(mailboxes.length, 4);
        assert.deepStrictEqual(
            pipelineCalls.sort(),
            paths.map(path => getMailboxStatusKey(ACCOUNT, path)).sort(),
            'every folder must be fetched through the pipeline'
        );
    });

    await t.test('merges the stored listing with the per-folder counters', async () => {
        seedAccount();
        seedStoredListing([
            { path: 'INBOX', name: 'INBOX', delimiter: '/', specialUse: '\\Inbox', noInferiors: false },
            { path: 'Sent', name: 'Sent', delimiter: '/', specialUse: '\\Sent', noInferiors: false }
        ]);
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'INBOX')] = { path: 'INBOX', messages: '42', uidNext: '99' };
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'Sent')] = { path: 'Sent', messages: '7', uidNext: '8' };

        const mailboxes = await createAccountObject().getMailboxListing({});
        const inbox = mailboxes.find(mailbox => mailbox.path === 'INBOX');

        assert.strictEqual(inbox.messages, 42, 'counters are stored as strings and must come back as numbers');
        assert.strictEqual(inbox.uidNext, 99);
        assert.strictEqual(inbox.specialUse, '\\Inbox', 'fields from the stored listing survive the merge');
        assert.strictEqual(inbox.name, 'INBOX');
    });

    await t.test('a folder with no status hash yet is still listed', async () => {
        // A folder discovered by LIST but not synced yet has no status hash.
        seedAccount();
        seedStoredListing([
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'NeverSynced', delimiter: '/', noInferiors: false }
        ]);
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'INBOX')] = { path: 'INBOX', messages: '5', uidNext: '6' };

        const mailboxes = await createAccountObject().getMailboxListing({});
        const neverSynced = mailboxes.find(mailbox => mailbox.path === 'NeverSynced');

        assert.ok(neverSynced, 'a folder without counters must not disappear from the listing');
        assert.strictEqual(neverSynced.messages, undefined);
        assert.strictEqual(neverSynced.uidNext, undefined);
    });

    await t.test('non-numeric and zero counter values are normalized', async () => {
        seedAccount();
        seedStoredListing([
            { path: 'Empty', delimiter: '/', noInferiors: false },
            { path: 'Garbage', delimiter: '/', noInferiors: false }
        ]);
        // An empty mailbox legitimately reports 0; a corrupt value must not surface as NaN
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'Empty')] = { path: 'Empty', messages: '0', uidNext: '1' };
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'Garbage')] = { path: 'Garbage', messages: 'not-a-number', uidNext: '' };

        const mailboxes = await createAccountObject().getMailboxListing({});
        const empty = mailboxes.find(mailbox => mailbox.path === 'Empty');
        const garbage = mailboxes.find(mailbox => mailbox.path === 'Garbage');

        assert.strictEqual(empty.messages, 0, 'an empty mailbox reports a real 0, not false');
        assert.strictEqual(empty.uidNext, 1);
        assert.strictEqual(garbage.messages, false, 'an unparseable counter degrades to false rather than NaN');
        assert.ok(!Number.isNaN(garbage.messages));
        assert.strictEqual(garbage.uidNext, false, 'an empty string counter degrades to false');
    });

    await t.test('a corrupt stored listing entry is skipped, not returned as a garbage mailbox', async () => {
        // The msgpack decoder resolves some corrupt buffers to a primitive instead of throwing.
        // Without a shape check that primitive gets boxed by Object.assign() and shipped to the caller.
        seedAccount();
        seedStoredListing([{ path: 'INBOX', delimiter: '/', noInferiors: false }]);
        mockRedisData[mailboxListKey].Broken = Buffer.from('not msgpack at all');
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'INBOX')] = { path: 'INBOX', messages: '5', uidNext: '6' };

        const mailboxes = await createAccountObject().getMailboxListing({});

        assert.deepStrictEqual(
            mailboxes.map(mailbox => mailbox.path),
            ['INBOX'],
            'the healthy folders must still be listed and the corrupt one dropped'
        );
        assert.ok(
            mailboxes.every(mailbox => typeof mailbox === 'object' && !(mailbox instanceof Number)),
            'no boxed primitive may reach the API response'
        );
    });

    await t.test('parentPath is derived for nested folders only', async () => {
        seedAccount();
        seedStoredListing([
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'Archive/2024', delimiter: '/', noInferiors: false },
            { path: 'Archive/2024/Q1', delimiter: '/', noInferiors: false }
        ]);

        const mailboxes = await createAccountObject().getMailboxListing({});
        const byPath = new Map(mailboxes.map(mailbox => [mailbox.path, mailbox]));

        assert.strictEqual(byPath.get('INBOX').parentPath, undefined, 'a top level folder has no parent');
        assert.strictEqual(byPath.get('Archive/2024').parentPath, 'Archive');
        assert.strictEqual(byPath.get('Archive/2024/Q1').parentPath, 'Archive/2024');
    });

    await t.test('a failed pipeline entry drops only that folder counters', async () => {
        seedAccount();
        seedStoredListing([
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'Sent', delimiter: '/', noInferiors: false }
        ]);
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'INBOX')] = { path: 'INBOX', messages: '10', uidNext: '50' };
        mockRedisData[getMailboxStatusKey(ACCOUNT, 'Sent')] = { path: 'Sent', messages: '3', uidNext: '4' };
        pipelineErrorKeys.add(getMailboxStatusKey(ACCOUNT, 'Sent'));

        const mailboxes = await createAccountObject().getMailboxListing({});
        const byPath = new Map(mailboxes.map(mailbox => [mailbox.path, mailbox]));

        assert.strictEqual(byPath.get('INBOX').messages, 10);
        assert.strictEqual(byPath.get('Sent').messages, undefined, 'the failed entry loses its counters');
        assert.strictEqual(byPath.get('Sent').path, 'Sent', 'but the folder itself still comes from the stored listing');
    });

    await t.test('a not-yet-initialized account is reported as NotYetConnected', async () => {
        seedAccount('init');

        await assert.rejects(
            () => createAccountObject().getMailboxListing({}),
            err => {
                assert.strictEqual(err.output.statusCode, 503);
                assert.strictEqual(err.output.payload.code, 'NotYetConnected');
                return true;
            }
        );
    });

    await t.test('an account with syncing disabled is reported as NotSyncing', async () => {
        seedAccount('unset');

        await assert.rejects(
            () => createAccountObject().getMailboxListing({}),
            err => {
                assert.strictEqual(err.output.statusCode, 503);
                assert.strictEqual(err.output.payload.code, 'NotSyncing');
                return true;
            }
        );
    });

    await t.test('status counters from a live LIST are merged onto the stored listing', async () => {
        // With ?counters=true (or a connected account) the API runs a real LIST through the IMAP
        // worker and folds its STATUS counters into the response.
        seedAccount('connected');
        seedStoredListing([
            { path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'Sent', name: 'Sent', delimiter: '/', noInferiors: false }
        ]);

        const accountObject = createAccountObject(async message => {
            assert.strictEqual(message.cmd, 'listMailboxes');
            assert.deepStrictEqual(message.options.statusQuery, { messages: true, unseen: true });
            return [
                { path: 'INBOX', status: { path: 'INBOX', messages: 120, unseen: 4 } },
                { path: 'Sent', status: { path: 'Sent', messages: 9, unseen: 0 } }
            ];
        });

        const mailboxes = await accountObject.getMailboxListing({ counters: true });
        const inbox = mailboxes.find(mailbox => mailbox.path === 'INBOX');

        assert.deepStrictEqual(inbox.status, { messages: 120, unseen: 4 }, 'the redundant path field is stripped from the status object');
        assert.strictEqual(inbox.name, 'INBOX');
    });

    await t.test('status counters survive a server that spells the inbox in mixed case', async () => {
        // The stored listing is keyed through normalizePath(), which case-folds INBOX so that a
        // server alternating "Inbox" and "INBOX" between passes does not read as a delete plus an
        // add. The live LIST result keeps the server spelling, so matching the two by raw path
        // dropped the counters for the one folder every account has.
        seedAccount('connected');
        seedStoredListing([{ path: 'Inbox', name: 'Inbox', delimiter: '/', specialUse: '\\Inbox', noInferiors: false }]);

        const accountObject = createAccountObject(async () => [{ path: 'Inbox', status: { path: 'Inbox', messages: 120, unseen: 4 } }]);

        const mailboxes = await accountObject.getMailboxListing({ counters: true });

        assert.strictEqual(mailboxes.length, 1);
        assert.deepStrictEqual(mailboxes[0].status, { messages: 120, unseen: 4 }, 'the live counters must be matched through the normalized path');
        assert.strictEqual(mailboxes[0].path, 'Inbox', 'the response keeps the spelling the server reported');
    });

    await t.test('a LIST failure surfaces as an error rather than a silently empty listing', async () => {
        seedAccount('connected');
        seedStoredListing([{ path: 'INBOX', delimiter: '/', noInferiors: false }]);

        const accountObject = createAccountObject(async () => ({ error: 'Failed to list mailboxes', statusCode: 502, code: 'ListFailed' }));

        await assert.rejects(
            () => accountObject.getMailboxListing({ counters: true }),
            err => {
                assert.strictEqual(err.output.statusCode, 502);
                assert.strictEqual(err.output.payload.code, 'ListFailed');
                return true;
            }
        );
    });
});

// Drives the REAL IMAPClient.getCurrentListing() with stubbed collaborators (the LIST round
// trip, the per-folder clear, the logger). Everything under test - the \Noselect filter, the
// empty-listing guard, the corrupt-entry purge and the Redis write - is the production method
// itself, reached through IMAPClient.prototype rather than a copy of its logic.
// `primaryDown` is the state a listing read over a pooled secondary connection can be in: the
// LIST answers, but there is no primary client, so processListing() registers nothing.
function createListingClient(list, { primaryDown = false } = {}) {
    const cleared = [];
    let closed = false;

    return {
        cleared,
        wasClosed: () => closed,
        client: {
            account: ACCOUNT,
            redis: mockRedis,
            logger: { error: () => {}, info: () => {}, debug: () => {}, trace: () => {} },
            accountObject: { loadAccountData: async () => ({ account: ACCOUNT }) },
            imapClient: primaryDown
                ? false
                : {
                      close: () => {
                          closed = true;
                      }
                  },
            checkIMAPConnection: () => true,
            getImapConnection: async () => ({ list: async () => list }),
            clearMailboxEntry: async entry => {
                cleared.push(entry.path);
            },
            getMailboxListKey: () => mailboxListKey,
            getCurrentListing: IMAPClient.prototype.getCurrentListing
        }
    };
}

function serverFolder(path, flags = ['\\HasNoChildren']) {
    return { path, name: path, delimiter: '/', flags: new Set(flags), listed: true, subscribed: true, specialUseSource: undefined };
}

test('IMAPClient.getCurrentListing', async t => {
    t.beforeEach(() => {
        mockRedisData = {};
    });

    await t.test('a listing with nothing selectable is rejected instead of clearing every folder', async () => {
        // INBOX always exists and is always selectable, so this is the same server bug as an
        // empty response. Trusting it would clear every stored folder - dropping each folder's
        // message index and firing a mailboxDeleted webhook per folder - and then abort the
        // MULTI on the empty HMSET, leaving the stored listing in place to repeat the whole
        // cycle on the next pass.
        seedStoredListing([
            { path: 'INBOX', delimiter: '/', noInferiors: false },
            { path: 'Archive', delimiter: '/', noInferiors: false }
        ]);
        const before = mockRedisData[mailboxListKey].INBOX;

        const { client, cleared, wasClosed } = createListingClient([serverFolder('Shared', ['\\Noselect']), serverFolder('Public', ['\\NonExistent'])]);

        await assert.rejects(
            () => client.getCurrentListing({}, {}),
            err => err.code === 'ServerBug'
        );

        assert.deepStrictEqual(cleared, [], 'no folder may be cleared on a listing this broken');
        assert.strictEqual(mockRedisData[mailboxListKey].INBOX, before, 'the stored listing must survive untouched');
        assert.ok(mockRedisData[mailboxListKey].Archive);
        assert.strictEqual(wasClosed(), true, 'the connection is dropped so the next pass starts clean');
    });

    await t.test('an empty listing is still rejected', async () => {
        seedStoredListing([{ path: 'INBOX', delimiter: '/', noInferiors: false }]);
        const { client, cleared } = createListingClient([]);

        await assert.rejects(
            () => client.getCurrentListing({}, {}),
            err => err.code === 'ServerBug'
        );
        assert.deepStrictEqual(cleared, []);
    });

    await t.test('a corrupt stored entry is purged even when nothing else changed', async () => {
        // The corrupt value never decodes into the comparison, so it can not be reported as a
        // deleted folder either. Without forcing the rewrite it survives every sync pass forever
        // while the mailboxes API keeps skipping that folder.
        // Seeded to match the server folder exactly, so nothing but the corrupt field can make
        // this pass report a change.
        seedStoredListing([{ path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false, listed: true, subscribed: true }]);
        mockRedisData[mailboxListKey].Broken = Buffer.from('not msgpack at all');

        const { client, cleared } = createListingClient([serverFolder('INBOX')]);

        await client.getCurrentListing({}, {});

        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX'], 'the unusable field must be gone');
        assert.deepStrictEqual(cleared, [], 'a corrupt entry is not a deleted folder');
    });

    await t.test('an unchanged listing is not rewritten', async () => {
        seedStoredListing([{ path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false, listed: true, subscribed: true }]);
        const before = mockRedisData[mailboxListKey].INBOX;

        const { client } = createListingClient([serverFolder('INBOX')]);
        await client.getCurrentListing({}, {});

        assert.strictEqual(mockRedisData[mailboxListKey].INBOX, before, 'a no-op sync must not rewrite the listing hash');
    });

    await t.test('a folder the server no longer lists is cleared and dropped from the hash', async () => {
        seedStoredListing([
            { path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false, listed: true, subscribed: true },
            { path: 'Old', name: 'Old', delimiter: '/', noInferiors: false, listed: true, subscribed: true }
        ]);

        const { client, cleared } = createListingClient([serverFolder('INBOX')]);
        const listing = await client.getCurrentListing({}, {});

        assert.deepStrictEqual(cleared, ['Old']);
        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX']);
        assert.deepStrictEqual(
            listing.map(entry => entry.path),
            ['INBOX']
        );
    });

    await t.test('non-selectable folders are dropped from the returned listing', async () => {
        const { client } = createListingClient([serverFolder('INBOX'), serverFolder('Shared', ['\\Noselect']), serverFolder('Gone', ['\\NonExistent'])]);

        const listing = await client.getCurrentListing({}, {});

        assert.deepStrictEqual(
            listing.map(entry => entry.path),
            ['INBOX'],
            'a folder the sync can not SELECT must not enter the listing'
        );
        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX']);
    });

    await t.test('a folder found while the primary is down is not recorded as seen', async () => {
        // listMailboxes() and the subconnection reconciler both list over a pooled secondary,
        // which is allowed to answer while the primary connection is down - and processListing()
        // registers nothing in that state, so recording the folder here would be the last time
        // anything noticed it.
        seedStoredListing([{ path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false, listed: true, subscribed: true }]);
        const before = mockRedisData[mailboxListKey].INBOX;

        const { client } = createListingClient([serverFolder('INBOX'), serverFolder('Created Offline')], { primaryDown: true });
        const listing = await client.getCurrentListing({}, { allowSecondary: true });

        assert.deepStrictEqual(
            listing.filter(entry => entry.isNew).map(entry => entry.path),
            ['Created Offline'],
            'the caller still gets the folder'
        );
        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX'], 'but it is not stored as a folder that has been seen');
        assert.strictEqual(before, mockRedisData[mailboxListKey].INBOX, 'and with nothing else changed there is nothing to write at all');

        // The pass that can announce it is the one that records it
        const { client: reconnected } = createListingClient([serverFolder('INBOX'), serverFolder('Created Offline')]);
        const again = await reconnected.getCurrentListing({}, {});

        assert.deepStrictEqual(
            again.filter(entry => entry.isNew).map(entry => entry.path),
            ['Created Offline'],
            'the reconnected pass is what discovers it'
        );
        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]).sort(), ['Created Offline', 'INBOX']);
    });

    await t.test('a folder that disappeared while the primary is down is still cleared', async () => {
        // A deletion is complete on its own - the folder is gone, its index is cleared and the
        // announcement is claimed by the same pass - so it is not deferred.
        seedStoredListing([
            { path: 'INBOX', name: 'INBOX', delimiter: '/', noInferiors: false, listed: true, subscribed: true },
            { path: 'Old', name: 'Old', delimiter: '/', noInferiors: false, listed: true, subscribed: true }
        ]);

        const { client, cleared } = createListingClient([serverFolder('INBOX')], { primaryDown: true });
        await client.getCurrentListing({}, { allowSecondary: true });

        assert.deepStrictEqual(cleared, ['Old']);
        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX']);
    });

    await t.test('a folder named __proto__ round trips through the stored hash', async () => {
        const { client } = createListingClient([serverFolder('INBOX'), serverFolder('__proto__')]);

        const first = await client.getCurrentListing({}, {});
        assert.deepStrictEqual(
            first
                .filter(entry => entry.isNew)
                .map(entry => entry.path)
                .sort(),
            ['INBOX', '__proto__']
        );

        const stored = mockRedisData[mailboxListKey];
        assert.deepStrictEqual(Object.keys(stored).sort(), ['INBOX', '__proto__']);

        // Second pass: nothing may look new any more, otherwise the folder re-syncs and fires a
        // fresh mailboxNew webhook on every pass forever.
        const { client: second } = createListingClient([serverFolder('INBOX'), serverFolder('__proto__')]);
        const again = await second.getCurrentListing({}, {});
        assert.deepStrictEqual(
            again.filter(entry => entry.isNew).map(entry => entry.path),
            [],
            'a known folder must not be reported as new again'
        );
    });
});

// The connection half of the Mailbox.clear() fixture: the folder map and the notifier that two
// holders of the same listing snapshot share, because in production they live on one IMAPClient.
function createClearableConnection() {
    const notifications = [];

    // The notifier's record hangs on the connection because that is what the reuse call sites
    // share: one IMAPClient, one folder map, one notification stream
    return {
        redis: mockRedis,
        mailboxes: new Map(),
        notifications,
        getMailboxListKey: () => mailboxListKey,
        notify: async (mailbox, event, data) => {
            notifications.push({ event, path: data.path });
        }
    };
}

// Drives the REAL Mailbox.clear() through the prototype. Constructing a Mailbox would pull in a
// whole connection and a SyncOperations instance for a method that only touches Redis, the
// in-memory folder map and the notifier, so the receiver carries exactly those.
// `tracked: false` is the instance clearMailboxEntry() builds when the connection no longer
// tracks the folder; `connection` reuses another fixture's connection so the two clears race
// over the same map and notifier, which is why the notifications ride on the connection.
function createClearableMailbox(path, opts) {
    opts = opts || {};

    const connection = opts.connection || createClearableConnection();

    const receiver = {
        path,
        listingEntry: { path, name: path, specialUse: '\\Junk' },
        runPartialSyncTimer: false,
        logger: { debug: () => {}, error: () => {} },
        getMailboxKey: () => `${REDIS_PREFIX}iam:${ACCOUNT}:h:${path}`,
        getMessagesKey: () => `${REDIS_PREFIX}iam:${ACCOUNT}:l:${path}`,
        getNotificationsKey: () => `${REDIS_PREFIX}iam:${ACCOUNT}:n:${path}`,
        connection,
        clear: Mailbox.prototype.clear
    };

    if (opts.tracked !== false) {
        // Keyed the way IMAPClient keys it, so the map cleanup in clear() is actually covered
        // for a path that normalizes to something else
        connection.mailboxes.set(normalizePath(path), receiver);
    }

    return { receiver, notifications: connection.notifications, connection };
}

test('Mailbox.clear() deletion announcement', async t => {
    t.beforeEach(() => {
        mockRedisData = {};
    });

    await t.test('drops the folder from the stored listing and announces it once', async () => {
        seedStoredListing([serverFolder('INBOX'), serverFolder('Spam')]);
        const { receiver, notifications } = createClearableMailbox('Spam');

        await receiver.clear();

        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX'], 'the cleared folder must leave the stored listing');
        assert.deepStrictEqual(notifications, [{ event: MAILBOX_DELETED_NOTIFY, path: 'Spam' }]);
        assert.strictEqual(receiver.connection.mailboxes.size, 0, 'and the in-memory folder map');
    });

    await t.test('a second clear of the same folder announces nothing', async () => {
        // Two listing passes overlap whenever an API request lands during the resync walk, and
        // both read the stored listing before either writes it back. Without the HDEL claim both
        // find the folder missing from the server and both send mailboxDeleted. The second pass
        // reaches clearMailboxEntry() with the folder already gone from the connection's map, so
        // it clears through an instance that tracks nothing.
        seedStoredListing([serverFolder('INBOX'), serverFolder('Spam')]);
        const { receiver, notifications, connection } = createClearableMailbox('Spam');

        await receiver.clear();

        const second = createClearableMailbox('Spam', { connection, tracked: false });
        await second.receiver.clear();

        assert.deepStrictEqual(notifications, [{ event: MAILBOX_DELETED_NOTIFY, path: 'Spam' }], 'the pass that claimed neither must stay quiet');
    });

    await t.test('a tracked folder missing from the stored listing is still announced once', async () => {
        // The listing hash is not the only record of a folder: processListing() registers a
        // Mailbox without writing the hash, and a pass that could not register the folder (no
        // primary connection) or purged a corrupt value writes the hash back without it. Gating
        // on the HDEL alone tore such a folder down in silence, and no later pass could announce
        // it either - the deletions a pass reports come from the very hash it is missing from.
        seedStoredListing([serverFolder('INBOX')]);
        const { receiver, notifications, connection } = createClearableMailbox('Spam');

        await receiver.clear();

        assert.deepStrictEqual(notifications, [{ event: MAILBOX_DELETED_NOTIFY, path: 'Spam' }]);
        assert.strictEqual(connection.mailboxes.size, 0);

        // and the claim is spent: an overlapping pass over the same connection stays quiet
        const second = createClearableMailbox('Spam', { connection, tracked: false });
        await second.receiver.clear();

        assert.strictEqual(notifications.length, 1);
    });

    await t.test('a folder that is neither tracked nor listed announces nothing', async () => {
        seedStoredListing([serverFolder('INBOX')]);
        const { receiver, notifications } = createClearableMailbox('Spam', { tracked: false });

        await receiver.clear();

        assert.deepStrictEqual(notifications, [], 'nothing was claimed, so there is nothing to announce');
    });

    await t.test('skipNotify clears the folder without announcing it', async () => {
        // The account teardown path: every folder is cleared and the listing key deleted right
        // after, and no webhook may be sent for any of it.
        seedStoredListing([serverFolder('INBOX'), serverFolder('Spam')]);
        const { receiver, notifications } = createClearableMailbox('Spam');

        await receiver.clear({ skipNotify: true });

        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), ['INBOX']);
        assert.deepStrictEqual(notifications, []);
    });

    await t.test('the folder is matched through the normalized path', async () => {
        seedStoredListing([serverFolder('Inbox')]);
        const { receiver } = createClearableMailbox('Inbox');

        await receiver.clear();

        assert.deepStrictEqual(Object.keys(mockRedisData[mailboxListKey]), [], 'the stored key is "INBOX" while the mailbox knows itself as "Inbox"');
        assert.strictEqual(receiver.connection.mailboxes.size, 0);
    });

    await t.test('a folder deleted through the API is not re-announced by the next listing pass', async () => {
        // deleteMailbox() clears the folder itself. The listing pass that follows sees the server
        // without it and used to announce the same deletion a second time, because nothing had
        // removed it from the stored listing. The same pass against an un-cleared listing does
        // still report the folder - that is the 'a folder the server no longer lists is cleared
        // and dropped from the hash' case in the getCurrentListing suite above.
        seedStoredListing([serverFolder('INBOX'), serverFolder('Spam')]);
        const { receiver } = createClearableMailbox('Spam');
        await receiver.clear();

        const { client, cleared } = createListingClient([serverFolder('INBOX')]);
        await client.getCurrentListing({}, {});

        assert.deepStrictEqual(cleared, [], 'the pass has nothing left to announce');
    });
});

// Drives the REAL GmailClient.listMailboxes() detailed-label cache, reached through
// GmailClient.prototype with the API collaborators stubbed. The previous coverage was a set of
// "let cache = {...}" simulations inside the test file, so it could not fail when the real cache
// changed; deleting those left the cache with no coverage at all. What matters here: the cache
// spares one API call PER LABEL (an account with 60 labels pays 60 requests per uncached call),
// and a stale hit would report wrong unread counts after a label mutation.
const { GmailClient } = require('../lib/email-client/gmail-client');

const GMAIL_LABELS = [
    { id: 'INBOX', name: 'INBOX', type: 'system' },
    { id: 'Label_1', name: 'Work', type: 'user' },
    { id: 'Label_2', name: 'Personal', type: 'user' }
];

function createGmailClient() {
    const detailRequests = [];

    const client = {
        cachedDetailedLabels: null,
        cachedDetailedLabelsTime: null,
        cachedLabels: null,
        cachedLabelsTime: null,
        logger: { error: () => {}, info: () => {}, debug: () => {}, trace: () => {} },
        prepare: async () => {},
        getLabels: async () => GMAIL_LABELS,
        // Resolves a path to an existing label the way the real lookup does; rename and delete
        // both go through it before issuing the mutation.
        getLabel: async path => GMAIL_LABELS.find(label => label.name === [].concat(path || '').join('/')) || false,
        request: async (url, method) => {
            const labelId = url.split('/labels/')[1];
            // Only a GET of a single label is a detail fetch; the mutation paths below hit the
            // same URL shape with a method, and counting those would mask a missing refetch.
            if (labelId && !method) {
                detailRequests.push(labelId);
                return { id: labelId, name: GMAIL_LABELS.find(label => label.id === labelId).name, type: 'user', messagesTotal: 100, messagesUnread: 5 };
            }
            return { id: labelId || 'Label_new', name: 'New Label', type: 'user' };
        },
        listMailboxes: GmailClient.prototype.listMailboxes
    };

    return { client, detailRequests };
}

const UNSEEN_QUERY = { statusQuery: { unseen: true } };

test('Gmail detailed label cache', async t => {
    await t.test('a second call inside the window is served from the cache', async () => {
        const { client, detailRequests } = createGmailClient();

        const first = await client.listMailboxes(UNSEEN_QUERY);
        const afterFirst = detailRequests.length;
        const second = await client.listMailboxes(UNSEEN_QUERY);

        assert.strictEqual(afterFirst, GMAIL_LABELS.length, 'the first call fetches every label individually');
        assert.strictEqual(detailRequests.length, afterFirst, 'the second call must not hit the API again');
        assert.deepStrictEqual(
            second.map(mailbox => mailbox.path),
            first.map(mailbox => mailbox.path)
        );
    });

    await t.test('the cache expires after 60 seconds', async () => {
        const { client, detailRequests } = createGmailClient();

        await client.listMailboxes(UNSEEN_QUERY);
        const afterFirst = detailRequests.length;

        // Age the cache past the window rather than waiting a minute
        client.cachedDetailedLabelsTime -= 61 * 1000;
        await client.listMailboxes(UNSEEN_QUERY);

        assert.strictEqual(detailRequests.length, afterFirst * 2, 'an expired cache must be refetched');
    });

    await t.test('the cache is still fresh one second before it expires', async () => {
        const { client, detailRequests } = createGmailClient();

        await client.listMailboxes(UNSEEN_QUERY);
        const afterFirst = detailRequests.length;

        client.cachedDetailedLabelsTime -= 59 * 1000;
        await client.listMailboxes(UNSEEN_QUERY);

        assert.strictEqual(detailRequests.length, afterFirst, 'the window must not be cut short');
    });

    await t.test('a label mutation invalidates the cache', async () => {
        // Creating, renaming or deleting a label changes what the next listing must report, so
        // every mutation path clears the cache. Driven through the real methods.
        for (const [label, mutate] of [
            ['createMailbox', client => GmailClient.prototype.createMailbox.call(client, 'New Label')],
            ['renameMailbox', client => GmailClient.prototype.renameMailbox.call(client, 'Work', 'Work 2')],
            ['deleteMailbox', client => GmailClient.prototype.deleteMailbox.call(client, 'Work')]
        ]) {
            const { client, detailRequests } = createGmailClient();

            await client.listMailboxes(UNSEEN_QUERY);
            const afterFirst = detailRequests.length;
            assert.ok(client.cachedDetailedLabels, 'sanity check: the listing populated the cache');

            await mutate(client);
            assert.strictEqual(client.cachedDetailedLabels, null, `${label} must clear the detailed label cache`);

            await client.listMailboxes(UNSEEN_QUERY);
            assert.strictEqual(detailRequests.length, afterFirst * 2, `${label} must force the next listing to refetch`);
        }
    });

    await t.test('a listing without an unseen query never touches the per-label endpoint', async () => {
        // The expensive fan-out only exists to answer unread counts.
        const { client, detailRequests } = createGmailClient();

        await client.listMailboxes({});

        assert.deepStrictEqual(detailRequests, [], 'a plain listing must be served from the label list alone');
        assert.strictEqual(client.cachedDetailedLabels, null);
    });
});
