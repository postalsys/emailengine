'use strict';

// Gmail categories over IMAP (resolveGmailCategories): each new Inbox message used to cost up to seven
// X-GM-RAW searches, one category at a time. Mailbox.createCategoryResolver() looks up every message
// queued in the same pass with one search per category, and must still give each message the first
// category in order that matches it.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { forAll, gen } = require('./helpers/property');

const silentLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

require('./helpers/redis-teardown')();

const CATEGORIES = ['primary', 'social', 'promotions', 'updates', 'forums', 'reservations', 'purchases'];

function parseUidSet(value) {
    return String(value).split(',').map(Number);
}

// membership: uid -> categories it matches
function createMailbox(membership, queuedUids, opts = {}) {
    const searches = [];
    const mailbox = Object.assign(Object.create(Mailbox.prototype), {
        logger: silentLogger,
        getNotificationsKey: () => 'n',
        connection: {
            redis: {
                zrange: async () => queuedUids.flatMap(uid => [JSON.stringify({ uid }), String(uid)])
            }
        },
        requireImapClient: () => ({
            async search(query) {
                searches.push(query);
                if (opts.fail) {
                    throw opts.fail;
                }
                const category = query.gmraw.replace('category:', '');
                return parseUidSet(query.uid).filter(uid => (membership[uid] || []).includes(category));
            }
        })
    });
    return { mailbox, searches };
}

test('Gmail category resolver', async t => {
    await t.test('one search per category covers every queued message', async () => {
        const membership = { 1: ['social'], 2: ['primary'], 3: ['purchases'], 4: [] };
        const { mailbox, searches } = createMailbox(membership, [1, 2, 3, 4]);
        const resolver = mailbox.createCategoryResolver();

        assert.strictEqual(await resolver.categoryOf(1), 'social');
        assert.strictEqual(await resolver.categoryOf(2), 'primary');
        assert.strictEqual(await resolver.categoryOf(3), 'purchases');
        assert.strictEqual(await resolver.categoryOf(4), null);
        assert.strictEqual(searches.length, CATEGORIES.length);
        assert.strictEqual(searches[0].uid, '1,2,3,4');
    });

    await t.test('stops searching once every message has a category', async () => {
        const { mailbox, searches } = createMailbox({ 1: ['primary'], 2: ['primary'] }, [1, 2]);
        await mailbox.createCategoryResolver().categoryOf(1);
        assert.strictEqual(searches.length, 1);
    });

    await t.test('a message queued after the lookup gets a lookup of its own', async () => {
        const queued = [1];
        const { mailbox, searches } = createMailbox({ 1: ['primary'], 9: ['forums'] }, queued);
        const resolver = mailbox.createCategoryResolver();
        assert.strictEqual(await resolver.categoryOf(1), 'primary');
        queued.push(9);
        assert.strictEqual(await resolver.categoryOf(9), 'forums');
        assert.deepStrictEqual(
            searches.map(search => search.uid),
            ['1', '9', '9', '9', '9', '9']
        );
    });

    await t.test('a failed lookup is reported once, not repeated for every message of the batch', async () => {
        const { mailbox, searches } = createMailbox({}, [1, 2, 3], { fail: new Error('BAD') });
        const resolver = mailbox.createCategoryResolver();
        await assert.rejects(resolver.categoryOf(1), /BAD/);
        assert.strictEqual(await resolver.categoryOf(2), null);
        assert.strictEqual(searches.length, 1);
    });

    await t.test('property: the first category in order that matches wins, as with one message at a time', async () => {
        await forAll(
            gen.array(gen.array(gen.integer(0, CATEGORIES.length - 1), 0, 3), 1, 40),
            async assignments => {
                const membership = {};
                const uids = assignments.map((categories, i) => {
                    membership[i + 1] = categories.map(index => CATEGORIES[index]);
                    return i + 1;
                });
                const { mailbox, searches } = createMailbox(membership, uids);
                const resolver = mailbox.createCategoryResolver();
                for (const uid of uids) {
                    const expected = CATEGORIES.find(category => membership[uid].includes(category)) || null;
                    assert.strictEqual(await resolver.categoryOf(uid), expected);
                }
                assert.ok(searches.length <= CATEGORIES.length);
            },
            { runs: 300 }
        );
    });
});
