'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time
require('./helpers/mock-db').installDbMock();

const { IMAPClient } = require('../lib/email-client/imap-client');

// imap-client.js pulls in modules that keep the event loop alive; the shared
// teardown forces the exit once the tests are done
require('./helpers/redis-teardown')();

// getCurrentListing() flags the folders that appeared as isNew and persists the
// listing in the same call, so that flag is a one-shot record: a caller that only
// reads the listing and drops the result leaves the folder to be registered by a
// later resync, with its mailboxNew never sent. Read-only callers hand the listing
// to processListing() instead, which registers what it does not already track.

function createCtx(listing) {
    const calls = { processed: [], errors: [] };

    const ctx = {
        logger: {
            error(entry) {
                calls.errors.push(entry);
            }
        },
        checkIMAPConnection() {},
        getCurrentListing: async () => listing,
        processListing: listing => {
            calls.processed.push(listing);
            // Never settles: the caller must not wait for it
            return new Promise(() => {});
        },
        processNewListingEntries: IMAPClient.prototype.processNewListingEntries
    };

    return { ctx, calls };
}

test('listMailboxes hands its listing to processListing without waiting for it', async () => {
    const listing = [{ path: 'INBOX' }, { path: 'New Folder', isNew: true }];
    const { ctx, calls } = createCtx(listing);

    const result = await IMAPClient.prototype.listMailboxes.call(ctx);

    assert.equal(result, listing, 'the listing is returned as fetched');
    assert.deepEqual(calls.processed, [listing], 'the new folder must be registered and synced');
});

test('a failed background processing is logged, not thrown at the caller', async () => {
    const { ctx, calls } = createCtx([{ path: 'New Folder', isNew: true }]);
    ctx.processListing = async () => {
        throw new Error('Connection not available');
    };

    await IMAPClient.prototype.listMailboxes.call(ctx);
    await new Promise(setImmediate);

    assert.equal(calls.errors.length, 1);
    assert.equal(calls.errors[0].msg, 'Failed to process listing');
});

// --- processListing(): the account load is skipped when there is nothing to register ---

function createProcessCtx(trackedPaths, accountPath = '*') {
    const calls = { loads: 0 };

    return {
        calls,
        ctx: {
            account: 'test-account',
            mailboxes: new Map(trackedPaths.map(path => [path, { path }])),
            isGmail: false,
            isLarkSuite: false,
            imapIndexer: 'full',
            // A registered folder is synced right away; an empty STATUS ends that at once
            imapClient: { status: async () => false },
            mainLogger: { child: () => ({}) },
            accountObject: {
                loadAccountData: async () => {
                    calls.loads++;
                    return { path: accountPath };
                }
            },
            registerMailbox: IMAPClient.prototype.registerMailbox
        }
    };
}

test('processListing does not load account data when every folder is already tracked', async () => {
    const { ctx, calls } = createProcessCtx(['INBOX', 'Archive']);

    const syncNeeded = await IMAPClient.prototype.processListing.call(ctx, [{ path: 'INBOX' }, { path: 'Archive' }]);

    assert.equal(calls.loads, 0, 'the listing holds no unseen folder, so nothing has to be read');
    assert.equal(syncNeeded.size, 0, 'the empty-set return shape is kept');
});

test('processListing registers nothing while the primary connection is down', async () => {
    // A listing can be read over a pooled secondary connection before the account has
    // ever connected. Registering from it would build every folder before connect()
    // decided isGmail, so Gmail labels would be indexed instead of skipped
    const { ctx, calls } = createProcessCtx([]);
    ctx.imapClient = null;

    const syncNeeded = await IMAPClient.prototype.processListing.call(ctx, [{ path: 'INBOX', isNew: true }]);

    assert.equal(calls.loads, 0);
    assert.equal(syncNeeded.size, 0, 'connect() registers the whole listing once it is done');
    assert.equal(ctx.mailboxes.size, 0);
});

test('processListing registers an untracked folder even when it is not flagged as new', async () => {
    // The flag says the folder is absent from the stored listing, which is not the
    // same question as whether this connection tracks it - the registration decision
    // is the tracking one, so the guard must not narrow to isNew
    const { ctx, calls } = createProcessCtx(['INBOX']);
    const listing = [{ path: 'INBOX' }, { path: 'Archive' }];

    const syncNeeded = await IMAPClient.prototype.processListing.call(ctx, listing);

    assert.equal(calls.loads, 1);
    assert.equal(syncNeeded.size, 1, 'the untracked folder must be registered');
    assert.equal(ctx.mailboxes.has('Archive'), true);
});

// --- processListing(): the configured path list is matched against the server's spelling ---

test('an account restricted to INBOX still syncs it when the server answers "Inbox"', async () => {
    // account.path is stored exactly as the API received it while the listing carries whatever
    // the server chose to answer with. Compared raw, an account configured "INBOX" against a
    // server that lists "Inbox" matched nothing at all: every folder including the inbox was
    // flagged syncDisabled, so the account indexed nothing and never emitted messageNew.
    const { ctx } = createProcessCtx([], ['INBOX']);

    await IMAPClient.prototype.processListing.call(ctx, [
        { path: 'Inbox', specialUse: '\\Inbox' },
        { path: 'Sent', specialUse: '\\Sent' }
    ]);

    assert.equal(!!ctx.mailboxes.get('INBOX').syncDisabled, false, 'the configured folder must be monitored');
    assert.equal(!!ctx.mailboxes.get('Sent').syncDisabled, true, 'a folder outside the configured list stays excluded');
});

test('a configured special-use token still selects its folder', async () => {
    const { ctx } = createProcessCtx([], ['\\Sent']);

    await IMAPClient.prototype.processListing.call(ctx, [
        { path: 'Inbox', specialUse: '\\Inbox' },
        { path: 'Sent', specialUse: '\\Sent' }
    ]);

    assert.equal(!!ctx.mailboxes.get('Sent').syncDisabled, false);
    assert.equal(!!ctx.mailboxes.get('INBOX').syncDisabled, true);
});

// --- registerMailbox(): the pending mailboxNew survives a reconnect ---

test('re-registering a folder carries over a mailboxNew that was never sent', async () => {
    // The initial sync of a new folder can take minutes, and a disconnect in that window
    // leaves the flag set on the instance. The reconnect registers the folder from a listing
    // that no longer reports it as new - it has been in the stored listing since the pass that
    // discovered it - so without the carry-over the folder is silently never announced.
    const { ctx } = createProcessCtx([]);

    const first = IMAPClient.prototype.registerMailbox.call(ctx, { path: 'Archive', isNew: true });
    assert.equal(first.listingEntry.isNew, true);

    const second = IMAPClient.prototype.registerMailbox.call(ctx, { path: 'Archive' });

    assert.notEqual(second, first, 'the folder is tracked by the new instance');
    assert.equal(ctx.mailboxes.get('Archive'), second);
    assert.equal(second.listingEntry.isNew, true, 'the next successful open must announce it');
});

test('a folder whose first sync completed is not announced again', async () => {
    const { ctx } = createProcessCtx([]);

    const first = IMAPClient.prototype.registerMailbox.call(ctx, { path: 'Archive', isNew: true });
    // What onOpen() does once it has emitted the mailboxNew
    first.listingEntry.isNew = false;

    const second = IMAPClient.prototype.registerMailbox.call(ctx, { path: 'Archive' });

    assert.equal(!!second.listingEntry.isNew, false);
});

test('the pending flag is carried over through the normalized path', async () => {
    // The map is keyed through normalizePath(), so a server that lists "Inbox" one pass and
    // "INBOX" the next must still be recognised as the same folder
    const { ctx } = createProcessCtx([]);

    IMAPClient.prototype.registerMailbox.call(ctx, { path: 'Inbox', isNew: true });
    const second = IMAPClient.prototype.registerMailbox.call(ctx, { path: 'INBOX' });

    assert.equal(ctx.mailboxes.size, 1);
    assert.equal(second.listingEntry.isNew, true);
});
