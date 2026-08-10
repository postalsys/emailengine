'use strict';

// Pure helpers behind IMAPClient.getCurrentListing().
//
// Every IMAP sync pass re-runs LIST and has to work out which folders are new, which changed
// shape, and which disappeared, then persist the result. That comparison is the part worth
// testing on its own: it is pure, it runs on every sync for every account, and getting it wrong
// either floods operators with spurious mailboxNew notifications or silently drops folders.
// The surrounding IO (the LIST call, clearing a deleted folder's index, the Redis write) stays
// in imap-client.js.
//
// Folder paths are compared through normalizePath(), which case-folds INBOX so a server that
// reports "Inbox" one pass and "INBOX" the next does not look like a delete plus an add.

const msgpack = require('../../msgpack');
const { normalizePath } = require('../../tools');
const { STORED_MAILBOX_FIELDS } = require('../../consts');

// The fields diffMailboxListing() compares, i.e. everything buildStoredListingObject() persists
// except the path, which is the hash key and therefore equal by construction. Derived from the
// stored field list so that persisting a new field can not silently leave it uncompared.
const COMPARED_MAILBOX_FIELDS = STORED_MAILBOX_FIELDS.filter(field => field !== 'path');

/**
 * Decodes one msgpack-encoded entry of the stored mailbox listing hash, or returns false if the
 * value is unusable. Callers drop a false entry rather than failing: a single corrupt value must
 * not take down the sync (or the mailboxes API response) for every other folder in the account.
 *
 * The shape check is not redundant with the try/catch. The msgpack decoder only throws on input
 * it can not parse at all - a corrupt buffer whose first byte is a valid type marker decodes to
 * a plain number or string instead. Such an entry has no `path`, so downstream it would register
 * as a phantom mailbox keyed `undefined` and (via Object.assign onto a primitive) surface as a
 * boxed Number in the mailboxes API response.
 *
 * @param {Buffer} value - msgpack-encoded hash value
 * @returns {Object|false} Decoded mailbox entry, or false when the value is missing or corrupt
 */
function decodeStoredMailboxEntry(value) {
    let entry;
    try {
        entry = msgpack.decode(value);
    } catch (err) {
        // should not happen
        return false;
    }
    return entry && typeof entry === 'object' && typeof entry.path === 'string' ? entry : false;
}

/**
 * Decodes the msgpack-encoded mailbox listing hash read back from Redis, separating out the
 * entries that did not decode.
 *
 * The corrupt paths are reported rather than just dropped because a dropped entry is invisible to
 * every later step: it is not in the decoded listing, so it can never be matched against a server
 * folder, so it can never register as deleted either. Without an explicit rewrite the bad field
 * survives every sync pass forever while the mailboxes API keeps skipping that folder.
 *
 * @param {Object} storedListing - Redis hash (path -> msgpack Buffer), possibly null
 * @returns {Object} { entries, corruptPaths } - decoded mailbox entries and the unusable fields
 */
function decodeStoredListing(storedListing) {
    const entries = [];
    const corruptPaths = [];

    for (let path of Object.keys(storedListing || {})) {
        let entry = decodeStoredMailboxEntry(storedListing[path]);
        if (entry) {
            entries.push(entry);
        } else {
            corruptPaths.push(path);
        }
    }

    return { entries, corruptPaths };
}

/**
 * Compares a fresh server listing against the stored one.
 *
 * Mutates the entries of `listing`: a folder with no stored counterpart is flagged `isNew`.
 * That flag is the one-shot carrier that makes processListing() emit mailboxNew, so it has to
 * ride on the returned listing rather than being reported separately.
 *
 * @param {Array} listing - Mailbox entries from the server (already filtered of \Noselect)
 * @param {Array} storedListing - Decoded entries previously persisted for this account
 * @returns {Object} { hasChanges, deletedEntries } - deletedEntries are stored folders the
 *                   server no longer lists, whose message index the caller must clear
 */
function diffMailboxListing(listing, storedListing) {
    let hasChanges = false;

    // Map for O(1) lookups - a linear scan per folder is quadratic on accounts with thousands
    // of folders, which is common on shared/public namespaces.
    const storedListingMap = new Map();
    for (const entry of storedListing) {
        storedListingMap.set(normalizePath(entry.path), entry);
    }

    for (let mailbox of listing) {
        let existingMailbox = storedListingMap.get(normalizePath(mailbox.path));
        if (!existingMailbox) {
            // found new!
            mailbox.isNew = true;
            hasChanges = true;
        } else {
            // Every persisted field has to be compared, not just the structural ones. The
            // mailboxes API answers from the stored hash (Account.getMailboxListing merges only
            // the live status counters onto it), so a field that changed without setting
            // hasChanges is never written back and the stale value is served until some
            // unrelated folder happens to be created or deleted. Unsubscribing a folder moves
            // `subscribed` alone, and modifyMailbox() explicitly refreshes the listing right
            // afterwards expecting exactly that to be picked up.
            for (let field of COMPARED_MAILBOX_FIELDS) {
                if (existingMailbox[field] !== mailbox[field]) {
                    hasChanges = true;
                    break;
                }
            }
        }
    }

    // Check for deleted mailboxes
    const listingPathSet = new Set(listing.map(mailbox => normalizePath(mailbox.path)));
    const deletedEntries = storedListing.filter(entry => !listingPathSet.has(normalizePath(entry.path)));
    if (deletedEntries.length) {
        hasChanges = true;
    }

    return { hasChanges, deletedEntries };
}

/**
 * Builds the Redis hash written back when the listing changed: normalized path -> msgpack of
 * the persisted field subset.
 *
 * The accumulator has a null prototype because folder names are attacker-influenced strings and
 * one of them is special on a plain object: assigning `listingObject['__proto__']` would invoke
 * the Object.prototype setter instead of creating an own property, so Object.keys() (which is
 * how ioredis serializes the hash) would silently omit that folder. It would then look unseen on
 * every following sync: a fresh mailboxNew notification plus a full initial sync of the folder,
 * every pass, forever.
 *
 * @param {Array} listing - Mailbox entries from the server
 * @returns {Object} Hash suitable for HMSET
 */
function buildStoredListingObject(listing) {
    const listingObject = Object.create(null);
    listing.forEach(entry => {
        let mailbox = {};
        Object.keys(entry).forEach(key => {
            if (STORED_MAILBOX_FIELDS.includes(key)) {
                mailbox[key] = entry[key];
            }
        });
        listingObject[normalizePath(entry.path)] = msgpack.encode(mailbox);
    });
    return listingObject;
}

module.exports = {
    decodeStoredMailboxEntry,
    decodeStoredListing,
    diffMailboxListing,
    buildStoredListingObject
};
