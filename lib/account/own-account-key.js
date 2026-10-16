'use strict';

// Which per-account Redis keys belong to one account.
//
// The per-account keys are `<prefix>iam:<account>:<suffix>`, and an account id is free text that
// may contain ":" itself. A glob of `iam:<account>:*` therefore also matches every key of an
// account whose id begins with this one and a colon (`iam:tenant:*` covers `tenant:x`), so a
// delete or a flush of one account used to take another tenant's index with it. The suffix is
// a fixed vocabulary, which is what tells the two apart: the key is this account's only when what
// follows its id is one of the shapes EmailEngine writes.

// `g` (the gateway counters), `announced-in` (the Graph announced set), `h:<hash>` (a mailbox
// status hash), `l:<hash>` and `n:<hash>` (a mailbox's message list and notifications). The hash
// is mailboxPathHash(), a base36 number
const ACCOUNT_KEY_SUFFIX = /^(?:g|announced-in|[hln]:[0-9a-z]+)$/;

/**
 * Whether a key matched by the account's `iam:<account>:*` glob really belongs to the account.
 *
 * @param {String} prefix - REDIS_PREFIX
 * @param {String} account - the account id
 * @param {String} key - a key the scan returned
 * @returns {Boolean}
 */
function isOwnAccountKey(prefix, account, key) {
    let head = `${prefix}iam:${account}:`;
    if (typeof key !== 'string' || !key.startsWith(head)) {
        return false;
    }
    return ACCOUNT_KEY_SUFFIX.test(key.slice(head.length));
}

module.exports = { isOwnAccountKey, ACCOUNT_KEY_SUFFIX };
