'use strict';

// Lives here rather than in lib/tools.js so that pure modules can use it: tools.js opens Redis,
// which hangs a unit test that only wants to compare two folder names. tools.js re-exports
// normalizePath, so the existing `require('../tools')` consumers are unaffected.

/**
 * Folds a folder path to the spelling the sync keys everything by. IMAP makes the name "INBOX"
 * case-insensitive, so a server is free to answer "Inbox" in one response and "INBOX" in the
 * next; without this the two would read as different folders. Only that one name is folded -
 * every other folder name is case-sensitive on IMAP and must be left alone.
 *
 * With a separator the fold also covers the hierarchy below the inbox ("inbox/Sub" into
 * "INBOX/Sub"), which needs the server's delimiter and so is only available to callers that
 * have listed the account.
 *
 * @param {String} path - Folder path
 * @param {String} [separator] - The server's hierarchy delimiter, when known
 * @returns {String} Normalized path
 */
function normalizePath(path, separator) {
    if (separator) {
        return path.replace(new RegExp(`^INBOX($|${separator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'i'), n => n.toUpperCase());
    }

    if (/^INBOX$/i.test(path)) {
        return 'INBOX';
    }

    return path;
}

/**
 * Do two paths name the same folder? Both sides are normalized, so the "INBOX" an operator typed
 * into the account configuration matches the "Inbox" a server chose to report. Anything that is
 * not a string matches nothing, so two missing paths can never compare equal - normalizePath()
 * hands back what it was given, and `undefined === undefined` would otherwise be a match.
 *
 * Only the top-level inbox name is folded, because the separator is not available at every call
 * site: a configured "Inbox/Archive" still has to match the server's spelling below the root,
 * the same gap the mailbox map and the stored listing keys have.
 *
 * @param {String} a - Folder path
 * @param {String} b - Folder path
 * @returns {Boolean} True when both name the same folder
 */
function samePath(a, b) {
    return typeof a === 'string' && typeof b === 'string' && normalizePath(a) === normalizePath(b);
}

module.exports = { normalizePath, samePath };
