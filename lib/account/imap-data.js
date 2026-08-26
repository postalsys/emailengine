'use strict';

/**
 * Decides what a stored `imap` blob is, without reading it.
 *
 * Split out from readImapData() so a caller that already holds the raw field, and cannot await or
 * afford a log line per account, still shares the one definition of a usable blob. The scan in
 * auth-failure-backfill.js is that caller.
 *
 * @param {String} imapInfo - The raw field as stored
 * @param {Object} [logger] - Logger for a blob that cannot be used; silent when omitted
 * @returns {{imapData: Object|null, invalid: Boolean}} See readImapData()
 */
function parseImapData(imapInfo, logger) {
    if (!imapInfo) {
        return { imapData: null, invalid: false };
    }

    let imapData;
    try {
        imapData = JSON.parse(imapInfo);
    } catch (err) {
        logger?.error({ msg: 'Failed parsing IMAP data', err });
        return { imapData: null, invalid: true };
    }

    // Parsing is not enough: every caller goes on to read or set `disabled` on what comes back, and
    // a blob that parsed to a scalar throws on the assignment while one that parsed to an array
    // takes the flag and loses it again at the next JSON.stringify. Only an object is usable, so a
    // stored value that is anything else counts as unreadable and is left alone rather than
    // replaced with a bare flag. `null` parses fine and is reported as an absent blob, which is
    // what it is.
    if (imapData !== null && (typeof imapData !== 'object' || Array.isArray(imapData))) {
        logger?.error({ msg: 'Unexpected IMAP data type', type: Array.isArray(imapData) ? 'array' : typeof imapData });
        return { imapData: null, invalid: true };
    }

    return { imapData, invalid: false };
}

/**
 * Reads an account's stored `imap` blob.
 *
 * Three call sites need it before, or instead of, a full account load: the connection gate that
 * asks whether syncing is switched off, the safety net that switches it off, and the recovery path
 * that switches it back on. They all have to treat an unreadable blob the same way - rewriting one
 * that does not parse would replace the account's IMAP configuration with a bare flag - so the
 * decision lives here rather than in three copies of the same try/catch.
 *
 * @param {Object} redis - ioredis client
 * @param {String} accountKey - Redis key of the account hash
 * @param {Object} logger - Logger for the parse failure
 * @param {String} [imapInfo] - The raw field when the caller has already read it, to save a round trip
 * @returns {Promise<{imapData: Object|null, invalid: Boolean}>} The parsed blob, or null with
 *   `invalid` telling an absent field (an OAuth2 account has none) apart from an unreadable one.
 *   Unreadable covers anything the callers cannot use, not only text that fails to parse
 */
async function readImapData(redis, accountKey, logger, imapInfo) {
    if (imapInfo === undefined) {
        imapInfo = await redis.hget(accountKey, 'imap');
    }

    return parseImapData(imapInfo, logger);
}

module.exports = { readImapData, parseImapData };
