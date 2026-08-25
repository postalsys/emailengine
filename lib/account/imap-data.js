'use strict';

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
 *   `invalid` telling an absent field (an OAuth2 account has none) apart from an unreadable one
 */
async function readImapData(redis, accountKey, logger, imapInfo) {
    if (imapInfo === undefined) {
        imapInfo = await redis.hget(accountKey, 'imap');
    }

    if (!imapInfo) {
        return { imapData: null, invalid: false };
    }

    try {
        return { imapData: JSON.parse(imapInfo), invalid: false };
    } catch (err) {
        logger.error({ msg: 'Failed parsing IMAP data', err });
        return { imapData: null, invalid: true };
    }
}

module.exports = { readImapData };
