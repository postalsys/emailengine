'use strict';

// One-time bridge for the OAuth2 accounts 2.79.3 switched off and 2.79.4 cannot recognise.
//
// 2.79.3 extended the auth-failure safety net to OAuth2 accounts, which until then it had skipped in
// silence, and its release note predicted the result: on upgrade, every account whose refresh token
// had already been dead for longer than the threshold was parked in one burst. It recorded that park
// as `imap.disabled` and nothing else.
//
// 2.79.4 then gave the automatic park its own provenance marker, because `imap.disabled` is also the
// operator's deliberate send-only switch and the two must not share one boolean. Every recovery and
// reporting surface reads the marker: the API's `authFailureDisabledAt`, the account page's
// "Syncing was switched off" alert and its "Resume syncing" action, the listing's state badge, the
// reconnect refusal, and - the one that matters here - the lift that re-authorization performs
// through Account.create() and Account.update().
//
// So an account parked during the roughly nineteen hours 2.79.3 was the current release reads as one
// the operator switched off on purpose. Re-authorizing it, through the hosted authentication form or
// POST /v1/account, reports success and lifts nothing. That is unrecoverable rather than merely
// wrong for an OAuth2 account: its page renders no IMAP settings card, so there is no disable
// checkbox to clear, and "Resume syncing" is marker-gated like everything else.
//
// The signature is therefore the synthesized blob 2.79.3 wrote for exactly that population, not the
// park in general: the bare flag, an OAuth2 credential, and an authentication error beside them
// (see isLegacyPark() for why the error is not required to be the park's own text). A password
// account carries a real IMAP configuration and has been wearing this same threshold error state
// since v2.46.0 (2024-08-28), where the safety net first shipped; it is deliberately not matched,
// because it was never stuck - clearing its checkbox is an explicit `disabled: false`, which is not
// marker-gated - and matching it would stamp accounts nobody has touched in two years with a park
// time of today.
//
// The true park time is not recoverable, since 2.79.3 stored none, so the marker holds the time of
// this run and the log says so. It overstates how recently the account stopped syncing, by however
// long the instance sat on 2.79.3, and that is the only cost of making it recoverable.
//
// Retire this once no supported upgrade path starts below 2.79.4. Until then a completion key says
// it has run, because a successful backfill leaves nothing behind to re-detect. An instance rolled
// back onto 2.79.3 afterwards, or a 2.79.3 sibling still parking accounts on the same Redis during a
// rolling upgrade, would leave a second batch that the key then hides; re-arming means deleting
// BACKFILL_KEY and restarting.

const { redis } = require('../db');
const logger = require('../logger');
const { parseImapData } = require('./imap-data');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_FIELD, AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION } = require('../consts');

// Marks the backfill as done for this Redis. Value is the ISO time of the run.
const BACKFILL_KEY = `${REDIS_PREFIX}migration:authFailureDisabled`;

// Accounts read per pipeline. Large installs hold tens of thousands, and sequential reads would
// stall startup; matches the chunking oauth2Apps.migrateLegacyApps() uses for its own backfill.
const CHUNK_SIZE = 500;

// Fields the scan reads per account, in the order isLegacyPark() destructures them
const SCAN_FIELDS = ['imap', AUTH_FAILURE_DISABLED_FIELD, 'lastErrorState', 'oauth2'];

/**
 * Whether an account hash carries the park 2.79.3 wrote for an OAuth2 account.
 *
 * @param {Array} row - The SCAN_FIELDS values as stored, any of them null
 * @returns {Boolean} True when the marker should be backfilled for this account
 */
function isLegacyPark([imapInfo, marker, errorStateInfo, oauth2Info]) {
    // Ordered cheapest first, so a healthy fleet is rejected without parsing anything. A successful
    // connection deletes lastErrorState outright, and only an OAuth2 credential could have been
    // parked into an `imap` blob the account does not otherwise own.
    if (marker || !imapInfo || !errorStateInfo || !oauth2Info) {
        return false;
    }

    const { imapData } = parseImapData(imapInfo);

    // The whole blob 2.79.3 synthesized was the flag. A `host` means a real IMAP configuration that
    // the operator can re-enable from the account page, which is the population deliberately left
    // out; anything that did not parse to a usable object was never written by the safety net.
    if (!imapData || imapData.disabled !== true || imapData.host) {
        return false;
    }

    let errorState;
    try {
        errorState = JSON.parse(errorStateInfo);
    } catch (err) {
        return false;
    }

    // The threshold text is what 2.79.3 wrote at the park, and it does not always survive: a parked
    // account still serves send requests and, for Gmail, push notifications, and each of those runs
    // the same failing token refresh through setErrorState(), which overwrites the stored error with
    // the refresh failure that caused the park. That failure carries a serverResponseCode
    // ('TokenGenerationError', 'OauthRenewError') where the park text carries none, so either shape
    // counts. The operator's send-only switch is still told apart by what sits beside the bare
    // flag: a deliberately switched-off account has no reason to carry a coded authentication error.
    return !!errorState && (errorState.description === AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION || !!errorState.serverResponseCode);
}

/**
 * Backfills AUTH_FAILURE_DISABLED_FIELD onto the OAuth2 accounts 2.79.3 parked, so the 2.79.4
 * recovery paths can see them.
 *
 * No lock, unlike oauth2Apps.migrateLegacyApps(): every write here is an idempotent set of the same
 * field on an account already carrying the signature, so two instances sharing one Redis can both
 * run it and the worst that happens is the scan being done twice. Taking a lock would cost every
 * instance a permanent second Redis connection - ioredfour duplicates one for its subscriber and
 * offers no way to close it - to serialize something that does not need serializing.
 *
 * @param {Object} [opts] - Overrides for tests; the defaults are the shared clients
 * @param {Object} [opts.redis] - ioredis client, carrying the hSetExists custom command
 * @param {Object} [opts.logger] - Logger
 * @returns {Promise<Number>} How many accounts were backfilled
 */
async function backfillAuthFailureDisabled(opts = {}) {
    const { redis: client = redis, logger: log = logger } = opts;

    // The common case is an instance that never ran 2.79.3, and this is the whole cost for it
    if (await client.exists(BACKFILL_KEY)) {
        return 0;
    }

    const stamp = new Date().toISOString();
    const accounts = await client.smembers(`${REDIS_PREFIX}ia:accounts`);

    // One write pipeline for the whole scan rather than one per chunk: matches are a small subset by
    // definition, and a round trip per chunk would double what the scan costs at startup.
    const writeReq = client.pipeline();
    let queued = 0;

    for (let i = 0; i < accounts.length; i += CHUNK_SIZE) {
        const chunk = accounts.slice(i, i + CHUNK_SIZE);

        const readReq = client.pipeline();
        for (const account of chunk) {
            readReq.hmget(`${REDIS_PREFIX}iad:${account}`, ...SCAN_FIELDS);
        }
        const rows = await readReq.exec();

        for (let j = 0; j < chunk.length; j++) {
            const [err, row] = rows[j];
            if (err || !row || !isLegacyPark(row)) {
                continue;
            }
            // hSetExists rather than hset, for the same reason the safety net writes it that way: an
            // account deleted between the read above and this write must not come back as a hash
            // holding nothing but a marker.
            writeReq.hSetExists(`${REDIS_PREFIX}iad:${chunk[j]}`, AUTH_FAILURE_DISABLED_FIELD, stamp);
            queued++;
        }
    }

    // Counted from the replies rather than from what was queued: hSetExists writes nothing to an
    // account deleted since the read, and a marker the log claims but Redis does not hold would send
    // whoever reads that number looking for accounts that are still invisible.
    let backfilled = 0;
    if (queued) {
        const results = await writeReq.exec();
        backfilled = (results || []).filter(([err, written]) => !err && written).length;
    }

    // Written last, so a crash mid-scan re-enters and repeats it. Every write is idempotent, so
    // repeating costs nothing.
    await client.set(BACKFILL_KEY, stamp);

    if (queued) {
        log.info({
            msg: 'Backfilled the auth-failure disable marker for accounts switched off by an earlier version',
            accounts: backfilled,
            skipped: queued - backfilled,
            disabledAt: stamp,
            note: 'the recorded time is when this ran, not when the accounts were switched off'
        });
    }

    return backfilled;
}

module.exports = { backfillAuthFailureDisabled, isLegacyPark, BACKFILL_KEY };
