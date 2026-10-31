'use strict';

const Boom = require('@hapi/boom');

// Account state constants
const ACCOUNT_STATES = {
    INIT: 'init',
    UNSET: 'unset',
    CONNECTED: 'connected',
    CONNECTING: 'connecting',
    SYNCING: 'syncing',
    AUTHENTICATION_ERROR: 'authenticationError',
    CONNECT_ERROR: 'connectError'
};

// States that indicate the account is operational
const VALID_STATES = [ACCOUNT_STATES.CONNECTED, ACCOUNT_STATES.CONNECTING, ACCOUNT_STATES.SYNCING];

// Non-operational error states. Re-authorizing / re-saving credentials for an account in one of
// these states should trigger a full reconnect so syncing resumes.
const ERROR_STATES = [ACCOUNT_STATES.AUTHENTICATION_ERROR, ACCOUNT_STATES.CONNECT_ERROR];

// States that bypass the run check
const BYPASS_RUN_INDEX_STATES = [ACCOUNT_STATES.INIT, ACCOUNT_STATES.UNSET];

/**
 * Whether the stored connection state was written by the run that serves the account now. A record
 * no instance has claimed yet (written before ownership existed, or read before the first claim)
 * carries no `ownerRun`, and its stored state is taken as it is, which is what every reader that
 * did not pass a run index got before.
 *
 * Every process start gets a run number (`settings.run`). The instance that claims an account
 * records its run as `ownerRun` (lib/lua/cluster-claim.lua), and the connection records its run as
 * `runIndex` with every state it reaches (lib/lua/account-set-state.lua). Until the two match, the
 * stored state is left over from an earlier run or another instance, and the account has not
 * connected in its current owner yet. Comparing against the run of whichever process answers the
 * request, as before, reported `init` for every account another instance had connected earlier.
 *
 * @param {Object} accountData - Account data with `runIndex` and `ownerRun`
 * @returns {boolean}
 */
function isCurrentRunState(accountData) {
    const ownerRun = Number(accountData.ownerRun) || 0;
    return !ownerRun || ownerRun === (Number(accountData.runIndex) || 0);
}

/**
 * Calculates the effective account state: the stored one when the current owner wrote it, and
 * `connecting` while the instance that claimed the account is setting its connection up (after a
 * restart, or when the account moved to another instance). A request for it is let through and
 * waits for the connection there, instead of being refused for a state left behind by the previous run
 * @param {Object} accountData - The account data object
 * @returns {string} The effective state value
 */
function calculateEffectiveState(accountData) {
    const currentState = accountData.state;

    // API accounts and special states bypass the run check
    if (BYPASS_RUN_INDEX_STATES.includes(currentState) || accountData.isApi || isCurrentRunState(accountData)) {
        return currentState;
    }

    return ACCOUNT_STATES.CONNECTING;
}

/**
 * Validates that an account is in a state suitable for operations
 * @param {Object} accountData - The account data object with state
 * @throws {Boom} When the account state is not valid for operations
 */
function validateAccountState(accountData) {
    if (VALID_STATES.includes(accountData.state)) {
        return;
    }

    let err;
    switch (accountData.state) {
        case ACCOUNT_STATES.INIT:
            err = new Error('Requested account is not yet initialized');
            err.code = 'NotYetConnected';
            break;

        case ACCOUNT_STATES.AUTHENTICATION_ERROR:
            err = new Error('Requested account can not be authenticated');
            err.code = 'AuthenticationFails';
            break;

        case ACCOUNT_STATES.CONNECT_ERROR:
            err = new Error('Can not establish server connection for requested account');
            err.code = 'ConnectionError';
            break;

        case ACCOUNT_STATES.UNSET:
            err = new Error('Syncing is disabled for the requested account');
            err.code = 'NotSyncing';
            break;

        default:
            err = new Error('Requested account currently not available');
            err.code = 'NoAvailable';
            break;
    }

    const error = Boom.boomify(err, { statusCode: 503 });
    if (accountData.state) {
        error.output.payload.state = accountData.state;
    }
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
}

// A stored timestamp is only as good as whatever wrote it: a corrupt or hand-edited record must
// degrade to null rather than fail the response schema and 500 the endpoint
function isoOrNull(date) {
    return date && date.toString() !== 'Invalid Date' ? date.toISOString() : null;
}

/**
 * The state of a Gmail account's Pub/Sub watch, for whoever has to answer "is push working right
 * now". Derived rather than stored: the account keeps the last successful arm (`lastWatch`,
 * `watchResponse`, `watchExpiration`) and the last failure (`watchFailure`) as separate records,
 * and neither answers the question on its own.
 *
 * Everything here is a timestamp or an enum EmailEngine produced, and nothing the provider wrote is
 * quoted. The stored failure carries plenty that is: `req.response` is Google's body verbatim, and
 * `err` is `formatTokenError()` output whenever the failure was a token fetch, which interpolates
 * the provider's `error_description`. GET /v1/account/{id} is reachable by an account-bound tenant
 * token, by an MCP token whose contents reach an LLM, and by a session token that lives in page
 * HTML, so the reason a watch failed stays on the account page - behind an admin session, reading
 * the stored record directly.
 *
 * A dead watch is not an error state: the Gmail client keeps syncing on its fallback poller, so
 * mail is delayed rather than lost. That is why this is a field to read and not a webhook.
 *
 * @param {Object} accountData - Account data object
 * @returns {Object|null} Watch state, or null for an account that has never armed one
 */
function formatGmailWatch(accountData) {
    if (!accountData || (!accountData.watchResponse && !accountData.watchFailure)) {
        return null;
    }

    // Push is configured on the linked application. An account whose application has no Pub/Sub
    // app has no watch to report, whatever an earlier configuration left behind: the Gmail client
    // clears that record when it next arms a watch, but a send-only or parked account never
    // arms one, and its months-old failure would otherwise read as the current state.
    if (accountData._app && !accountData._app.pubSubApp) {
        return null;
    }

    const failure = accountData.watchFailure;

    // The response of the arm that is actually live wins. `watchExpiration` rides the default
    // serializer branch, which skips a null, so a success that carried no expiration leaves the
    // previous arm's number in place and preferring it would report a lapsed watch as active
    const expiration = (accountData.watchResponse && accountData.watchResponse.expiration) || accountData.watchExpiration;
    const expires = isoOrNull(expiration && new Date(Number(expiration)));

    // The failure carries its own attempt time because a failed renewal no longer moves lastWatch -
    // doing so used to buy a broken watch a full day of silence, whatever the retry timer wanted
    const lastCheck = (failure && isoOrNull(failure.time && new Date(failure.time))) || isoOrNull(accountData.lastWatch && new Date(accountData.lastWatch));

    let state = 'expired';
    if (failure) {
        state = 'error';
    } else if (expires && new Date(expires) > new Date()) {
        state = 'active';
    }

    return { state, lastCheck, expires };
}

/**
 * Formats the last error for API responses
 * Returns null if account is connected or no error exists
 * @param {Object} accountData - Account data object
 * @returns {Object|null} Formatted error object or null
 */
function formatLastError(accountData) {
    if (accountData.state === ACCOUNT_STATES.CONNECTED) {
        return null;
    }

    if (!accountData.lastErrorState || !Object.keys(accountData.lastErrorState).length) {
        return null;
    }

    return accountData.lastErrorState;
}

/**
 * The state an account listing shows, see calculateEffectiveState()
 * @param {Object} accountData - Account data with state, runIndex and ownerRun
 * @returns {string} Effective state for display
 */
function getDisplayState(accountData) {
    return calculateEffectiveState(accountData);
}

module.exports = {
    // Constants
    ACCOUNT_STATES,
    VALID_STATES,
    ERROR_STATES,
    BYPASS_RUN_INDEX_STATES,

    // State calculation
    calculateEffectiveState,
    isCurrentRunState,
    validateAccountState,
    getDisplayState,

    // Error state formatting
    formatLastError,
    formatGmailWatch
};
