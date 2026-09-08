'use strict';

// Where EmailEngine decides whether a failed attempt to obtain a credential means "the credential
// was refused" or "the service that holds it is having a bad minute". Getting that wrong is
// expensive: a refusal webhooks `authenticationError`, parks the account in an error state and
// stops the API clients retrying, and then the next attempt contradicts it with
// `authenticationSuccess`. Microsoft and Google throttle and 5xx their token endpoints often
// enough, and one authentication server is shared by every account on an instance, for that to be
// a steady stream of events and parked accounts on a busy deployment.
//
// Its own module rather than a corner of base-client.js because both sides of the fence need it:
// base-client owns the IMAP and API credential paths, message-builder owns the SMTP one, and
// base-client already imports message-builder - so there is no direction in which one could
// require the other.

const { resolveCredentials } = require('../tools');
const { AUTH_ERROR_NOTIFY, TRANSIENT_NETWORK_CODES } = require('../consts');
const { ACCOUNT_STATES } = require('../account/account-state');

/**
 * Failing to reach a remote endpoint is a connection problem, not a rejected credential. Both
 * OAuth2 credential sources (EmailEngine's own token refresh and an external authentication
 * server) use this to avoid reporting an unreachable host as an authentication error, and the API
 * transports use it to decide which failed requests to repeat. undici reports a connection failure
 * as a generic TypeError ("fetch failed") with the real DNS/socket error attached as err.cause, so
 * the code is looked up there as well
 * @param {Error} err - The error to check
 * @returns {boolean} True if the error is a transient network failure
 */
function isTransientNetworkError(err) {
    return !!err && (TRANSIENT_NETWORK_CODES.has(err.code) || (!!err.cause && TRANSIENT_NETWORK_CODES.has(err.cause.code)));
}

/**
 * Reads the HTTP status a failed credential request came back with. The OAuth2 clients put it on
 * the error itself and repeat it in the request record they attach; the Graph and Gmail transports
 * only carry the request record. Boom wrappers are deliberately not consulted:
 * Account.getActiveAccessTokenData() boomifies every renewal failure as 403, which would mask the
 * status the token endpoint actually sent
 * @param {Error} err - The error to read
 * @returns {number} The status, or 0 when the failure never reached a response
 */
function credentialErrorStatus(err) {
    return Number(err?.statusCode || err?.tokenRequest?.status || err?.oauthRequest?.status || 0);
}

/**
 * Whether a failed attempt to obtain a credential means the credential service is unavailable
 * rather than the credential being refused. 408, 429 and every 5xx are the service failing; only a
 * 4xx is the credential itself being rejected (an expired refresh token comes back as 400
 * invalid_grant, a revoked one as 401), which is the case a human has to resolve by
 * re-authorizing the account
 * @param {Error} err - The error to check
 * @returns {boolean} True when the failure is the service's, not the credential's
 */
function isTransientCredentialError(err) {
    if (isTransientNetworkError(err)) {
        return true;
    }

    const status = credentialErrorStatus(err);
    return status === 408 || status === 429 || (status >= 500 && status < 600);
}

/**
 * Fetches an account's credentials from the operator's external authentication server and reports
 * a refusal as an authentication error. Shared by every connection path - IMAP, SMTP and the API
 * clients - because they all have to draw the same line: one authentication server serves every
 * account on the instance, so announcing an outage as an authentication failure webhooks and parks
 * the whole fleet at once. A transient failure is rethrown unflagged, and the caller reports it as
 * a connection error and retries.
 *
 * @param {String} account - Account id
 * @param {String} target - Protocol the credentials are for ('imap', 'smtp' or 'api')
 * @param {Object} ctx - What to report the failure on; needs `logger`, `notify` and `state` (an
 *   IMAP subconnection passes itself, and its notify() is a no-op, so its failures stay its own)
 * @returns {Promise<Object>} Resolved credentials
 */
async function resolveAuthServerCredentials(account, target, ctx) {
    try {
        return await resolveCredentials(account, target);
    } catch (err) {
        if (isTransientCredentialError(err)) {
            ctx.logger.warn({
                msg: 'Network error while resolving credentials from the authentication server',
                account,
                target,
                code: err.code,
                status: credentialErrorStatus(err) || undefined,
                err
            });
            throw err;
        }

        err.authenticationFailed = true;
        await ctx.notify(false, AUTH_ERROR_NOTIFY, {
            response: err.message,
            serverResponseCode: 'HTTPRequestError'
        });
        ctx.logger.error({
            msg: 'Failed to resolve credentials from the authentication server',
            account,
            target,
            err
        });
        ctx.state = ACCOUNT_STATES.AUTHENTICATION_ERROR;
        throw err;
    }
}

module.exports = {
    isTransientNetworkError,
    credentialErrorStatus,
    isTransientCredentialError,
    resolveAuthServerCredentials
};
