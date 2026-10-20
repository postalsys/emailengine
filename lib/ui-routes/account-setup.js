'use strict';

// The last step of the hosted account setup, shared by both arms of the form: the IMAP arm
// (POST /accounts/new/imap/server in ./account-routes.js) and the OAuth2 callback (GET /oauth in
// workers/api.js). Both claim the signed link's single-use nonce, create the account, give the
// nonce back when the create fails, and send the visitor on to the calling application or to the
// account page. The two copies this replaced had drifted apart: the OAuth2 one answered in
// untranslated English and built the account page link from the raw account ID.

const Boom = require('@hapi/boom');

const { redis } = require('../db');
const settings = require('../settings');
const { claimFormNonce, releaseFormNonce } = require('../tools');
const { adminUrl } = require('./route-helpers');

/**
 * Where the visitor goes once the account exists: the calling application's redirect URL with the
 * account ID and its state appended, or the account's admin page when the link named none.
 *
 * @param {string|undefined} redirectUrl - The redirect URL the signed link carried, resolved against `serviceUrl`
 * @param {string|undefined} serviceUrl - The instance's Service URL
 * @param {Object} result - What Account.create() returned (`account`, `state`)
 * @returns {string}
 */
function setupRedirectUrl(redirectUrl, serviceUrl, result) {
    if (!redirectUrl) {
        return adminUrl`/admin/accounts/${result.account}`;
    }

    const url = new URL(redirectUrl, serviceUrl);
    url.searchParams.set('account', result.account);
    url.searchParams.set('state', result.state);
    return url.href;
}

/**
 * Claims the link's nonce, creates the account and returns the URL to send the visitor to.
 *
 * The nonce is claimed BEFORE create (SET NX), so a concurrent double-submit, a replayed callback
 * or one signed link spent on both arms (start OAuth2, then submit the same blob to the IMAP arm)
 * cannot create a second account. A link with no nonce skips the claim: setup and re-auth links
 * issued before nonces existed carry none, and the OAuth2 arm accepts them for that reason. When
 * create() fails the nonce is released so the visitor can retry. Accepted residual: if Redis fails
 * there too, the nonce stays consumed for its TTL and a fresh link is needed, the price of the
 * claim-before-create ordering that makes the dedupe atomic.
 *
 * @param {Object} request - The Hapi request; its `app.gt` translates the refusals
 * @param {Object} options
 * @param {Object} options.accountObject - An Account instance to create the account with
 * @param {Object} options.accountData - The account to create
 * @param {Object} [options.nonce] - The signed link's nonce (`n`) and its timestamp (`t`)
 * @param {string} [options.redirectUrl] - Where the calling application wants the visitor back
 * @returns {Promise<string>} The URL to redirect the visitor to
 */
async function completeAccountSetup(request, { accountObject, accountData, nonce, redirectUrl }) {
    const gt = request.app.gt;

    let nonceClaimed = false;
    if (nonce && nonce.n) {
        let claimed;
        try {
            claimed = await claimFormNonce(redis, nonce.n, nonce.t);
        } catch (err) {
            // A Redis failure is not a consumed nonce. Report it as a retryable server error
            // instead of misdiagnosing a valid setup URL as invalid or expired.
            request.logger.error({ msg: 'Failed to claim nonce for an account form request', err });
            throw Boom.boomify(new Error(gt.gettext('Temporary error, please try again')), { statusCode: 500 });
        }
        if (!claimed) {
            // SET NX returned null: the nonce key already exists, so this URL was already used.
            //
            // Reviewed, accepted (do not "fix" server-side): the LOSING side of a legitimate
            // concurrent double-submit lands here and sees this 403 even though the winning request
            // created the account. The client-side formSubmitting latch
            // (views/accounts/register/imap-server.hbs) is the primary guard; the residual is a
            // no-JS double-click, and even then this is strictly better than two duplicate
            // accounts. Storing the created account ID under the nonce key and redirecting the
            // loser to success is a possible future enhancement, not a bug.
            throw Boom.boomify(new Error(gt.gettext('Invalid or expired account setup URL')), { statusCode: 403 });
        }
        nonceClaimed = true;
    }

    let result;
    try {
        result = await accountObject.create(accountData);
    } catch (err) {
        if (nonceClaimed) {
            await releaseFormNonce(redis, nonce.n, request.logger);
        }
        throw err;
    }

    const serviceUrl = redirectUrl ? await settings.get('serviceUrl') : undefined;
    return setupRedirectUrl(redirectUrl, serviceUrl, result);
}

module.exports = { completeAccountSetup, setupRedirectUrl };
