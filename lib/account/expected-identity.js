'use strict';

const { REDIS_PREFIX } = require('../consts');

// An account can carry an expected identity: the address that must own it, set by an authenticated API
// caller through `expectedEmail` on POST /v1/authentication/form, POST /v1/account or
// PUT /v1/account/{account}. Every interactive setup checks it before writing credentials.
//
// How strong that is depends on the arm, and the difference is not cosmetic. On OAuth2 the provider
// vouches for the identity, so the pin genuinely stops someone binding a different mailbox. On IMAP the
// only evidence is what was typed into the form: the submitted address is checked, but the credentials
// beside it are a separate field, so a hand-crafted POST can still register the pinned address against a
// mailbox it does not own. The IMAP guarantee is therefore "the account is registered under the expected
// address", not "the account holds that mailbox". Do not restate it more strongly than that.
//
// Everything the two arms must agree on lives here - where the expectation is read from, which one wins,
// and what counts as a match - because the arms are 1500 lines apart in different workers and any of
// those drifting is a silently weaker constraint. How a rejection is PRESENTED is deliberately not here:
// both arms render views/account-identity-error.hbs, but only each arm knows where "try again" leads.
//
// What counts as EVIDENCE is the one thing each arm supplies itself, because it genuinely differs:
//
//   OAuth2 - the addresses the provider returned over a back-channel. Caller-supplied hints
//            (accountData.email, oauth2.auth.delegatedUser) are excluded on purpose, so for a delegated
//            or shared mailbox the expectation must name the authenticating principal, not the mailbox.
//   IMAP   - the address submitted on the form. The credentials still have to authenticate against the
//            server, but nothing proves the address belongs to that mailbox, so the guarantee is the
//            weaker "the account is registered under the expected address".

function normalizeEmail(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

// Fails closed: an empty expectation is not a licence to skip the check (callers must not call it in that
// case), and an empty or unusable identity list means we learned nothing about who authenticated, which
// is a rejection rather than a pass. That also makes a future provider that forgets to collect its
// identities reject setups instead of silently admitting them.
function matchesExpectedIdentity(expectedEmail, identities) {
    const expected = normalizeEmail(expectedEmail);
    if (!expected || !Array.isArray(identities)) {
        return false;
    }

    return identities.some(identity => normalizeEmail(identity) === expected);
}

// The expectation that applies to a setup: the one carried by the signed form blob, or failing that the
// one already pinned to the account it targets.
//
// The blob wins because it is a deliberate re-statement by the authenticated caller, and that is what
// gives a legitimate mailbox migration a way through. A blob carrying none (an older link, or the admin
// re-authenticate blob) inherits the stored pin instead of clearing it, which is what makes the
// constraint outlive the single link that introduced it.
//
// Redis is read lazily, only on that fallback: a pinned link would otherwise pay a round trip for a value
// it always discards. Reads the field directly rather than through Account.loadAccountData(), which
// hgetalls and decrypts the whole record - same single-field pattern as getAccountState().
// The expectation carried by a pending OAuth2 setup, whichever of the two shapes it arrives in.
//
// Both are written by the server for an authenticated caller and stored under a random nonce, so they are
// equally trustworthy - they differ only because two entry points build the pending record differently.
// The hosted form (lib/ui-routes/account-routes.js) copies the field into `_meta` alongside redirectUrl;
// POST /v1/account with oauth2.authorize stores the request payload as-is and rebuilds `_meta` from
// scratch, leaving the field at the top level. Reading only `_meta` silently skipped the check on that
// second path - on the very setup that decides which mailbox the account gets bound to - while still
// persisting the pin afterwards, so the constraint looked active when it had never run.
function pendingSetupExpectation(accountData, accountMeta) {
    return (accountMeta && accountMeta.expectedEmail) || (accountData && accountData.expectedEmail) || null;
}

// Returns the normalized form, so what gets persisted back onto the account does not depend on which
// branch produced it or on how the caller happened to capitalize the address.
async function resolveExpectedIdentity(redis, opts) {
    const { account, blobExpectation } = opts || {};

    const fromBlob = normalizeEmail(blobExpectation);
    if (fromBlob) {
        return fromBlob;
    }

    if (!account) {
        return null;
    }

    return normalizeEmail(await redis.hget(`${REDIS_PREFIX}iad:${account}`, 'expectedEmail')) || null;
}

module.exports = { normalizeEmail, matchesExpectedIdentity, pendingSetupExpectation, resolveExpectedIdentity };
