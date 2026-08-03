'use strict';

// Builds the pending-setup record for a retry after an OAuth2 attempt the user can correct themselves -
// a consent screen with permissions unchecked, or signing in as an account the setup link is not pinned
// to. The retry is a fresh single-use setup, so it needs a record of its own.
//
// The subtlety is which parts of the rejected attempt to carry over. By the time either failure is
// detected, the provider branches have already rewritten accountData from whoever actually signed in:
// `email` holds the authenticated address, `name` may hold their display name, and `oauth2` holds their
// tokens. Copying that wholesale would let a rejected identity leak into the account the retry creates,
// while rebuilding from scratch would drop what the caller actually asked for.
//
// So the tokens go, and the caller's own intent comes back:
//
//   oauth2.auth.delegatedUser - names the MAILBOX TO BIND, not a credential. Dropping it silently turns a
//                               shared-mailbox setup into a personal one, so the retry would bind the
//                               principal's own mailbox while reporting success.
//   email                     - for a delegated setup this is the shared mailbox, and both delegation
//                               paths in the Outlook branch key on it. Overwriting it with the address
//                               the user is being steered towards breaks them.
//   name                      - filled in from the signed-in profile when the caller supplied none, and
//                               kept by `name || profile.name` on the retry, so the rejected user's
//                               display name would stick to the account and become its From name.
//
// `_meta` rides along unchanged: it carries the redirect URL, the expected identity and the single-use
// form nonce, which is claimed only on success and so is still unspent here.
function buildRetrySetup(accountData, requestedSetup, provider, accountMeta) {
    const { email, name, delegatedUser } = requestedSetup || {};

    return Object.assign({}, accountData, {
        oauth2: delegatedUser ? { provider, auth: { delegatedUser } } : { provider },
        email,
        name,
        _meta: accountMeta
    });
}

module.exports = { buildRetrySetup };
