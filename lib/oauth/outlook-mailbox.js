'use strict';

// Decides which mailbox a Microsoft account setup binds once the OAuth2 callback knows who signed
// in. Three cases, checked in this order:
//
//   1. `oauth2.auth.delegatedUser` names a shared mailbox. The signed-in user authenticates and the
//      named mailbox is the one accessed; the account's address defaults to that mailbox when the
//      setup named none.
//   2. Legacy form: `delegated: true` plus an `email` that differs from the signed-in address. The
//      address is the shared mailbox and it is kept.
//   3. Anything else is the signed-in user's own mailbox, and the account takes their address.
//
// Pure, so the precedence can be tested without driving a whole callback.

/**
 * @param {Object} accountData - The pending account (`email`, `delegated`, `oauth2.auth.delegatedUser`)
 * @param {Object} userInfo - The resolved identity of the signed-in user (`email`)
 * @returns {{ email: (string|undefined), delegatedUser: (string|undefined) }} The account address,
 *   and the mailbox to access on the signed-in user's behalf when it is not their own
 */
function resolveOutlookMailbox(accountData, userInfo) {
    const delegatedUser = accountData.oauth2 && accountData.oauth2.auth && accountData.oauth2.auth.delegatedUser;

    if (delegatedUser) {
        return { email: accountData.email || delegatedUser, delegatedUser };
    }

    if (accountData.delegated && accountData.email && accountData.email !== userInfo.email) {
        return { email: accountData.email, delegatedUser: accountData.email };
    }

    return { email: userInfo.email, delegatedUser: undefined };
}

module.exports = { resolveOutlookMailbox };
