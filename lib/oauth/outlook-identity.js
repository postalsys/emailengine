'use strict';

const { isEmail } = require('../utils/is-email');

// Resolves the Microsoft account identity from the sources the OAuth2 callback can have. Split out of
// workers/api.js because this is a TRUST BOUNDARY, and a trust boundary that exists only as an ordering
// of assignments inside a 300-line switch is one nobody can test or review.
//
// The sources are not equal:
//
//   clientInfo      - Microsoft's `client_info` blob. EmailEngine asks for it (lib/oauth/outlook.js sets
//                     client_info=1) and it comes back as a query parameter on the FRONT channel, i.e.
//                     through the user's browser. It is not signed and nothing verifies it, so whoever
//                     drives the callback URL chooses its contents.
//   idTokenPayload  - claims from the id_token returned by the token endpoint. Unverified as a token, but
//                     fetched over a direct TLS POST (see lib/oauth/decode-jwt-payload.js).
//   profile         - the MS Graph /v1.0/me response, also a back-channel request.
//
// Callers pass only the sources their branch actually has: the legacy IMAP-scope branch has clientInfo
// and the id_token, the Graph branch has the profile.
//
// `verifiedIdentities` therefore NEVER contains a clientInfo value. It is the only field callers may use
// to decide whether an authenticated identity satisfies an expected identity. Both the mailbox address
// and the user principal name are offered, because either can be the stable identity for a tenant and
// they routinely differ (user@contoso.com vs user@contoso.onmicrosoft.com).
//
// `email` prefers a verified value and falls back to clientInfo only when no back-channel source produced
// one. That fallback exists for OAuth2 apps predating the User.Read scope; it is rarely reached now, since
// the id_token carries preferred_username whenever `openid profile` is granted. The precedence matters
// beyond the identity check: accountData.email is persisted, shown in the admin UI, and used as the
// default From address, so a spoofable value winning there is a bug in its own right.
//
// `username` is the credential EmailEngine authenticates with (XOAUTH2), so it is verified-only with no
// clientInfo fallback. The profile's userPrincipalName is taken as-is rather than filtered as an address,
// matching the previous behavior - a tenant whose UPN is not email-shaped must still be able to log in.
function resolveOutlookUserInfo(sources) {
    const { clientInfo, idTokenPayload, profile } = sources || {};

    // isEmail already rejects non-strings, so these only normalize a miss to null.
    const asEmail = value => isEmail(value) || null;
    const asString = value => (typeof value === 'string' && value ? value : null);

    const profileUpn = asString(profile && profile.userPrincipalName);
    const idTokenUpn = asEmail(idTokenPayload && idTokenPayload.preferred_username);

    // One list in preference order does both jobs: membership answers "did the provider return this
    // address", and the first entry is the best address to show. Keeping two orderings in sync by hand
    // would be a silent bug the moment they drifted.
    const verifiedIdentities = [
        ...new Set([asEmail(profile && profile.mail), asEmail(idTokenPayload && idTokenPayload.email), idTokenUpn, asEmail(profileUpn)].filter(Boolean))
    ];

    return {
        name: asString(idTokenPayload && idTokenPayload.name) || asString(profile && profile.displayName) || asString(clientInfo && clientInfo.name),
        email: verifiedIdentities[0] || asEmail(clientInfo && clientInfo.preferred_username),
        username: idTokenUpn || profileUpn,
        verifiedIdentities
    };
}

module.exports = { resolveOutlookUserInfo };
