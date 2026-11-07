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
// The mailbox address (`mail` on the Graph profile, `email` in the id_token) is a directory attribute
// a tenant administrator can set to any address, in a domain the tenant never proved it owns, and
// Microsoft returns it unchanged. An address there is only evidence when its domain is one the issuing
// tenant has verified: the domain of the user principal name (which Entra ID only accepts in a
// verified domain), a domain the Graph branch read from /v1.0/organization, or an id_token that marks
// it verified with the `xms_edov` claim. Otherwise anyone administering any tenant could satisfy an
// expectedEmail pin for an address they do not own. Verified against Entra ID on 2026-11-07.
//
// `email` is the first verified identity. It used to fall back to the client_info address, which let
// the browser choose the account's persisted address and, through `username || email`, its login.
//
// `username` is the credential EmailEngine authenticates with (XOAUTH2), so it is verified-only with no
// clientInfo fallback. The profile's userPrincipalName is taken as-is rather than filtered as an address,
// matching the previous behavior - a tenant whose UPN is not email-shaped must still be able to log in.
function resolveOutlookUserInfo(sources) {
    const { clientInfo, idTokenPayload, profile, verifiedDomains } = sources || {};

    // isEmail already rejects non-strings, so these only normalize a miss to null.
    const asEmail = value => isEmail(value) || null;
    const asString = value => (typeof value === 'string' && value ? value : null);
    const domainOf = address => address.slice(address.lastIndexOf('@') + 1).toLowerCase();

    const profileUpn = asString(profile && profile.userPrincipalName);
    const idTokenUpn = asEmail(idTokenPayload && idTokenPayload.preferred_username);
    const upnAddresses = [idTokenUpn, asEmail(profileUpn)].filter(Boolean);

    const trustedDomains = new Set([...upnAddresses.map(domainOf), ...(verifiedDomains || []).map(domain => domain.toLowerCase())]);
    const vouched = address => trustedDomains.has(domainOf(address));

    const profileMail = asEmail(profile && profile.mail);
    const idTokenEmail = asEmail(idTokenPayload && idTokenPayload.email);
    const mailboxAddresses = [];
    if (profileMail && vouched(profileMail)) {
        mailboxAddresses.push(profileMail);
    }
    if (idTokenEmail && (idTokenPayload.xms_edov === true || vouched(idTokenEmail))) {
        mailboxAddresses.push(idTokenEmail);
    }

    // One list in preference order does both jobs: membership answers "did the provider vouch for this
    // address", and the first entry is the best address to show. Keeping two orderings in sync by hand
    // would be a silent bug the moment they drifted.
    const verifiedIdentities = [...new Set([...mailboxAddresses, ...upnAddresses])];

    return {
        name: asString(idTokenPayload && idTokenPayload.name) || asString(profile && profile.displayName) || asString(clientInfo && clientInfo.name),
        email: verifiedIdentities[0] || null,
        username: idTokenUpn || profileUpn,
        verifiedIdentities
    };
}

/**
 * The domains the signed-in user's tenant has verified, from Graph /v1.0/organization (covered by
 * User.Read). A Graph `mail` value is only identity evidence in one of these or in the domain of the
 * user principal name. An empty list (a personal Microsoft account has no organization, or the request
 * failed) leaves only the user principal name's domain, which narrows what is accepted and never
 * widens it.
 *
 * @param {Object} oAuth2Client - The Outlook OAuth2 client (`request()`, `apiBase`)
 * @param {string} accessToken
 * @param {Object} logger
 * @returns {Promise<string[]>}
 */
async function readTenantVerifiedDomains(oAuth2Client, accessToken, logger) {
    try {
        const res = await oAuth2Client.request(accessToken, `${oAuth2Client.apiBase}/v1.0/organization?$select=verifiedDomains`);
        return ((res && res.value) || [])
            .flatMap(org => (Array.isArray(org.verifiedDomains) ? org.verifiedDomains : []).map(domain => domain && domain.name))
            .filter(Boolean);
    } catch (err) {
        logger.warn({ msg: 'Could not read the verified domains of the Microsoft tenant', err });
        return [];
    }
}

module.exports = { resolveOutlookUserInfo, readTenantVerifiedDomains };
