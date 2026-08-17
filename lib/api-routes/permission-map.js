'use strict';

// The vocabulary a narrowed access token is written in, and the mapping from every registered /v1
// route onto it. Published per operation into /swagger.json as `x-ee-action` and `x-ee-group`, and
// read at request time by the api-token strategy, so a customer can see what each endpoint requires
// and the enforcement cannot disagree with the documentation.
//
// Two axes, both subtractive. `actions` says what a token may do, `groups` says what it may touch.
// Verbs are deliberately absent from the groups: `actions` already separates them, and a
// `message-delete` group would make two axes say the same thing.

const { resolveImpact, IMPACT } = require('./operation-impact');
const { pluginOptions } = require('./route-metadata');

// What a token may be allowed to do. Named apart from the impacts on purpose: `readonly` and
// `sends` describe a route, while `read` and `send` describe a grant on a credential, and the
// grant is written by whoever issues the token.
const ACTION = {
    READ: 'read',
    WRITE: 'write',
    SEND: 'send',
    DESTRUCTIVE: 'destructive'
};

// Splitting DESTRUCTIVE out from WRITE is the point of the axis rather than a detail of it: "an
// agent that can file and reply but not delete" is one bit, and it is the shape most often asked
// for.
//
// Has to stay total over IMPACT - an impact with no action here resolves to undefined, which reads
// as an unclassifiable route and denies. test/api-routes-table-test.js asserts the totality.
const IMPACT_ACTIONS = {
    [IMPACT.READONLY]: ACTION.READ,
    [IMPACT.WRITE]: ACTION.WRITE,
    [IMPACT.SENDS]: ACTION.SEND,
    [IMPACT.DESTRUCTIVE]: ACTION.DESTRUCTIVE
};

// What a token may be allowed to touch. Cut by what a grant exposes rather than by the tag the
// documentation files a route under: the display tags group `GET /v1/pubsub/status` with OAuth2
// client-secret writes, put the instance-wide `GET /v1/changes` stream under Account, and file the
// harmless `GET /v1/autoconfig` under Settings. Reusing them would mean a grant whose blast radius
// depends on a documentation decision.
const GROUP = {
    // Account lifecycle and connection state. Credential reads are NOT here, see ADMIN.
    ACCOUNT: 'account',

    // Folder shape: create, rename, delete, list
    MAILBOX: 'mailbox',

    // Mail content, including the bulk actions. The largest group, and where `actions` does most
    // of the work.
    MESSAGE: 'message',

    // Anything that hands a message to a mail server, including the delivery test
    SUBMIT: 'submit',

    // The sending queue: inspect and cancel
    OUTBOX: 'outbox',

    // Bulk export. Its own group because one call archives the whole account, so a token allowed
    // to read messages should not get that for free.
    EXPORT: 'export',

    TEMPLATE: 'template',
    BLOCKLIST: 'blocklist',
    WEBHOOK: 'webhook',

    // SMTP gateways, which hold outbound SMTP credentials
    GATEWAY: 'gateway',

    // The instance-wide change stream. Its own group because it is a firehose over every account
    // rather than a request about one, so it should not ride along with an account grant.
    EVENTS: 'events',

    // Reads about the instance and its connections. Nothing here carries a credential or the
    // contents of a message - the account log did, which is why it has its own group.
    DIAGNOSTICS: 'diagnostics',

    // The per-account log. Its own group because it discloses strictly more than any other read:
    // the entries are the raw ImapFlow trace, so folder names, UIDs and untagged ENVELOPE responses
    // carrying subjects and correspondents all land in it, and with EENGINE_LOG_RAW set the server
    // frames go in whole. Granting it alongside `diagnostics` would have hidden mail content behind
    // a word that promises none, and folding it into `message` would have made every reader of a
    // mailbox a reader of the protocol trace as well.
    LOGS: 'logs',

    // Never grantable. See NEVER_GRANTABLE below.
    ADMIN: 'admin'
};

// Groups a `permissions` record may never name. The enforcement is in lib/token-permissions.js;
// what lives here is the policy it reads.
//
// A deny set rather than an absence from the grantable list, so widening the grantable list can
// never quietly reopen these.
const NEVER_GRANTABLE = new Set([GROUP.ADMIN]);

const GRANTABLE_GROUPS = Object.values(GROUP).filter(group => !NEVER_GRANTABLE.has(group));

// Membership sets for the two vocabularies. lib/token-permissions.js rejects a record naming
// anything outside them, which is what makes an unknown value a denial rather than something a
// reader silently drops.
//
// GROUP_VALUES deliberately includes ADMIN even though no record may name it: a record that does is
// well-formed but refused, which is a different answer from malformed, and the reason for the
// refusal should be "you may never have this" rather than "I could not read that".
const ACTION_VALUES = new Set(Object.values(ACTION));
const GROUP_VALUES = new Set(Object.values(GROUP));

/**
 * Identity of a route, in the `METHOD /path` form the rest of the test and helper code already uses
 * for the same purpose, so the two listings of these 82 routes can be diffed against each other.
 * Hapi reports a lowercase method on both `server.table()` entries and a live `request.route`.
 */
function routeKey(method, path) {
    return `${String(method).toUpperCase()} ${path}`;
}

// Every registered /v1 operation, by group. One entry per route rather than a rule per tag: a rule
// would give a newly added route the group of whatever tag it happened to carry, where an explicit
// entry means a new route has no group until someone chooses one, and no group is a denial.
//
// Grouped this way round because the access-control surface is then readable in one pass - the ADMIN
// block below IS the list of everything a narrowed token can never reach, rather than something a
// reviewer has to assemble by grepping. test/api-routes-table-test.js asserts this and the real
// route table agree exactly in both directions, so an added, removed or renamed route fails the
// build rather than drifting.
const GROUP_ROUTES = {
    // Reading an account and operating on its connection. Creating one and editing its
    // configuration are NOT here - see the note on those two entries under ADMIN.
    [GROUP.ACCOUNT]: [
        'GET /v1/accounts',
        'GET /v1/account/{account}',
        'DELETE /v1/account/{account}',
        'PUT /v1/account/{account}/flush',
        'PUT /v1/account/{account}/reconnect',
        'PUT /v1/account/{account}/sync',
        'GET /v1/account/{account}/server-signatures'
    ],

    [GROUP.MAILBOX]: [
        'GET /v1/account/{account}/mailboxes',
        'POST /v1/account/{account}/mailbox',
        'PUT /v1/account/{account}/mailbox',
        'DELETE /v1/account/{account}/mailbox'
    ],

    [GROUP.MESSAGE]: [
        'GET /v1/account/{account}/messages',
        'POST /v1/account/{account}/search',
        'GET /v1/account/{account}/message/{message}',
        'PUT /v1/account/{account}/message/{message}',
        'DELETE /v1/account/{account}/message/{message}',
        'PUT /v1/account/{account}/message/{message}/move',
        'GET /v1/account/{account}/message/{message}/source',
        'POST /v1/account/{account}/message',
        'GET /v1/account/{account}/text/{text}',
        'GET /v1/account/{account}/attachment/{attachment}',
        'PUT /v1/account/{account}/messages',
        'PUT /v1/account/{account}/messages/move',
        'PUT /v1/account/{account}/messages/delete'
    ],

    [GROUP.SUBMIT]: [
        'POST /v1/account/{account}/submit',
        'POST /v1/account/{account}/message/{message}/submit',
        // Sends a real message to a probe address, so it belongs with sending rather than with the
        // diagnostics read that later collects the result
        'POST /v1/delivery-test/account/{account}'
    ],

    [GROUP.OUTBOX]: ['GET /v1/outbox', 'GET /v1/outbox/{queueId}', 'DELETE /v1/outbox/{queueId}'],

    [GROUP.EXPORT]: [
        'POST /v1/account/{account}/export',
        'GET /v1/account/{account}/exports',
        'GET /v1/account/{account}/export/{exportId}',
        'GET /v1/account/{account}/export/{exportId}/download',
        'DELETE /v1/account/{account}/export/{exportId}'
    ],

    [GROUP.TEMPLATE]: [
        'GET /v1/templates',
        'POST /v1/templates/template',
        'GET /v1/templates/template/{template}',
        'PUT /v1/templates/template/{template}',
        'DELETE /v1/templates/template/{template}',
        'DELETE /v1/templates/account/{account}'
    ],

    [GROUP.BLOCKLIST]: ['GET /v1/blocklists', 'GET /v1/blocklist/{listId}', 'POST /v1/blocklist/{listId}', 'DELETE /v1/blocklist/{listId}'],

    [GROUP.WEBHOOK]: ['GET /v1/webhookRoutes', 'GET /v1/webhookRoutes/webhookRoute/{webhookRoute}'],

    [GROUP.GATEWAY]: ['GET /v1/gateways', 'POST /v1/gateway', 'GET /v1/gateway/{gateway}', 'PUT /v1/gateway/edit/{gateway}', 'DELETE /v1/gateway/{gateway}'],

    [GROUP.EVENTS]: ['GET /v1/changes'],

    [GROUP.DIAGNOSTICS]: ['GET /v1/stats', 'GET /v1/delivery-test/check/{deliveryTest}', 'GET /v1/pubsub/status', 'GET /v1/autoconfig'],

    [GROUP.LOGS]: ['GET /v1/logs/{account}'],

    // Everything that hands out a lasting credential or widens what the instance can do. This block
    // is the safety property of the whole model: while a narrowed token cannot reach any of it, it
    // cannot read the settings blob, cannot read a stored OAuth2 credential, and cannot mint or
    // revoke a token, so it cannot widen itself.
    [GROUP.ADMIN]: [
        'GET /v1/settings',
        'POST /v1/settings',
        'GET /v1/settings/queue/{queue}',
        'PUT /v1/settings/queue/{queue}',

        'GET /v1/oauth2',
        'POST /v1/oauth2',
        'GET /v1/oauth2/{app}',
        'PUT /v1/oauth2/{app}',
        'DELETE /v1/oauth2/{app}',
        'POST /v1/oauth2/{app}/verify',

        'GET /v1/license',
        'POST /v1/license',
        'DELETE /v1/license',

        'POST /v1/token',
        'DELETE /v1/token/{token}',
        'GET /v1/tokens',
        'GET /v1/tokens/account/{account}',

        // Returns a live OAuth2 access token for the account: a mail credential in its own right,
        // which outlives any narrowing on the token that fetched it
        'GET /v1/account/{account}/oauth-token',

        // Editing an account is a credential operation even when the payload carries no credential,
        // which is why it sits here and not in the grantable `account` group. `imap`, `smtp` and
        // `oauth2` accept `partial: true`, and Account.persistUpdate() then merges the STORED object
        // over the payload (lib/account.js:858), so `auth.pass` survives a request that only changes
        // `host`. An 'imap' key also arms the reconnect gate, so the worker promptly authenticates
        // to the new host with the old password. The same route retargets `proxy` and the
        // per-account `webhooks` URL, which would stream future message notifications - body text
        // included, up to notifyTextSize - somewhere else entirely.
        'PUT /v1/account/{account}',

        // Adds an account, so it widens what the instance holds. Grouped with the hosted form below
        // for the same reason, and it can set the same webhook and proxy targets as the edit above.
        'POST /v1/account',

        // Mints a hosted account-add URL, so it grows the set of accounts the instance holds
        'POST /v1/authentication/form',

        // Connects to a supplied host with supplied credentials
        'POST /v1/verifyAccount',

        // The deprecated Document Store. Disabled by default and leaving the releases on
        // 2026-10-01, so keeping it out of the grantable vocabulary means the removal does not
        // retire a slug a customer had written into a token.
        'POST /v1/chat/{account}',
        'POST /v1/unified/search'
    ]
};

// Inverted once at load. Object.entries over a literal cannot carry a duplicate route silently -
// a route listed under two groups would have to be spelled twice, and the round-trip assertion in
// test/api-routes-table-test.js counts entries, so the second one cannot hide.
const ROUTE_GROUPS = new Map(Object.entries(GROUP_ROUTES).flatMap(([group, routes]) => routes.map(route => [route, group])));

/**
 * Resolves the action an operation requires.
 *
 * @param {String} [declared] - the route's `x-ee-impact`, if it sets one
 * @param {String} method - HTTP method
 * @returns {String|null} one of ACTION, or null when the impact does not resolve
 */
function resolveAction(declared, method) {
    const impact = resolveImpact(declared, method);
    return impact ? IMPACT_ACTIONS[impact] || null : null;
}

/**
 * The grant a route requires, for a Hapi route from `server.table()` or a live `request.route`.
 *
 * Either half can be null, and null always means deny: an operation whose action or group does not
 * resolve is one this vocabulary does not describe, and guessing is how a route ends up ungoverned.
 * The route table test asserts neither half is ever null for a registered /v1 route, so a null here
 * means the table and the routes have diverged.
 *
 * @param {Object} route - `server.table()` entry or `request.route`
 * @returns {{action: (String|null), group: (String|null)}}
 */
function routeGrant(route) {
    return {
        action: resolveAction(pluginOptions(route)['x-ee-impact'], route && route.method),
        group: ROUTE_GROUPS.get(routeKey(route && route.method, route && route.path)) || null
    };
}

module.exports = {
    ACTION,
    GROUP,
    GRANTABLE_GROUPS,
    ACTION_VALUES,
    GROUP_VALUES,
    NEVER_GRANTABLE,
    IMPACT_ACTIONS,
    ROUTE_GROUPS,
    routeKey,
    routeGrant
};
