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
// It separates the endpoints, not every route to the outcome, and the difference matters for
// messages specifically. EmailEngine deletes a message by moving it to Trash, so `write` on
// `message` - which has to allow filing mail into a folder the caller names - reaches the same end
// state as the DELETE the same token is refused, and `\Deleted` can be set through the flag update
// for the same reason. Withholding DESTRUCTIVE from a message grant is therefore a statement of
// intent about message content rather than a wall, and it is described that way wherever a token is
// issued. For everything genuinely irreversible - a folder, an export, a template, a gateway, a
// blocklist entry, a queued message - there is no write-shaped route to the same result, and the
// axis is a hard boundary. Closing the message case would mean reading a destination folder and a
// flag name out of a payload and deciding whether they amount to a deletion - a judgement about
// intent, unlike the one payload rule this model does make (see the note on GROUP.SUBMIT, which
// refuses a field outright rather than interpreting its value).
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

    // Anything that hands a message to a mail server, including the delivery test. Note this reaches
    // stored mail as well as sending it: a submit payload may carry `reference: {message, action:
    // 'forward'}`, which reads the named message and delivers it. The check is route-level and does
    // not inspect payloads, so `submit` is not a promise of no read access.
    //
    // One payload field is refused anyway, by assertNoNetworkOverride() in ./route-helpers.js:
    // `proxy` decides where a session carrying the account's SMTP credentials connects, so a grant
    // to send mail would otherwise be a route to reading the credential that sends it. That is a
    // narrow exception rather than the start of a payload model - it is the only field here that
    // DISCLOSES a stored credential. `gateway` selects one to send through, which a send grant
    // reasonably covers and which reveals nothing (the same token cannot read GET /v1/gateways to
    // learn the ids), and `baseUrl` only points tracking links at a host of the caller's choosing.
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

// Every grant a non-HTTP surface can exercise once it has authenticated, rather than the one it
// nominally performs. These surfaces are checked once at login and never again, so a token is
// admitted only if it holds ALL of them.
//
// SMTP really is one operation: the server accepts a message and queues it. The IMAP proxy is not -
// after login lib/imapproxy/imap-server.js pipes the two sockets together, so the session can STORE
// \Deleted, EXPUNGE, APPEND, CREATE, DELETE and RENAME. Checking it as a single read would admit a
// token narrowed to reading and then hand it a session that can destroy the mailbox, which is a
// promise the surface cannot keep.
//
// Lives here rather than in lib/auth-token.js because it is policy that several places read - the
// admin form shows it to explain why a scope would be unusable - and auth-token.js reaches Redis,
// which a presentation module has no business loading.
const SURFACE_GRANTS = {
    smtp: [{ action: ACTION.SEND, group: GROUP.SUBMIT }],
    'imap-proxy': [
        { action: ACTION.READ, group: GROUP.MESSAGE },
        { action: ACTION.WRITE, group: GROUP.MESSAGE },
        { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE },
        { action: ACTION.WRITE, group: GROUP.MAILBOX },
        { action: ACTION.DESTRUCTIVE, group: GROUP.MAILBOX }
    ],
    // Not a submission surface: /metrics is an ordinary api-token route, so this mirrors its entry in
    // GROUP_ROUTES below. Listed with the others because the admin form shows all three together.
    metrics: [{ action: ACTION.READ, group: GROUP.DIAGNOSTICS }],

    // The MCP endpoint. Unlike smtp and imap-proxy this surface is checked per request, not once
    // at login (see PER_REQUEST_SURFACES below): an mcp-scoped token opens /mcp, and each tool
    // call is re-authenticated as the API request it dispatches, admitted only when that route's
    // grant is in this list - the surfaceAdmits() predicate below is the one place that rule is
    // written. The list must therefore cover every grant a tool the MCP registry exposes can
    // require - test/mcp-tools-test.js asserts exactly that, so a new plugins.mcp block on a
    // route outside these grants fails the build rather than shipping a tool that mcp-scoped
    // tokens cannot call.
    mcp: [
        { action: ACTION.READ, group: GROUP.ACCOUNT },
        { action: ACTION.READ, group: GROUP.MAILBOX },
        { action: ACTION.READ, group: GROUP.MESSAGE },
        { action: ACTION.WRITE, group: GROUP.MESSAGE },
        { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE },
        { action: ACTION.SEND, group: GROUP.SUBMIT },
        { action: ACTION.READ, group: GROUP.OUTBOX },
        { action: ACTION.READ, group: GROUP.TEMPLATE }
    ]
};

// The quantifier over SURFACE_GRANTS differs by surface, and consumers must not hard-code their
// own: the login-time surfaces (smtp, imap-proxy, metrics) admit a token only if it holds ALL of
// their grants, because they are checked once and then hand over a session; a per-request
// surface admits a request when ANY single grant covers it, because every request is checked on
// its own. The admin token form renders its scope warning from this distinction too.
const PER_REQUEST_SURFACES = new Set(['mcp']);

/**
 * Whether one operation is inside a surface's grant list. This is the per-request quantifier -
 * the api-token strategy asks it for the `mcp` scope, and test/mcp-tools-test.js asserts every
 * exposed tool against it, so the guardrail and the enforcement share one predicate.
 *
 * @param {String} scope - a SURFACE_GRANTS key
 * @param {{action: String, group: String}} grant - the operation, from routeGrant()
 * @returns {Boolean}
 */
function surfaceAdmits(scope, grant) {
    return (SURFACE_GRANTS[scope] || []).some(entry => entry.action === grant.action && entry.group === grant.group);
}

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

    // Reading a gateway and removing one. The two WRITES are in ADMIN below, because they can
    // redirect where the stored relay credentials are sent - so they are deliberately absent here
    // rather than listed in both places.
    [GROUP.GATEWAY]: ['GET /v1/gateways', 'GET /v1/gateway/{gateway}', 'DELETE /v1/gateway/{gateway}'],

    [GROUP.EVENTS]: ['GET /v1/changes'],

    [GROUP.DIAGNOSTICS]: [
        'GET /v1/stats',
        'GET /v1/delivery-test/check/{deliveryTest}',
        'GET /v1/pubsub/status',
        'GET /v1/autoconfig',
        // The Prometheus endpoint. Not a /v1 route and registered in workers/api.js rather than
        // lib/api-routes/index.js, so the route table test cannot see it - listed here anyway
        // because it authenticates with the same tokens. Without an entry it resolves to no group,
        // and a narrowed token is refused on it: a `metrics`-scoped token that set any permissions
        // at all became unusable, including one asking for exactly this.
        'GET /metrics'
    ],

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

        'POST /v1/tokens',
        'DELETE /v1/tokens/{token}',
        'GET /v1/tokens',
        // Who read whose mail with this credential. Admin because the trail is at least as sensitive
        // as the requests in it, and a narrowed token has no business reading its own audit record.
        'GET /v1/tokens/{token}',
        'GET /v1/tokens/{token}/log',
        // Deprecated pre-2.79 aliases of the three above (see lib/api-routes/token-routes.js)
        'POST /v1/token',
        'DELETE /v1/token/{token}',
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

        // The same shape as the account edit above, and for the same reason. Gateway.update() writes
        // only the keys the payload carries (lib/gateway.js:233), so a request setting just `host`
        // leaves the encrypted `user` and `pass` in place - and the next message routed through that
        // gateway performs SMTP AUTH against the new host with the customer's relay credentials.
        // Reading them back is masked; sending them somewhere is not.
        'POST /v1/gateway',
        'PUT /v1/gateway/edit/{gateway}',

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

// Inverted once at load, refusing a route that appears under two groups.
//
// The refusal is the point. Building this with `new Map(...)` let the later entry win silently, and
// it had already happened: the two gateway writes were listed under both `gateway` and `admin`, and
// only the order of the literal decided that the never-grantable one took effect. The route-table
// test cannot see it either - it compares this map's size against the route table, and a duplicate
// leaves the size unchanged. Throwing at load turns "whichever is written last" into a build
// failure, in a table where one of the two answers is a grant a customer must never be able to hold.
const ROUTE_GROUPS = new Map();
for (const [group, routes] of Object.entries(GROUP_ROUTES)) {
    for (const route of routes) {
        if (ROUTE_GROUPS.has(route)) {
            throw new Error(`${route} is listed under two permission groups, ${ROUTE_GROUPS.get(route)} and ${group}`);
        }
        ROUTE_GROUPS.set(route, group);
    }
}

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
    SURFACE_GRANTS,
    PER_REQUEST_SURFACES,
    surfaceAdmits,
    GRANTABLE_GROUPS,
    ACTION_VALUES,
    GROUP_VALUES,
    NEVER_GRANTABLE,
    IMPACT_ACTIONS,
    ROUTE_GROUPS,
    routeKey,
    routeGrant
};
