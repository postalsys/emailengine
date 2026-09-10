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

    // Instance settings and the two queues. A write here reaches the global webhook target and
    // every notification knob, and is disclosed as such wherever the grant is offered. The keys
    // that would make the holder more than a settings editor - operator code, proxies, secrets,
    // the MCP and audit switches - are refused to a narrowed token by assertNoPrivilegedSettings()
    // in ./route-helpers.js, keyed on PRIVILEGED_SETTINGS_KEYS in lib/settings.js.
    SETTINGS: 'settings',

    // OAuth2 applications. Secrets are write-only (every read masks them), but a write can move
    // an application's redirect URL, which is where the provider sends authorization codes.
    OAUTH2: 'oauth2',

    // The license: read it, apply one, remove it
    LICENSE: 'license',

    // Access tokens: list, inspect, read the audit log of, revoke. Minting is NOT here - it stays
    // in ADMIN, because a token that can mint tokens can widen itself.
    TOKEN: 'token',

    // Adding accounts and gateways, and reconfiguring them, including where they connect. Its own
    // group rather than a write on `account` or `gateway` because both records keep their stored
    // credential across a partial update, so a change to nothing but `host` makes the next
    // connection authenticate to the new host with the old password - a token issued with write
    // access to accounts before this group existed must not gain that. Disclosed on every screen
    // that offers the grant. `proxy` in these payloads is refused to a narrowed token by
    // assertNoNetworkOverride(), like the submit payloads.
    PROVISIONING: 'provisioning',

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
    ],

    // The management half of the MCP endpoint: the same door, checked per request the same way,
    // but a second scope with its own table. A second scope rather than a longer `mcp` list on
    // purpose: the "Full access" level of the consent page used to mint a token with no
    // permissions record, bounded by the `mcp` table alone, and growing that table would have
    // handed every such token the management tools on upgrade. This one leaves every issued
    // credential exactly as wide as it was.
    //
    // Reads about the instance, the writes that operate it, and the deletions an administrator
    // makes. Deliberately absent: `send/submit` (mail, in the table above), `export` (one call
    // archives an account), `events` (a stream, not a tool), `destructive/license` (no agent use
    // case, only harm), and every `admin` route. The three read pairs shared with the mail table
    // are shared on purpose - an agent managing the instance needs to list accounts too.
    'mcp-manage': [
        { action: ACTION.READ, group: GROUP.ACCOUNT },
        { action: ACTION.WRITE, group: GROUP.ACCOUNT },
        { action: ACTION.DESTRUCTIVE, group: GROUP.ACCOUNT },
        { action: ACTION.READ, group: GROUP.SETTINGS },
        { action: ACTION.WRITE, group: GROUP.SETTINGS },
        { action: ACTION.READ, group: GROUP.OAUTH2 },
        { action: ACTION.WRITE, group: GROUP.OAUTH2 },
        { action: ACTION.DESTRUCTIVE, group: GROUP.OAUTH2 },
        { action: ACTION.READ, group: GROUP.LICENSE },
        { action: ACTION.WRITE, group: GROUP.LICENSE },
        { action: ACTION.READ, group: GROUP.TOKEN },
        { action: ACTION.DESTRUCTIVE, group: GROUP.TOKEN },
        { action: ACTION.READ, group: GROUP.PROVISIONING },
        { action: ACTION.WRITE, group: GROUP.PROVISIONING },
        { action: ACTION.READ, group: GROUP.GATEWAY },
        { action: ACTION.DESTRUCTIVE, group: GROUP.GATEWAY },
        { action: ACTION.READ, group: GROUP.WEBHOOK },
        { action: ACTION.READ, group: GROUP.BLOCKLIST },
        { action: ACTION.WRITE, group: GROUP.BLOCKLIST },
        { action: ACTION.DESTRUCTIVE, group: GROUP.BLOCKLIST },
        { action: ACTION.READ, group: GROUP.TEMPLATE },
        { action: ACTION.WRITE, group: GROUP.TEMPLATE },
        { action: ACTION.DESTRUCTIVE, group: GROUP.TEMPLATE },
        { action: ACTION.READ, group: GROUP.OUTBOX },
        { action: ACTION.DESTRUCTIVE, group: GROUP.OUTBOX },
        { action: ACTION.READ, group: GROUP.DIAGNOSTICS },
        { action: ACTION.READ, group: GROUP.LOGS }
    ]
};

// The two MCP scopes by what they are for, so the modules that reason about "the management
// half" and "the mail half" (the access sections, the instructions, the catalog grouping) name
// them through this rather than spelling the slugs again.
const MCP_SCOPES = {
    manage: 'mcp-manage',
    mail: 'mcp'
};

// The quantifier over SURFACE_GRANTS differs by surface, and consumers must not hard-code their
// own: the login-time surfaces (smtp, imap-proxy, metrics) admit a token only if it holds ALL of
// their grants, because they are checked once and then hand over a session; a per-request
// surface admits a request when ANY single grant covers it, because every request is checked on
// its own. The admin token form renders its scope warning from this distinction too.
const PER_REQUEST_SURFACES = new Set([MCP_SCOPES.mail, MCP_SCOPES.manage]);

// The `action:group` spelling of a pair, the key every set of pairs below is built on
const grantKey = grant => `${grant.action}:${grant.group}`;

const grantKeySet = grants => new Set((grants || []).map(grantKey));

// One membership set per surface, built once: the per-request predicate below runs for every
// tool of every tools/list and for every MCP-dispatched request, and the management table has
// two dozen entries
const SURFACE_GRANT_KEYS = Object.fromEntries(Object.entries(SURFACE_GRANTS).map(([scope, grants]) => [scope, grantKeySet(grants)]));

/**
 * Whether one operation is inside a surface's grant list. This is the per-request quantifier -
 * the api-token strategy asks it for the MCP scopes, and test/mcp-tools-test.js asserts every
 * exposed tool against it, so the guardrail and the enforcement share one predicate.
 *
 * @param {String} scope - a SURFACE_GRANTS key
 * @param {{action: String, group: String}} grant - the operation, from routeGrant()
 * @returns {Boolean}
 */
function surfaceAdmits(scope, grant) {
    const keys = SURFACE_GRANT_KEYS[scope];
    return !!keys && keys.has(grantKey(grant));
}

/**
 * Whether the per-request surface scopes a token holds admit one operation.
 *
 * The rule the api-token strategy applies to an MCP-dispatched request: a token holding `mcp`,
 * `mcp-manage` or both is admitted to a route when any held scope's table covers the route's
 * grant. Written once here so the strategy and tools/list (through surfaceBoundAdmits) cannot
 * disagree about which scope reaches which tool.
 *
 * @param {Array} scopes - the token's scope list
 * @param {{action: String, group: String}} grant - the operation, from routeGrant()
 * @returns {Boolean}
 */
function perRequestSurfaceAdmits(scopes, grant) {
    return Array.isArray(scopes) && scopes.some(scope => PER_REQUEST_SURFACES.has(scope) && surfaceAdmits(scope, grant));
}

/**
 * Whether a token's scopes leave one operation reachable over MCP at all.
 *
 * A token with no scope list, with `*`, or with `api` reaches every route its permissions allow,
 * so the bound is only the surface tables of the per-request scopes it holds. For tools/list,
 * which advertises a credential the tools it can actually call: the permission record is the
 * other half of that answer, and lib/token-permissions.js owns it.
 *
 * @param {Object} tokenData - the token record, as the auth strategy leaves it in artifacts
 * @param {{action: String, group: String}} grant - the operation, from routeGrant()
 * @returns {Boolean}
 */
function surfaceBoundAdmits(tokenData, grant) {
    const scopes = tokenData && tokenData.scopes;
    if (!Array.isArray(scopes) || scopes.includes('*') || scopes.includes('api')) {
        return true;
    }
    return perRequestSurfaceAdmits(scopes, grant);
}

/**
 * What a `sess_` session token may reach.
 *
 * Deliberately not a SURFACE_GRANTS entry: those are token scopes an operator picks on the token
 * form, and this is not one. A session token is minted by the message browser page for its own
 * fetches (lib/ui-routes/account-routes.js), lives in the page HTML where any script on it can read
 * it, and is bound to the account whose page issued it.
 *
 * The list is exactly what static/js/ee-client.js calls: read the account and its folders, read,
 * flag, move, upload and delete messages, and submit. Before it existed the credential skipped the
 * permission check entirely, which let a page-readable token reach every api-tagged route naming
 * its account - including `PUT /v1/account/{account}`, which rewrites the account's webhook target
 * and credentials, and `GET /v1/account/{account}/oauth-token`, which hands out the account's live
 * provider access token. Both are in the never-grantable ADMIN group that no issued token may hold,
 * and this is what makes that true of session tokens too.
 *
 * Per-request, like the mcp surface: the browser calls one route at a time.
 */
const SESSION_TOKEN_GRANTS = [
    { action: ACTION.READ, group: GROUP.ACCOUNT },
    { action: ACTION.READ, group: GROUP.MAILBOX },
    { action: ACTION.READ, group: GROUP.MESSAGE },
    { action: ACTION.WRITE, group: GROUP.MESSAGE },
    { action: ACTION.DESTRUCTIVE, group: GROUP.MESSAGE },
    { action: ACTION.SEND, group: GROUP.SUBMIT }
];

/**
 * Whether a session token may perform one operation on one account.
 *
 * The account is half the rule rather than a detail of it. A session token is bound to the account
 * whose page minted it, so a route that names no account is outside its scope by construction - and
 * `GET /v1/accounts`, which lists every account on the instance, resolves to the same read/account
 * grant as the account page the browser does need. The grant list cannot tell those two apart, so
 * the binding is what separates them, and both halves live here so the enforcement and the
 * guardrail ask one question.
 *
 * @param {{action: String, group: String}} grant - the operation, from routeGrant()
 * @param {Object} [opts]
 * @param {String} [opts.account] - the account the request names, from request.params
 * @returns {Boolean}
 */
const SESSION_TOKEN_GRANT_KEYS = grantKeySet(SESSION_TOKEN_GRANTS);

function sessionTokenAdmits(grant, opts) {
    if (!opts || !opts.account) {
        return false;
    }
    return SESSION_TOKEN_GRANT_KEYS.has(grantKey(grant));
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
    // configuration are NOT here - see the note on those two entries under PROVISIONING.
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

    // Reading a gateway and removing one. The two WRITES are in PROVISIONING below, because they
    // can redirect where the stored relay credentials are sent - so they are deliberately absent
    // here rather than listed in both places.
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

    // The five groups below used to be the admin block. They were split out so an agent that
    // manages the instance can hold them, and each went to a NEW group rather than into one that
    // already existed: a record cannot name a group that did not exist when it was written, so no
    // token issued before the split gained a route from it. test/api-routes-table-test.js asserts
    // the pre-split groups still hold exactly the routes they held.

    [GROUP.SETTINGS]: ['GET /v1/settings', 'POST /v1/settings', 'GET /v1/settings/queue/{queue}', 'PUT /v1/settings/queue/{queue}'],

    [GROUP.OAUTH2]: [
        'GET /v1/oauth2',
        'POST /v1/oauth2',
        'GET /v1/oauth2/{app}',
        'PUT /v1/oauth2/{app}',
        'DELETE /v1/oauth2/{app}',
        'POST /v1/oauth2/{app}/verify'
    ],

    [GROUP.LICENSE]: ['GET /v1/license', 'POST /v1/license', 'DELETE /v1/license'],

    // Everything about tokens except minting one, which is under ADMIN
    [GROUP.TOKEN]: [
        'GET /v1/tokens',
        'DELETE /v1/tokens/{token}',
        // Who read whose mail with this credential. The trail is at least as sensitive as the
        // requests in it, which the group description says.
        'GET /v1/tokens/{token}',
        'GET /v1/tokens/{token}/log',
        // Deprecated pre-2.79 aliases (see lib/api-routes/token-routes.js)
        'DELETE /v1/token/{token}',
        'GET /v1/tokens/account/{account}'
    ],

    [GROUP.PROVISIONING]: [
        // Editing an account is a credential operation even when the payload carries no credential,
        // which is why it sits here and not in the `account` group. `imap`, `smtp` and `oauth2`
        // accept `partial: true`, and Account.persistUpdate() then merges the STORED object over
        // the payload (lib/account.js:858), so `auth.pass` survives a request that only changes
        // `host`. An 'imap' key also arms the reconnect gate, so the worker promptly authenticates
        // to the new host with the old password. The same route retargets the per-account
        // `webhooks` URL, which would stream future message notifications - body text included, up
        // to notifyTextSize - somewhere else entirely. `proxy` is the one field refused outright.
        'PUT /v1/account/{account}',

        // Adds an account, so it widens what the instance holds. Grouped with the hosted form below
        // for the same reason, and it can set the same webhook target as the edit above.
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
        'POST /v1/verifyAccount'
    ],

    // Everything that hands out a lasting credential or reads one back. This block is the safety
    // property of the whole model: while a narrowed token cannot reach any of it, it cannot mint a
    // token and cannot read a live provider credential, so it cannot widen itself. The settings and
    // provisioning writes above can change a great deal, but nothing they change hands the caller
    // a credential it did not already hold - the keys that would (operator code, proxies, secrets)
    // are refused to a narrowed token per key.
    [GROUP.ADMIN]: [
        'POST /v1/tokens',
        // Deprecated pre-2.79 alias of the mint (see lib/api-routes/token-routes.js)
        'POST /v1/token',

        // Returns a live OAuth2 access token for the account: a mail credential in its own right,
        // which outlives any narrowing on the token that fetched it
        'GET /v1/account/{account}/oauth-token',

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
    MCP_SCOPES,
    PER_REQUEST_SURFACES,
    grantKey,
    surfaceAdmits,
    perRequestSurfaceAdmits,
    surfaceBoundAdmits,
    SESSION_TOKEN_GRANTS,
    sessionTokenAdmits,
    GRANTABLE_GROUPS,
    ACTION_VALUES,
    GROUP_VALUES,
    NEVER_GRANTABLE,
    IMPACT_ACTIONS,
    ROUTE_GROUPS,
    routeKey,
    routeGrant
};
