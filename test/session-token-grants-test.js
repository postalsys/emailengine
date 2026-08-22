'use strict';

// What a browse-page `sess_` token may reach (SESSION_TOKEN_GRANTS in
// lib/api-routes/permission-map.js), asserted against the real route table.
//
// The credential is minted by the message browser page for its own fetches and lives in the page
// HTML, where any script on the page can read it - unlike the HttpOnly session cookie it rides on.
// It used to skip the permission model entirely, so it reached every api-tagged route naming its
// account. This pins both halves of the fix: the browser can still do its job, and the routes that
// hand out a credential or rewrite where one is sent are refused.
//
// Pure route-table reading plus the two policy modules; no Redis, no server.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const { routeGrant, sessionTokenAdmits, SESSION_TOKEN_GRANTS, NEVER_GRANTABLE, GROUP, ACTION } = require('../lib/api-routes/permission-map');

// Requiring lib/api-routes opens Redis and BullMQ handles that outlive the tests.
registerRedisTeardown(redis);

// Every request static/js/ee-client.js makes, as (method, path) pairs. The message browser is the
// only thing that holds one of these tokens, so this list is the requirement - a grant list that
// refuses any of these breaks the page.
const BROWSER_ROUTES = [
    'GET /v1/account/{account}',
    'GET /v1/account/{account}/mailboxes',
    'GET /v1/account/{account}/messages',
    'GET /v1/account/{account}/message/{message}',
    'GET /v1/account/{account}/message/{message}/source',
    'GET /v1/account/{account}/attachment/{attachment}',
    'GET /v1/account/{account}/text/{text}',
    'PUT /v1/account/{account}/message/{message}',
    'PUT /v1/account/{account}/message/{message}/move',
    'DELETE /v1/account/{account}/message/{message}',
    'POST /v1/account/{account}/message',
    'POST /v1/account/{account}/submit',
    'POST /v1/account/{account}/message/{message}/submit'
];

// Routes a session token must never reach. The first two are the escalation the grant list exists
// to close: one rewrites the account's webhook target and stored credentials, the other hands out
// the account's live provider access token. Both name {account}, so the account binding - the only
// check a session token used to face - lets them straight through.
const REFUSED_ROUTES = [
    'PUT /v1/account/{account}',
    'GET /v1/account/{account}/oauth-token',
    'DELETE /v1/account/{account}',
    'POST /v1/account/{account}/export',
    'GET /v1/logs/{account}',
    'DELETE /v1/templates/account/{account}',
    'POST /v1/account/{account}/mailbox',
    'DELETE /v1/account/{account}/mailbox'
];

test('session token grants', async t => {
    const { routes } = await captureApiRoutes();
    const byKey = new Map(routes.map(route => [route.route, route]));

    // Models a request the way the strategy asks the question: the account comes from
    // request.params, so a route whose path names none carries none.
    const admitsRoute = route => sessionTokenAdmits(routeGrant(route), { account: /\{account\}/.test(route.path) ? 'acct-1' : undefined });

    const admits = key => {
        const route = byKey.get(key);
        assert.ok(route, `${key} is not a registered route - update this test with the route table`);
        return admitsRoute(route);
    };

    await t.test('covers every request the message browser makes', () => {
        const refused = BROWSER_ROUTES.filter(key => !admits(key));
        assert.deepEqual(refused, [], `the message browser would break on: ${JSON.stringify(refused)}`);
    });

    await t.test('refuses the routes that would widen the credential', () => {
        const allowed = REFUSED_ROUTES.filter(key => admits(key));
        assert.deepEqual(allowed, [], `a page-readable session token must not reach: ${JSON.stringify(allowed)}`);
    });

    await t.test('never admits the never-grantable group, whatever the action', () => {
        // Belt and braces over the list above: no entry may name ADMIN, so no route in that group
        // can be admitted by any action.
        for (const grant of SESSION_TOKEN_GRANTS) {
            assert.ok(!NEVER_GRANTABLE.has(grant.group), `SESSION_TOKEN_GRANTS names the never-grantable group ${grant.group}`);
        }

        for (const action of Object.values(ACTION)) {
            assert.equal(sessionTokenAdmits({ action, group: GROUP.ADMIN }, { account: 'acct-1' }), false, `admin/${action} must never be admitted`);
        }
    });

    await t.test('admits nothing outside the account it is bound to', () => {
        // The binding is what keeps the instance-wide routes out, and it is checked as part of the
        // same question rather than left to the caller. Asserted over the whole table.
        const admitted = routes.filter(route => route.path.startsWith('/v1/') && admitsRoute(route)).map(route => route.route);

        const accountless = admitted.filter(key => !/\{account\}/.test(key));
        assert.deepEqual(accountless, [], `session tokens must not reach routes that name no account: ${JSON.stringify(accountless)}`);

        // GET /v1/accounts is the case this rule exists for: it lists every account on the
        // instance and resolves to the same read/account grant as the account page the browser
        // needs, so only the binding separates the two.
        assert.equal(admitsRoute(byKey.get('GET /v1/accounts')), false);
        assert.equal(admitsRoute(byKey.get('GET /v1/account/{account}')), true);
    });

    await t.test('an unclassified route is refused rather than admitted', () => {
        // routeGrant() answers null for a route outside the permission map, and a grant list that
        // matched on nulls would admit exactly the routes nobody has classified yet
        assert.equal(sessionTokenAdmits({ action: null, group: null }, { account: 'acct-1' }), false);
        assert.equal(sessionTokenAdmits({ action: ACTION.READ, group: null }, { account: 'acct-1' }), false);
        assert.equal(sessionTokenAdmits({}, { account: 'acct-1' }), false);

        // and no account at all is refused whatever the grant
        assert.equal(sessionTokenAdmits({ action: ACTION.READ, group: GROUP.MESSAGE }, {}), false);
        assert.equal(sessionTokenAdmits({ action: ACTION.READ, group: GROUP.MESSAGE }), false);
    });
});
