'use strict';

// Which routes an account-bound access token can reach although their path carries no {account}
// parameter.
//
// The api-token strategy checks a bound token's binding against `request.params.account`
// (workers/api.js), so a route whose path has no such parameter refuses the token with
// "Unauthorized account" unless it is named here. Three resolutions exist, and the strategy keeps the
// code for each - this table only says which route gets which:
//
//   'query'  - the account arrives as a query argument and has to name the token's own account.
//              Omitting it still refuses, so a bound credential cannot enumerate the instance.
//   'token'  - the account is taken from the token rather than from the request, and the handler is
//              held to it through `request.app.enforceAccount`.
//   'record' - the entity named in the path is checked for membership in the token's account.
//
// The MCP tool registry reads the same table to decide which tools are advertised to a bound
// credential (lib/mcp/tools.js). It used to answer that question from "the route takes an `account`
// argument", which is a different question: `POST /v1/account`, `POST /v1/authentication/form` and
// `POST /v1/blocklist/{listId}` all take one in the payload and are refused here, so three tools were
// offered to a credential whose every call died on the same bare 403, while the template routes that
// a bound token really can reach were hidden because they name no account at all. One table is what
// keeps the advertisement and the enforcement from drifting apart again.
const BOUND_ROUTES = new Map([
    ['get:/v1/templates', 'query'],
    ['get:/v1/tokens', 'query'],
    ['post:/v1/templates/template', 'token'],
    // Matched for every method: the strategy's own case carries no method switch
    ['get:/v1/templates/template/{template}', 'record'],
    ['put:/v1/templates/template/{template}', 'record'],
    ['delete:/v1/templates/template/{template}', 'record']
]);

/**
 * How a bound token's binding is satisfied on one route, or null when the route has to carry the
 * account in its path.
 *
 * @param {String} method - HTTP method, in any case
 * @param {String} path - the Hapi route path, with its parameter placeholders
 * @returns {String|null} 'query', 'token', 'record', or null
 */
function boundRouteBinding(method, path) {
    return BOUND_ROUTES.get(`${String(method).toLowerCase()}:${path}`) || null;
}

/**
 * Whether an account-bound token can reach a route at all - either because the path names the
 * account, or because the route is one of the exceptions above.
 *
 * @param {String} method - HTTP method, in any case
 * @param {String} path - the Hapi route path
 * @returns {Boolean}
 */
function routeAdmitsBoundToken(method, path) {
    return /\{account\}/.test(path) || !!boundRouteBinding(method, path);
}

module.exports = { BOUND_ROUTES, boundRouteBinding, routeAdmitsBoundToken };
