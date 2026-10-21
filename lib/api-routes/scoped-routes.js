'use strict';

// Routes that exist twice: once for the whole instance, and once for one account under
// /v1/account/{account}/... The account form is what an account-bound access token can reach - its
// path names the account, which is what the api-token strategy checks the binding against - and
// every ID it is given has to belong to that account. The MCP tools stay on the instance form: the
// account form does the same thing for a narrower caller. Shared by the outbox and the failed
// webhook delivery routes, so a third pair does not start from a copy of either.

const Joi = require('joi');
const { accountIdSchema } = require('../schemas');

/**
 * @param {Object} prefixes
 * @param {string} prefixes.instance - Path prefix of the instance form
 * @param {string} prefixes.account - Path prefix of the account form, with an {account} parameter
 * @returns {{ instance: Object, account: Object, all: Object[] }} The two scopes
 */
function routeScopes(prefixes) {
    const instance = { prefix: prefixes.instance, params: {}, mcp: true, isInstance: true, labelPrefix: '' };
    const account = { prefix: prefixes.account, params: { account: accountIdSchema.required() }, mcp: false, isInstance: false, labelPrefix: 'Account' };
    return { instance, account, all: [instance, account] };
}

/**
 * Path parameter schema of a scoped route
 * @param {Object} scope - From routeScopes()
 * @param {Object} [extra] - Parameters of the route itself
 * @returns {Object|undefined} A joi object, or undefined for a route without parameters
 */
function routeParams(scope, extra) {
    const keys = Object.assign({}, scope.params, extra || {});
    return Object.keys(keys).length ? Joi.object(keys) : undefined;
}

/**
 * A schema label, prefixed with Account on the account form so the two forms name distinct types
 * @param {Object} scope - From routeScopes()
 * @param {string} label - The instance form's label
 * @returns {string}
 */
function scopedLabel(scope, label) {
    return scope.labelPrefix + label;
}

/**
 * The route's MCP tool block, on the instance form only
 * @param {Object} scope - From routeScopes()
 * @param {Object} definition - The plugins.mcp block
 * @returns {Object|undefined}
 */
function mcpFor(scope, definition) {
    return scope.mcp ? definition : undefined;
}

/**
 * The page and pageSize query parameters of a paged listing
 * @returns {Object} joi keys
 */
function pagingQuery() {
    return {
        page: Joi.number()
            .integer()
            .min(0)
            .max(1024 * 1024)
            .default(0)
            .example(0)
            .description('Page number (zero indexed, so use 0 for first page)')
            .label('PageNumber'),
        pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
    };
}

module.exports = { routeScopes, routeParams, scopedLabel, mcpFor, pagingQuery };
