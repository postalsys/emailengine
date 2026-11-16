'use strict';

// A framework-neutral description of a registered route: everything the OpenAPI document
// (lib/openapi/), the MCP tool registry (lib/mcp/tools.js) and the permission map
// (lib/api-routes/permission-map.js) read from a route. They used to read hapi's route objects
// directly (`route.settings.validate`, `route.settings.plugins`, ...); now they read descriptors, so
// moving off hapi would mean writing another describeRoute() rather than touching those three.
// The request-time code (the api-token strategy, deprecations, DBSC, security headers) still reads
// the live hapi `request.route`; routePlugins() below is the one accessor it shares with them.
// See the hapi vs Fastify study of the 2026-11 dependency audit.
//
// The joi schemas are passed through as they are: they are what both the document and the tool
// schemas are generated from, and joi is not tied to the framework.

const DESCRIPTOR = Symbol('routeDescriptor');

/**
 * @typedef {Object} RouteDescriptor
 * @property {string} method - lowercase, as hapi reports it
 * @property {string} path - in hapi's syntax ("/v1/account/{account}")
 * @property {string} [description] - one-line summary
 * @property {string|string[]} [notes] - longer description
 * @property {string[]} tags
 * @property {{headers?: Object, params?: Object, query?: Object, payload?: Object}} validate - joi schemas
 * @property {Object} [responseSchema] - joi schema of the success response
 * @property {Object} plugins - the route's `plugins` blocks (`openapi`, `mcp`, `securityHeaders`, ...)
 */

/**
 * Describes one route. A descriptor passed in is returned as it is.
 *
 * @param {Object} route - an entry of hapi's `server.table()`, a live `request.route`, or a descriptor
 * @returns {RouteDescriptor}
 */
function describeRoute(route) {
    if (route && route[DESCRIPTOR]) {
        return route;
    }
    const settings = (route && route.settings) || {};
    return Object.freeze({
        [DESCRIPTOR]: true,
        method: route && route.method,
        path: route && route.path,
        description: settings.description,
        notes: settings.notes,
        tags: settings.tags || [],
        validate: settings.validate || {},
        responseSchema: settings.response ? settings.response.schema : undefined,
        plugins: settings.plugins || {}
    });
}

/**
 * Describes a whole route table.
 *
 * @param {Array} routes - hapi's `server.table()`
 * @returns {RouteDescriptor[]}
 */
function describeRoutes(routes) {
    return routes.map(describeRoute);
}

/**
 * The `plugins` blocks of a route, for either a descriptor or a hapi route. The api-token strategy
 * reads them off the live `request.route` on every request, where building a descriptor would be
 * an allocation per request for nothing.
 *
 * @param {Object} route
 * @returns {Object|undefined}
 */
function routePlugins(route) {
    if (!route) {
        return undefined;
    }
    return route[DESCRIPTOR] ? route.plugins : route.settings && route.settings.plugins;
}

module.exports = { describeRoute, describeRoutes, routePlugins };
