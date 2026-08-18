'use strict';

// Where a route keeps the metadata that is about its documentation and its permissions rather than
// about serving the request: `plugins.openapi` in the route definition.
//
// Its own module because two readers need it and neither should own it. lib/openapi/build-document.js
// publishes what it finds there, and ./permission-map.js reads `x-ee-impact` out of it at request
// time to resolve what a token needs. Keeping the accessor in either would have the other spell the
// slot out again, and one of them feeds access control: rename the key with two independent readers
// and the second starts seeing an empty object, which downgrades every declared impact to the method
// default with nothing failing.
//
// It sits under lib/api-routes/ rather than lib/openapi/ so the dependency runs one way. The
// generator reads route metadata; route modules do not read the generator.

const PLUGIN_OPTIONS_KEY = 'openapi';

/**
 * The documentation and permission metadata a route declares.
 *
 * @param {Object} route - a `server.table()` entry, or a live `request.route`
 * @returns {Object} the route's `plugins.openapi`, or an empty object when it declares none
 */
function pluginOptions(route) {
    return (route && route.settings && route.settings.plugins && route.settings.plugins[PLUGIN_OPTIONS_KEY]) || {};
}

module.exports = { pluginOptions };
