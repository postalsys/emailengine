'use strict';

// Server-Sent Events feed of account state changes.
//
// Registered here rather than inline in workers/api.js so that it is part of the captured route
// table (test/api-routes-table-test.js): this endpoint streams every account's state transitions
// and error strings, and it was the one /v1 route no guardrail could see - a dropped auth block
// on it would have been invisible.

const { openChangeStream } = require('../response-stream');
const { errorResponses } = require('../schemas');

/**
 * Registers the change-stream route.
 *
 * @param {Object} args
 * @param {Object} args.server - Hapi server (or a route-recording mock)
 * @param {Object|Boolean} args.CORS_CONFIG
 */
async function init(args) {
    const { server, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/changes',

        // Shared with the admin feed (/admin/changes in workers/api.js)
        handler: openChangeStream,

        options: {
            description: 'Stream state changes',
            notes: 'Stream account state changes as an EventSource',
            tags: ['api', 'Account'],

            plugins: {
                'hapi-swagger': {
                    produces: ['text/event-stream'],
                    responses: errorResponses(401, 403, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG
        }
    });
}

module.exports = init;
