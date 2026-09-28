'use strict';

// The hapi authentication scheme behind the `api-token` strategy: `Authorization: Bearer <token>`,
// or the `access_token` query parameter when the strategy allows it. Replaces hapi-auth-bearer-token
// (unmaintained since 2020, and the last thing pinning @hapi/hoek 9 into the tree) with exactly the
// subset EmailEngine used, response for response: test/api-token-scheme-test.js replays the
// responses recorded from the plugin.
//
// The contract with the strategy's validate() is unchanged. It is called as
// validate(request, token, h) and answers { isValid, credentials, artifacts }; an error it throws
// is not caught here, so the coded refusals the api-token strategy raises (UnknownToken,
// ExpiredToken, a permission refusal) reach the client as they always did. A request that carries
// no bearer token at all is reported as missing authentication, which is what lets a route with
// `mode: 'optional'` or `'try'` continue without one.

const Boom = require('@hapi/boom');

const SCHEME_NAME = 'api-token-bearer';
const TOKEN_TYPE = 'Bearer';
const ACCESS_TOKEN_NAME = 'access_token';

/**
 * Scheme implementation for server.auth.scheme(SCHEME_NAME, apiTokenScheme)
 *
 * @param {object} server - Hapi server (unused, part of the scheme signature)
 * @param {object} options - Strategy options
 * @param {Function} options.validate - Token validation function
 * @param {boolean} [options.allowQueryToken=false] - Also accept the token as `?access_token=`
 */
function apiTokenScheme(server, options) {
    if (!options || typeof options.validate !== 'function') {
        throw new TypeError('The api-token scheme needs a validate function');
    }

    const { validate, allowQueryToken = false } = options;

    return {
        authenticate: async (request, h) => {
            let authorization = request.raw.req.headers.authorization;

            if (allowQueryToken && !authorization && request.query[ACCESS_TOKEN_NAME]) {
                authorization = `${TOKEN_TYPE} ${request.query[ACCESS_TOKEN_NAME]}`;
                // a credential, not an input the handler or its payload validation should see
                delete request.query[ACCESS_TOKEN_NAME];
            }

            if (!authorization) {
                throw Boom.unauthorized(null, TOKEN_TYPE);
            }

            const [tokenType, token] = authorization.split(/\s+/);
            if (!token || tokenType.toLowerCase() !== TOKEN_TYPE.toLowerCase()) {
                throw Boom.unauthorized(null, TOKEN_TYPE);
            }

            const { isValid, credentials, artifacts } = await validate(request, token, h);

            if (!isValid) {
                return h.unauthenticated(Boom.unauthorized('Bad token', TOKEN_TYPE), { credentials: credentials || {}, artifacts });
            }

            if (!credentials || typeof credentials !== 'object') {
                return h.unauthenticated(Boom.badImplementation('Bad token string received for Bearer auth validation'), { credentials: {} });
            }

            return h.authenticated({ credentials, artifacts });
        }
    };
}

module.exports = { apiTokenScheme, SCHEME_NAME, TOKEN_TYPE, ACCESS_TOKEN_NAME };
