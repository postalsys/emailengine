'use strict';

// lib/api-token-scheme.js replaced hapi-auth-bearer-token 8.0.0 as the scheme behind the
// `api-token` strategy. RECORDED below is every response the plugin gave on a bare hapi server,
// for the strategy options EmailEngine registers (allowQueryToken on, nothing else) and for a
// strategy with the query token off, across required, optional and try routes: a valid bearer
// token, no header, foreign schemes, malformed headers, the query token in its variants, and
// each way validate() can answer or throw. The scheme is registered the same way and has to
// give the same status, WWW-Authenticate header and payload, hand validate() the same token,
// and leave the request in the same state for the handler.

const test = require('node:test');
const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');

const { apiTokenScheme, SCHEME_NAME } = require('../lib/api-token-scheme');

const RECORDED = [
    {
        name: 'required, valid bearer',
        url: '/required',
        headers: {
            authorization: 'Bearer good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, no header',
        url: '/required',
        headers: {},
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'required, basic scheme',
        url: '/required',
        headers: {
            authorization: 'Basic Zm9vOmJhcg=='
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'required, scheme only',
        url: '/required',
        headers: {
            authorization: 'Bearer'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'required, scheme only with trailing space',
        url: '/required',
        headers: {
            authorization: 'Bearer '
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'required, lowercase scheme',
        url: '/required',
        headers: {
            authorization: 'bearer good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, extra parts',
        url: '/required',
        headers: {
            authorization: 'Bearer good extra'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, double space',
        url: '/required',
        headers: {
            authorization: 'Bearer  good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, tab separated',
        url: '/required',
        headers: {
            authorization: 'Bearer\tgood'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, semicolon suffix',
        url: '/required',
        headers: {
            authorization: 'Bearer good; other'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['good;']
    },
    {
        name: 'required, query token',
        url: '/required?access_token=good&other=1',
        headers: {},
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {
                other: '1'
            },
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'required, query token and header',
        url: '/required?access_token=good',
        headers: {
            authorization: 'Bearer bad'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['bad']
    },
    {
        name: 'required, empty query token',
        url: '/required?access_token=',
        headers: {},
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'required, invalid query token',
        url: '/required?access_token=bad',
        headers: {},
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['bad']
    },
    {
        name: 'required, validate isValid false',
        url: '/required',
        headers: {
            authorization: 'Bearer bad'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['bad']
    },
    {
        name: 'required, validate isValid false no creds',
        url: '/required',
        headers: {
            authorization: 'Bearer unknown'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['unknown']
    },
    {
        name: 'required, validate throws coded boom',
        url: '/required',
        headers: {
            authorization: 'Bearer boom'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            },
            code: 'ExpiredToken'
        },
        validateSaw: ['boom']
    },
    {
        name: 'required, validate throws forbidden',
        url: '/required',
        headers: {
            authorization: 'Bearer forbidden'
        },
        statusCode: 403,
        wwwAuthenticate: null,
        payload: {
            statusCode: 403,
            error: 'Forbidden',
            message: 'Unauthorized permission'
        },
        validateSaw: ['forbidden']
    },
    {
        name: 'required, validate throws plain error',
        url: '/required',
        headers: {
            authorization: 'Bearer crash'
        },
        statusCode: 500,
        wwwAuthenticate: null,
        payload: {
            statusCode: 500,
            error: 'Internal Server Error',
            message: 'An internal server error occurred'
        },
        validateSaw: ['crash']
    },
    {
        name: 'required, credentials not object',
        url: '/required',
        headers: {
            authorization: 'Bearer nocreds'
        },
        statusCode: 500,
        wwwAuthenticate: null,
        payload: {
            statusCode: 500,
            error: 'Internal Server Error',
            message: 'An internal server error occurred'
        },
        validateSaw: ['nocreds']
    },
    {
        name: 'required, credentials undefined',
        url: '/required',
        headers: {
            authorization: 'Bearer undefcreds'
        },
        statusCode: 500,
        wwwAuthenticate: null,
        payload: {
            statusCode: 500,
            error: 'Internal Server Error',
            message: 'An internal server error occurred'
        },
        validateSaw: ['undefcreds']
    },
    {
        name: 'optional, no header',
        url: '/optional',
        headers: {},
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: false,
            strategy: null,
            credentials: null,
            artifacts: null,
            query: {},
            error: {
                message: 'Missing authentication',
                statusCode: 401,
                isMissing: false
            }
        },
        validateSaw: []
    },
    {
        name: 'optional, valid',
        url: '/optional',
        headers: {
            authorization: 'Bearer good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'optional, invalid',
        url: '/optional',
        headers: {
            authorization: 'Bearer bad'
        },
        statusCode: 401,
        wwwAuthenticate: 'Bearer error="Bad token"',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        },
        validateSaw: ['bad']
    },
    {
        name: 'optional, basic scheme',
        url: '/optional',
        headers: {
            authorization: 'Basic x'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: false,
            strategy: null,
            credentials: null,
            artifacts: null,
            query: {},
            error: {
                message: 'Missing authentication',
                statusCode: 401,
                isMissing: false
            }
        },
        validateSaw: []
    },
    {
        name: 'try, no header',
        url: '/try',
        headers: {},
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: false,
            strategy: null,
            credentials: null,
            artifacts: null,
            query: {},
            error: {
                message: 'Missing authentication',
                statusCode: 401,
                isMissing: false
            }
        },
        validateSaw: []
    },
    {
        name: 'try, invalid',
        url: '/try',
        headers: {
            authorization: 'Bearer bad'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: false,
            strategy: 'api-token',
            credentials: {
                partial: true
            },
            artifacts: {
                why: 'bad'
            },
            query: {},
            error: {
                message: 'Bad token',
                statusCode: 401,
                isMissing: false
            }
        },
        validateSaw: ['bad']
    },
    {
        name: 'try, validate throws coded boom',
        url: '/try',
        headers: {
            authorization: 'Bearer boom'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: false,
            strategy: 'api-token',
            query: {},
            error: {
                message: 'Bad token',
                statusCode: 401,
                isMissing: false
            }
        },
        validateSaw: ['boom']
    },
    {
        name: 'try, valid',
        url: '/try',
        headers: {
            authorization: 'Bearer good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    },
    {
        name: 'noquery, query token',
        url: '/noquery?access_token=good',
        headers: {},
        statusCode: 401,
        wwwAuthenticate: 'Bearer',
        payload: {
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Missing authentication'
        },
        validateSaw: []
    },
    {
        name: 'noquery, header',
        url: '/noquery',
        headers: {
            authorization: 'Bearer good'
        },
        statusCode: 200,
        wwwAuthenticate: null,
        payload: {
            isAuthenticated: true,
            strategy: 'api-token-noquery',
            credentials: {
                token: 'good',
                scope: ['api']
            },
            artifacts: {
                source: 'validate'
            },
            query: {},
            error: null
        },
        validateSaw: ['good']
    }
];

async function buildServer() {
    const server = Hapi.server({ port: 0, debug: false });
    const seen = [];

    const validate = async (request, token) => {
        seen.push(token);
        if (token === 'good') {
            return { isValid: true, credentials: { token, scope: ['api'] }, artifacts: { source: 'validate' } };
        }
        if (token === 'bad') {
            return { isValid: false, credentials: { partial: true }, artifacts: { why: 'bad' } };
        }
        if (token === 'nocreds') {
            return { isValid: true, credentials: 'not-an-object' };
        }
        if (token === 'undefcreds') {
            return { isValid: true };
        }
        if (token === 'boom') {
            // what workers/api.js throws for an unknown or expired token
            const err = Boom.unauthorized('Bad token', 'Bearer');
            err.output.payload.code = 'ExpiredToken';
            throw err;
        }
        if (token === 'forbidden') {
            throw Boom.forbidden('Unauthorized permission');
        }
        if (token === 'crash') {
            throw new Error('validate exploded');
        }
        return { isValid: false };
    };

    server.auth.scheme(SCHEME_NAME, apiTokenScheme);
    server.auth.strategy('api-token', SCHEME_NAME, { allowQueryToken: true, validate });
    server.auth.strategy('api-token-noquery', SCHEME_NAME, { validate });

    const handler = request => ({
        isAuthenticated: request.auth.isAuthenticated,
        strategy: request.auth.strategy,
        credentials: request.auth.credentials,
        artifacts: request.auth.artifacts,
        query: request.query,
        error: request.auth.error
            ? {
                  message: request.auth.error.message,
                  statusCode: request.auth.error.output && request.auth.error.output.statusCode,
                  isMissing: !!request.auth.error.isMissing
              }
            : null
    });

    for (const [path, strategy, mode] of [
        ['/required', 'api-token', 'required'],
        ['/optional', 'api-token', 'optional'],
        ['/try', 'api-token', 'try'],
        ['/noquery', 'api-token-noquery', 'required']
    ]) {
        server.route({ method: 'GET', path, options: { auth: { strategy, mode } }, handler });
    }

    return { server, seen };
}

test('the api-token scheme answers every recorded request exactly as hapi-auth-bearer-token did', async t => {
    const { server, seen } = await buildServer();

    for (const recorded of RECORDED) {
        await t.test(recorded.name, async () => {
            seen.length = 0;
            const res = await server.inject({ method: 'GET', url: recorded.url, headers: recorded.headers });

            let payload;
            try {
                payload = JSON.parse(res.payload);
            } catch {
                payload = res.payload;
            }

            assert.deepEqual(
                {
                    statusCode: res.statusCode,
                    wwwAuthenticate: res.headers['www-authenticate'] || null,
                    payload,
                    validateSaw: seen.slice()
                },
                {
                    statusCode: recorded.statusCode,
                    wwwAuthenticate: recorded.wwwAuthenticate,
                    payload: recorded.payload,
                    validateSaw: recorded.validateSaw
                }
            );
        });
    }
});

test('the scheme refuses to register without a validate function', async () => {
    const server = Hapi.server({ port: 0, debug: false });
    server.auth.scheme(SCHEME_NAME, apiTokenScheme);
    assert.throws(() => server.auth.strategy('broken', SCHEME_NAME, {}), TypeError);
    assert.throws(() => server.auth.strategy('broken', SCHEME_NAME), TypeError);
});
