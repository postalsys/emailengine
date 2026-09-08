'use strict';

// The ACME HTTP-01 challenge route, GET /.well-known/acme-challenge/{token}.
//
// This is the one unauthenticated route Let's Encrypt fetches during issuance, and RFC 8555
// section 8.3 has the CA compare the whole response body against the key authorization byte for
// byte. Nothing else covers it: the route takes a path parameter, so it is excluded from
// ui-routes-smoke-test.js, and the route-table snapshot only proves it is registered.
//
// It is also the route that decides whether a failed validation is legible. The handler used to
// read `err.statusCode`, which @postalsys/certs never sets - it reports `err.responseCode` - so
// every miss came back as a 500 and looked like an EmailEngine fault rather than a missing token.
//
// Runs against the shared test server started by test/run-tests.js (config/test.toml, port 7077).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;

const baseUrl = `http://127.0.0.1:${config.api.port}`;

// The handler takes the domain from the Host header, and the test server is reached at
// 127.0.0.1, which is not a domain name. Let's Encrypt always arrives with the real hostname.
const HOST = 'test.example.com';

test('an unknown challenge token is a 404, not a 500', async () => {
    const response = await supertest(baseUrl).get('/.well-known/acme-challenge/no-such-token-exists').set('Host', HOST).expect(404);

    assert.match(response.headers['content-type'], /text\/plain/);
    assert.match(response.text, /Unknown challenge/);
    // The domain and token are echoed so an operator debugging a failed issuance can see which
    // hostname the request arrived for.
    assert.match(response.text, /no-such-token-exists/);
    assert.match(response.text, new RegExp(HOST));
});

test('a host that is not a domain name is rejected as a bad request', async () => {
    // Reached by IP, which is what a health checker or a stray scan does.
    await supertest(baseUrl).get('/.well-known/acme-challenge/probe').expect(400);
});

test('a malformed token is rejected before any lookup', async () => {
    // The token is capped at 256 characters by the library's own validation.
    await supertest(baseUrl)
        .get(`/.well-known/acme-challenge/${'a'.repeat(300)}`)
        .set('Host', HOST)
        .expect(400);
});

test('the route needs no authentication and no crumb', async () => {
    // Let's Encrypt sends a bare GET with no cookie. A route that answered 401 or 302 here would
    // fail every issuance, and the admin session strategy is the default for everything else.
    const response = await supertest(baseUrl).get('/.well-known/acme-challenge/probe').set('Host', HOST);

    assert.equal(response.status, 404, 'reached the handler rather than an auth redirect');
    assert.ok(!response.headers.location, 'nothing redirected the CA to a login page');
});
