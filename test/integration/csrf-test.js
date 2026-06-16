'use strict';

// Integration tests for admin CSRF (crumb) protection. Every admin mutation
// route relies on @hapi/crumb, but no test verified that a crumb-less or
// mismatched POST is actually rejected - a broken crumb config or skip-list
// would silently expose every admin POST (delete account, revoke token, write
// credentials). /admin/login is public (auth:false) and crumb-protected, so it
// exercises the crumb layer without needing an admin password to be configured.
//
// Runs against the shared test server (config/test.toml, port 7077).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;

const baseUrl = `http://127.0.0.1:${config.api.port}`;

function extractCrumb(setCookie) {
    for (const cookie of setCookie || []) {
        const match = /(?:^|;\s*)crumb=([^;]+)/.exec(cookie);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
}

test('Admin CSRF (crumb) protection', async t => {
    await t.test('the login page issues a crumb cookie', async () => {
        const res = await supertest(baseUrl).get('/admin/login');
        assert.equal(res.status, 200);
        assert.ok(extractCrumb(res.headers['set-cookie']), 'expected a crumb cookie to be set');
    });

    await t.test('POST without a crumb is rejected with 403', async () => {
        const res = await supertest(baseUrl).post('/admin/login').type('form').send({ username: 'admin', password: 'x' });
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });

    await t.test('POST with a mismatched crumb is rejected with 403', async () => {
        const agent = supertest.agent(baseUrl);
        const page = await agent.get('/admin/login');
        const crumb = extractCrumb(page.headers['set-cookie']);
        assert.ok(crumb, 'login page should set a crumb cookie');

        const res = await agent.post('/admin/login').type('form').send({ crumb: 'totally-wrong-value', username: 'admin', password: 'x' });
        assert.equal(res.status, 403, `expected 403, got ${res.status}`);
    });

    await t.test('POST with the matching crumb passes CSRF validation', async () => {
        const agent = supertest.agent(baseUrl);
        const page = await agent.get('/admin/login');
        const crumb = extractCrumb(page.headers['set-cookie']);
        assert.ok(crumb, 'login page should set a crumb cookie');

        // The agent resends the crumb cookie automatically; the body field must match it.
        const res = await agent.post('/admin/login').type('form').send({ crumb, username: 'admin', password: 'definitely-wrong-password', next: '/admin' });

        // CSRF must pass (the login itself fails / re-renders, which is not a 403).
        assert.notEqual(res.status, 403, 'a matching crumb must not be rejected as CSRF');
    });
});
