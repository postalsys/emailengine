'use strict';

// The OAuth2 apps listing (/admin/config/oauth) shows each app's provider-issued client id
// under the app name. The id is what the provider's own console lists apps by - Azure Entra
// calls the same value "Application (client) ID" - so without it on the row an operator has to
// open every app to match this listing against the provider's. Server-rendered, so the check
// needs the live server plus an app seeded into the shared Redis (the same recipe as
// token-scope-test.js uses for tokens).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../../lib/db');
const { oauth2Apps } = require('../../lib/oauth2-apps');
const registerRedisTeardown = require('../helpers/redis-teardown');

const baseUrl = `http://127.0.0.1:${config.api.port}`;

// Force the process to exit once tests finish; lib/db keeps connections open.
registerRedisTeardown(redis);

test('OAuth2 apps listing', async t => {
    await t.test('shows the client id of a listed app', async () => {
        // The GUID shape Entra issues, so the row is realistic; the app itself stays disabled
        // and unreferenced, it only has to render
        const clientId = '11111111-2222-3333-4444-555555555555';

        const created = await oauth2Apps.create({
            provider: 'outlook',
            name: 'Entra listing test app',
            description: 'Integration test app',
            clientId,
            clientSecret: 'test-secret',
            authority: 'common',
            redirectUrl: `${baseUrl}/oauth`,
            enabled: false
        });

        try {
            const res = await supertest(baseUrl).get('/admin/config/oauth');
            assert.equal(res.status, 200);
            assert.ok(res.text.includes(clientId), 'the listing must show the client id');
            assert.ok(res.text.includes('Client ID'), 'the id must be labeled');
        } finally {
            await oauth2Apps.del(created.id);
        }
    });
});
