'use strict';

// Covers the admin-password requirement in tokens.provision() - see lib/tokens.js for why it
// exists.

const test = require('node:test');
const assert = require('node:assert').strict;

const tokens = require('../lib/tokens');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { withAuthData, SECURED_AUTH_DATA } = require('./helpers/with-auth-data');

const issued = new Set();

async function provisionTracked(opts, context) {
    const token = await tokens.provision(opts, context);
    issued.add(token);
    return token;
}

registerRedisTeardown(redis, async () => {
    for (const token of issued) {
        try {
            await tokens.delete(token);
        } catch (err) {
            // ignore - best-effort cleanup
        }
    }
});

test('tokens.provision admin-password requirement', async t => {
    await t.test('refuses to mint a token when no admin password is set', async () => {
        await withAuthData(false, async () => {
            await assert.rejects(
                () => tokens.provision({ description: 'should not be issued' }),
                err => err.isBoom && err.output.statusCode === 403,
                'provisioning must fail with a 403 while the instance is unprotected'
            );
        });
    });

    await t.test('mints a token once an admin password exists', async () => {
        await withAuthData(SECURED_AUTH_DATA, async () => {
            const token = await provisionTracked({ description: 'issued after auth is enabled' });
            assert.match(token, /^[0-9a-f]{64}$/, 'a provisioned token is 64 hex characters');
        });
    });

    await t.test('the CLI context bypasses the check', async () => {
        // Reaching the CLI already requires shell access to the host, which grants strictly more
        // than a token would, so blocking it would break a setup flow without closing anything.
        await withAuthData(false, async () => {
            const token = await provisionTracked({ description: 'issued from the CLI' }, { allowWithoutAdminAuth: true });
            assert.match(token, /^[0-9a-f]{64}$/);
        });
    });

    await t.test('the bypass cannot be injected through the token options', async () => {
        // The regression this guards: POST /v1/token does
        // `tokens.provision(Object.assign({}, request.payload, ...))`, so anything honoured in the
        // first argument is reachable by an unauthenticated caller if a route is ever validated
        // with allowUnknown. The flag lives in a separate argument for exactly this reason.
        await withAuthData(false, async () => {
            await assert.rejects(
                () => tokens.provision({ description: 'injection attempt', allowWithoutAdminAuth: true }),
                err => err.isBoom && err.output.statusCode === 403,
                'a bypass flag supplied in the options object must be ignored'
            );
        });
    });
});
