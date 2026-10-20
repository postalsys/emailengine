'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const { NONCE_BYTES } = require('../lib/consts');
const { formNonceKey } = require('../lib/tools');
const { completeAccountSetup, setupRedirectUrl } = require('../lib/ui-routes/account-setup');
const registerRedisTeardown = require('./helpers/redis-teardown');

const usedNonces = new Set();

registerRedisTeardown(redis, async () => {
    for (const n of usedNonces) {
        await redis.del(formNonceKey(n));
    }
});

const newNonce = () => {
    const n = crypto.randomBytes(NONCE_BYTES).toString('base64url');
    usedNonces.add(n);
    return { n, t: Date.now() };
};

// A request whose catalog marks every string it translates, so a test can tell a translated
// refusal from an untranslated one
const createRequest = () => ({
    app: { gt: { gettext: msg => `[xx] ${msg}` } },
    logger: { error() {}, warn() {}, info() {}, debug() {} }
});

const createAccountObject = (result = { account: 'example', state: 'new' }) => {
    const accountObject = {
        created: [],
        async create(accountData) {
            accountObject.created.push(accountData);
            return result;
        }
    };
    return accountObject;
};

test('setupRedirectUrl', async t => {
    await t.test('the account page link encodes the account ID', () => {
        assert.equal(setupRedirectUrl(undefined, undefined, { account: 'a/b?c#d e', state: 'new' }), '/admin/accounts/a%2Fb%3Fc%23d%20e');
    });

    await t.test('a plain account ID is used as is', () => {
        assert.equal(setupRedirectUrl(null, 'https://ee.example.com', { account: 'example', state: 'new' }), '/admin/accounts/example');
    });

    await t.test('the calling application gets the account ID and state as query arguments', () => {
        const href = setupRedirectUrl('https://app.example.com/done?x=1', undefined, { account: 'a/b&c', state: 'existing' });
        const url = new URL(href);
        assert.equal(url.origin + url.pathname, 'https://app.example.com/done');
        assert.equal(url.searchParams.get('x'), '1');
        assert.equal(url.searchParams.get('account'), 'a/b&c');
        assert.equal(url.searchParams.get('state'), 'existing');
    });

    await t.test('a relative redirect URL resolves against the Service URL', () => {
        assert.equal(
            setupRedirectUrl('/finished', 'https://ee.example.com', { account: 'example', state: 'new' }),
            'https://ee.example.com/finished?account=example&state=new'
        );
    });
});

test('completeAccountSetup', async t => {
    await t.test('creates the account and claims the nonce', async () => {
        const nonce = newNonce();
        const accountObject = createAccountObject({ account: 'with space', state: 'new' });
        const accountData = { account: 'with space' };

        const href = await completeAccountSetup(createRequest(), { accountObject, accountData, nonce });

        assert.equal(href, '/admin/accounts/with%20space');
        assert.deepEqual(accountObject.created, [accountData]);
        assert.equal(await redis.get(formNonceKey(nonce.n)), String(nonce.t));
    });

    await t.test('a spent nonce is refused with a translated 403 and creates nothing', async () => {
        const nonce = newNonce();
        await completeAccountSetup(createRequest(), { accountObject: createAccountObject(), accountData: {}, nonce });

        const accountObject = createAccountObject();
        await assert.rejects(completeAccountSetup(createRequest(), { accountObject, accountData: {}, nonce }), err => {
            assert.equal(err.output.statusCode, 403);
            assert.equal(err.message, '[xx] Invalid or expired account setup URL');
            return true;
        });
        assert.equal(accountObject.created.length, 0);
    });

    await t.test('a Redis failure during the claim is a translated 500, not a spent link', async t => {
        const nonce = newNonce();
        t.mock.method(redis, 'set', async () => {
            throw new Error('Connection is closed');
        });

        const accountObject = createAccountObject();
        await assert.rejects(completeAccountSetup(createRequest(), { accountObject, accountData: {}, nonce }), err => {
            assert.equal(err.output.statusCode, 500);
            assert.equal(err.message, '[xx] Temporary error, please try again');
            return true;
        });
        assert.equal(accountObject.created.length, 0);
    });

    await t.test('a failed create releases the nonce so the link can be retried', async () => {
        const nonce = newNonce();
        const failing = {
            async create() {
                throw new Error('Validation failed');
            }
        };

        await assert.rejects(completeAccountSetup(createRequest(), { accountObject: failing, accountData: {}, nonce }), /Validation failed/);
        assert.equal(await redis.get(formNonceKey(nonce.n)), null);

        const accountObject = createAccountObject();
        await completeAccountSetup(createRequest(), { accountObject, accountData: {}, nonce });
        assert.equal(accountObject.created.length, 1);
    });

    await t.test('a link without a nonce is not claimed', async () => {
        for (const nonce of [null, undefined, {}]) {
            const accountObject = createAccountObject();
            await completeAccountSetup(createRequest(), { accountObject, accountData: {}, nonce });
            await completeAccountSetup(createRequest(), { accountObject, accountData: {}, nonce });
            assert.equal(accountObject.created.length, 2);
        }
    });

    await t.test('a redirect URL sends the visitor back to the calling application', async t => {
        t.mock.method(settings, 'get', async key => (key === 'serviceUrl' ? 'https://ee.example.com' : null));

        const href = await completeAccountSetup(createRequest(), {
            accountObject: createAccountObject({ account: 'a#b', state: 'new' }),
            accountData: {},
            nonce: newNonce(),
            redirectUrl: 'https://app.example.com/done'
        });
        assert.equal(href, 'https://app.example.com/done?account=a%23b&state=new');
    });
});
