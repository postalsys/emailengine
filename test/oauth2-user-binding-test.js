'use strict';

// Account.create() and Account.update() refuse an OAuth2 user another live account of the same app
// holds. The check loaded the other account through the updating account's own loadAccountData(),
// which refuses any id but its own, so it never found the conflict: an account-bound token could set
// another account's Gmail address as its own OAuth2 user and take over that account's Pub/Sub
// notification routing (oapp:h).

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { Account } = require('../lib/account');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { accountKeyFor, noopLogger } = require('./helpers/auth-failure');
const { REDIS_PREFIX } = require('../lib/consts');

const { oauth2Apps } = require('../lib/oauth2-apps');

const suffix = crypto.randomBytes(4).toString('hex');
let APP;
const VICTIM = `binding-victim-${suffix}`;
const ATTACKER = `binding-attacker-${suffix}`;
let BINDING_KEY;

test.before(async () => {
    const app = await oauth2Apps.create({
        provider: 'gmail',
        name: 'binding test',
        baseScopes: 'imap',
        clientId: 'cid',
        clientSecret: 'csecret',
        enabled: true
    });
    APP = app.id;
    BINDING_KEY = `${REDIS_PREFIX}oapp:h:${APP}`;
});

const oauth2 = user => JSON.stringify({ provider: APP, auth: { user } });

registerRedisTeardown(redis, async () => {
    await redis.del(accountKeyFor(VICTIM), accountKeyFor(ATTACKER));
    if (APP) {
        await oauth2Apps.del(APP).catch(() => false);
        await redis.del(BINDING_KEY, `${REDIS_PREFIX}oapp:a:${APP}`);
    }
});

const accountObject = account => new Account({ redis, account, logger: noopLogger, call: async () => ({}) });

test('an OAuth2 user bound to another live account can not be claimed', async () => {
    await redis.hset(accountKeyFor(VICTIM), { account: VICTIM, oauth2: oauth2('victim@gmail.com') });
    await redis.hset(BINDING_KEY, 'victim@gmail.com', VICTIM);
    await redis.hset(accountKeyFor(ATTACKER), { account: ATTACKER, oauth2: oauth2('attacker@gmail.com') });

    await assert.rejects(
        () => accountObject(ATTACKER).update({ account: ATTACKER, oauth2: { provider: APP, auth: { user: 'Victim@Gmail.com' } } }),
        err => err.output.statusCode === 400 && err.output.payload.code === 'AccountAlreadyExists' && err.output.payload.existingAccount === VICTIM
    );

    // the victim's routing is untouched
    assert.equal(await redis.hget(BINDING_KEY, 'victim@gmail.com'), VICTIM);
});

test('a binding whose account is gone, or holds another user now, may be taken over', async () => {
    await redis.hset(BINDING_KEY, 'victim@gmail.com', VICTIM);
    await redis.hset(accountKeyFor(VICTIM), { oauth2: oauth2('someone-else@gmail.com') });
    await accountObject(ATTACKER).assertOAuth2UserUnbound(APP, 'victim@gmail.com');

    await redis.del(accountKeyFor(VICTIM));
    await accountObject(ATTACKER).assertOAuth2UserUnbound(APP, 'victim@gmail.com');
});

test('an account re-binding its own user is not a conflict', async () => {
    await redis.hset(BINDING_KEY, 'attacker@gmail.com', ATTACKER);
    await accountObject(ATTACKER).assertOAuth2UserUnbound(APP, 'attacker@gmail.com');
});
