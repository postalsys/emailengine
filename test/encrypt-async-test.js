'use strict';

// decryptAsync(): decrypt() with the key derivation on the libuv thread pool. A cold wd02 key is a
// 600000 iteration PBKDF2, which the synchronous decrypt spends with the event loop blocked, and an
// account loader decrypting values that each carry their own salt (written before the salt became per
// process) paid it once per account, one after another, at every worker start.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { encrypt, decrypt, decryptAsync, PBKDF2_ITERATIONS, PBKDF2_DIGEST } = require('../lib/encrypt');
const { forAll, gen } = require('./helpers/property');
const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const SECRET = 'async-test-secret';

function sealed(scheme, key, salt, iv, cleartext) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    const ciphertext = Buffer.concat([cipher.update(cleartext), cipher.final()]);
    return ['', scheme, 'aes-256-gcm', cipher.getAuthTag(), iv, salt, ciphertext].map(part => (Buffer.isBuffer(part) ? part.toString('hex') : part)).join('$');
}

// A value with a salt of its own, so its key is not in the cache yet
function coldValue(cleartext, scheme = 'wd02', secret = SECRET) {
    const salt = crypto.randomBytes(16);
    const key = scheme === 'wd01' ? crypto.scryptSync(secret, salt, 32) : crypto.pbkdf2Sync(secret, salt, PBKDF2_ITERATIONS, 32, PBKDF2_DIGEST);
    return sealed(scheme, key, salt, crypto.randomBytes(12), cleartext);
}

test('decryptAsync', async t => {
    await t.test('answers what decrypt() answers for every scheme and for cleartext', async () => {
        const values = [coldValue('wd02 value'), coldValue('wd01 value', 'wd01'), encrypt('written now', SECRET), 'plain text', '', '$unknown$format$value'];
        for (const value of values) {
            assert.strictEqual(await decryptAsync(value, SECRET), decrypt(value, SECRET));
        }
        const value = coldValue('x');
        assert.strictEqual(await decryptAsync(value, ''), decrypt(value, ''), 'without a secret the value is returned as stored');
    });

    await t.test('fails the way decrypt() fails', async () => {
        const value = coldValue('secret', 'wd02', 'another secret');
        let syncError;
        try {
            decrypt(value, SECRET);
        } catch (err) {
            syncError = err;
        }
        await assert.rejects(decryptAsync(value, SECRET), err => err.code === syncError.code && err.message === syncError.message);
        await assert.rejects(decryptAsync('$wd02$aes-256-gcm$00$00$00$00', SECRET), err => err.code === 'InternalConfigError');
    });

    await t.test('the event loop keeps running while a cold key is derived', async () => {
        const value = coldValue('cold');
        let ticks = 0;
        const timer = setInterval(() => ticks++, 1);
        try {
            assert.strictEqual(await decryptAsync(value, SECRET), 'cold');
        } finally {
            clearInterval(timer);
        }
        assert.ok(ticks > 0, 'timers fired during the derivation');
    });

    await t.test('shares the key cache with decrypt(), also for concurrent callers on one salt', async () => {
        const salt = crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(SECRET, salt, PBKDF2_ITERATIONS, 32, PBKDF2_DIGEST);
        const values = Array.from({ length: 8 }, (v, i) => sealed('wd02', key, salt, crypto.randomBytes(12), `value ${i}`));

        assert.deepStrictEqual(
            await Promise.all(values.map(value => decryptAsync(value, SECRET))),
            values.map((v, i) => `value ${i}`)
        );

        // the synchronous path finds the key cached: no derivation, so no 600000 iteration delay
        const started = process.hrtime.bigint();
        assert.strictEqual(decrypt(values[0], SECRET), 'value 0');
        assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 20, 'decrypt() reused the key decryptAsync() derived');
    });

    await t.test('Account.loadAccountData() decrypts every credential and encrypted field', async () => {
        const account = `async-decrypt-${crypto.randomBytes(6).toString('hex')}`;
        const key = `${REDIS_PREFIX}iad:${account}`;
        try {
            await redis.hmset(key, {
                account,
                imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'u', pass: coldValue('imap pass') } }),
                smtp: JSON.stringify({ host: 'smtp.example.com', auth: { user: 'u', pass: coldValue('smtp pass', 'wd01') } }),
                oauth2: JSON.stringify({ provider: 'none', auth: { user: 'u' }, accessToken: coldValue('access'), refreshToken: encrypt('refresh', SECRET) }),
                webhooks: encrypt('https://user:pass@example.com/hook', SECRET)
            });
            const data = await new Account({ account, redis, secret: SECRET }).loadAccountData(account);
            assert.strictEqual(data.imap.auth.pass, 'imap pass');
            assert.strictEqual(data.smtp.auth.pass, 'smtp pass');
            assert.strictEqual(data.oauth2.accessToken, 'access');
            assert.strictEqual(data.oauth2.refreshToken, 'refresh');
            assert.strictEqual(data.webhooks, 'https://user:pass@example.com/hook');
        } finally {
            await redis.del(key);
        }
    });

    await t.test('property: round trips anything encrypt() writes', async () => {
        await forAll(
            // an array, so the emoji is one character rather than two lone surrogates
            gen.string([...'abcxyz 0123456789äö€\u{1F600}'], 1, 60),
            async text => {
                assert.strictEqual(await decryptAsync(encrypt(text, SECRET), SECRET), text);
            },
            { runs: 200 }
        );
    });
});

test('decryptAsync() bounds the derivations it runs at once', async () => {
    const { encrypt, decryptAsync } = require('../lib/encrypt');
    const crypto = require('node:crypto');
    // values with salts of their own, the way records written by older processes come back
    const secret = crypto.randomBytes(16).toString('hex');
    const values = [];
    for (let i = 0; i < 6; i++) {
        values.push(encrypt(`value-${i}`, secret));
    }
    let running = 0;
    let peak = 0;
    const original = crypto.pbkdf2;
    crypto.pbkdf2 = (...args) => {
        const callback = args.pop();
        running++;
        peak = Math.max(peak, running);
        original(...args, (err, key) => {
            running--;
            callback(err, key);
        });
    };
    try {
        // a fresh salt in each value, so each one needs a derivation of its own (the values then
        // fail to decrypt, which does not matter here)
        const distinct = values.map(value => {
            const parts = value.split('$');
            parts[parts.length - 2] = crypto.randomBytes(16).toString('hex');
            return parts.join('$');
        });
        await Promise.allSettled(distinct.map(value => decryptAsync(value, secret)));
    } finally {
        crypto.pbkdf2 = original;
    }
    assert.ok(peak >= 1, 'the derivations ran');
    assert.ok(peak <= 2, `at most two derivations at once, saw ${peak}`);
});
