'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { generateTotpSeed, verifyTotp, generateTotpUrl } = require('../lib/totp');
const { TOTP_WINDOW_SIZE } = require('../lib/consts');

// Regression vectors generated with speakeasy 2.0.0 through the exact call the admin login
// used (secret: base32(seed bytes), encoding: 'base32'), so seeds stored by earlier releases
// keep verifying after the library swap. Seeds cover the generateSecret() alphanumeric charset
// and a symbol-bearing legacy variant.
const SPEAKEASY_VECTORS = [
    { seed: 'x9yTNw2SPNe7V6EjsRWq', time: 1767225600000, code: '096426' },
    { seed: 'x9yTNw2SPNe7V6EjsRWq', time: 1786365296000, code: '324193' },
    { seed: 'x9yTNw2SPNe7V6EjsRWq', time: 1924991999000, code: '633013' },
    { seed: 'x&yTNw9S(Ne7V6Ejs&W)', time: 1767225600000, code: '385668' },
    { seed: 'x&yTNw9S(Ne7V6Ejs&W)', time: 1786365296000, code: '873156' },
    { seed: 'x&yTNw9S(Ne7V6Ejs&W)', time: 1924991999000, code: '242750' },
    { seed: 'abcDEF123ghiJKL456mn', time: 1767225600000, code: '451849' },
    { seed: 'abcDEF123ghiJKL456mn', time: 1786365296000, code: '177385' },
    { seed: 'abcDEF123ghiJKL456mn', time: 1924991999000, code: '634020' }
];

// RFC 6238 Appendix B test vectors for HMAC-SHA-1, truncated to 6 digits
const RFC6238_VECTORS = [
    { time: 59000, code: '287082' },
    { time: 1111111109000, code: '081804' },
    { time: 1111111111000, code: '050471' },
    { time: 1234567890000, code: '005924' },
    { time: 2000000000000, code: '279037' },
    { time: 20000000000000, code: '353130' }
];
const RFC6238_SEED = '12345678901234567890';

test('TOTP tests', async t => {
    await t.test('verifies RFC 6238 test vectors', () => {
        for (let { time, code } of RFC6238_VECTORS) {
            assert.strictEqual(verifyTotp(RFC6238_SEED, code, { now: time }), true, `vector at ${time}`);
        }
    });

    await t.test('verifies codes for seeds stored by speakeasy-based releases', () => {
        for (let { seed, time, code } of SPEAKEASY_VECTORS) {
            assert.strictEqual(verifyTotp(seed, code, { now: time }), true, `vector ${seed} at ${time}`);
        }
    });

    await t.test('rejects a valid code against a different seed', () => {
        let { time, code } = SPEAKEASY_VECTORS[0];
        assert.strictEqual(verifyTotp('abcDEF123ghiJKL456mn', code, { now: time }), false);
    });

    await t.test('accepts codes within the verification window and rejects outside it', () => {
        // vector time is aligned to a 30-second step boundary
        let { seed, time, code } = SPEAKEASY_VECTORS[0];
        let step = 30 * 1000;

        assert.strictEqual(verifyTotp(seed, code, { now: time + 6 * step, window: 6 }), true, 'code from 6 steps ago');
        assert.strictEqual(verifyTotp(seed, code, { now: time - 6 * step, window: 6 }), true, 'code from 6 steps ahead');
        assert.strictEqual(verifyTotp(seed, code, { now: time + 7 * step, window: 6 }), false, 'code from 7 steps ago');
        assert.strictEqual(verifyTotp(seed, code, { now: time - 7 * step, window: 6 }), false, 'code from 7 steps ahead');
        assert.strictEqual(verifyTotp(seed, code, { now: time + step }), false, 'stale code with no window');
    });

    await t.test('the login window admits one step of clock drift either side, no more', () => {
        // The admin login and TOTP enrollment verify with TOTP_WINDOW_SIZE. Every extra step
        // is another valid code for a guess to land on, so the constant is pinned to behavior
        let { seed, time, code } = SPEAKEASY_VECTORS[0];
        let step = 30 * 1000;

        assert.strictEqual(verifyTotp(seed, code, { now: time + step, window: TOTP_WINDOW_SIZE }), true, 'code from the previous step');
        assert.strictEqual(verifyTotp(seed, code, { now: time - step, window: TOTP_WINDOW_SIZE }), true, 'code from the next step');
        assert.strictEqual(verifyTotp(seed, code, { now: time + 2 * step, window: TOTP_WINDOW_SIZE }), false, 'code from two steps ago');
        assert.strictEqual(verifyTotp(seed, code, { now: time - 2 * step, window: TOTP_WINDOW_SIZE }), false, 'code from two steps ahead');
    });

    await t.test('rejects malformed tokens', () => {
        let { seed, time } = SPEAKEASY_VECTORS[0];
        for (let token of ['12345', '1234567', 'abcdef', '', null, undefined, '09642a']) {
            assert.strictEqual(verifyTotp(seed, token, { now: time, window: 6 }), false, `token ${JSON.stringify(token)}`);
        }
    });

    await t.test('accepts a padded token string', () => {
        let { seed, time, code } = SPEAKEASY_VECTORS[0];
        assert.strictEqual(verifyTotp(seed, ` ${code} `, { now: time }), true);
    });

    await t.test('builds the same otpauth: URL as the speakeasy-based code did', () => {
        // pinned against speakeasy.otpauthURL() output for this seed and label
        let url = generateTotpUrl('x9yTNw2SPNe7V6EjsRWq', { label: 'ee.example.com', issuer: 'EmailEngine' });
        assert.strictEqual(url, 'otpauth://totp/ee.example.com?secret=PA4XSVCOO4ZFGUCOMU3VMNSFNJZVEV3R&issuer=EmailEngine');
    });

    await t.test('URL-encodes label and issuer', () => {
        let url = generateTotpUrl('x9yTNw2SPNe7V6EjsRWq', { label: 'ee.example.com/path name', issuer: 'Email Engine' });
        let parsed = new URL(url);
        assert.strictEqual(parsed.protocol, 'otpauth:');
        assert.strictEqual(parsed.pathname, '/ee.example.com%2Fpath%20name');
        assert.strictEqual(parsed.searchParams.get('issuer'), 'Email Engine');
    });

    await t.test('generated seeds are 20 alphanumeric characters and unique', () => {
        let seen = new Set();
        for (let i = 0; i < 100; i++) {
            let seed = generateTotpSeed();
            assert.match(seed, /^[a-zA-Z0-9]{20}$/);
            seen.add(seed);
        }
        assert.strictEqual(seen.size, 100);
    });
});
