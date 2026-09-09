'use strict';

// The hostname the TLS certificates page adds to its table.
//
// It arrives from one text input, and operators type whatever a hostname looks like in their head:
// mixed case, surrounding whitespace, an IPv6 literal still wearing the brackets it had in a URL.
// It has to arrive in the settings store as the one spelling the certificate stores use, because
// the list is what certificates are ordered for and what the self-signed fallback is regenerated
// against - and it has to pass the same schema the REST API applies to the list, so the form is not
// the one way to store a "hostname" that no certificate could ever be issued for.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_routes';

const { parseHostname, validateHostname } = require('../lib/ui-routes/tls-config-routes');
const { redis } = require('../lib/db');

test('TLS hostname input', async t => {
    t.after(() => {
        redis.quit();
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('folds case and stray whitespace', () => {
        assert.equal(parseHostname('  Mail.Example.COM  '), 'mail.example.com');
        assert.equal(parseHostname('smtp.example.com\n'), 'smtp.example.com');
    });

    await t.test('unwraps an IPv6 literal', () => {
        // Copied out of a URL, where the brackets belong; a certificate name has none.
        assert.equal(parseHostname('[2001:db8::1]'), '2001:db8::1');
    });

    await t.test('an empty field is an empty name, not a name made of nothing', () => {
        assert.equal(parseHostname(''), '');
        assert.equal(parseHostname('   '), '');
        assert.equal(parseHostname(null), '');
    });

    await t.test('accepts what the REST API accepts', () => {
        assert.equal(validateHostname('smtp.example.com'), 'smtp.example.com');
        assert.equal(validateHostname('[2001:db8::1]'), '2001:db8::1');
    });

    await t.test('refuses what the REST API refuses, by name', () => {
        assert.throws(() => validateHostname('bad name'), /Not a valid hostname/, 'a space is not a hostname');
        assert.throws(() => validateHostname('<script>'), /Not a valid hostname/, 'and neither is markup');
        assert.throws(() => validateHostname(''), /Enter a hostname/, 'an empty field is asked for, not refused as invalid');
    });

    await t.test('refuses a port, which the colon allowed for IPv6 used to let through', () => {
        // A host:port copied out of a mail client's settings is not a name a certificate can be
        // issued for; stored as one it was a permanently failing order and a reachability check
        // made against the IMAPS port in plain HTTP.
        assert.throws(() => validateHostname('mail.example.com:993'), /must not include a port/);
        assert.throws(() => validateHostname('[2001:db8::1]:993'), /Not a valid hostname/);
        assert.throws(() => validateHostname('192.0.2.10:443'), /must not include a port/);

        // The IPv6 literal the colon is for still passes, bracketed or bare.
        assert.equal(validateHostname('2001:db8::1'), '2001:db8::1');
        assert.equal(validateHostname('[2001:db8::1]'), '2001:db8::1');
    });
});
