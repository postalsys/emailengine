'use strict';

// The hostname list the TLS configuration form posts.
//
// It is a textarea, and operators fill textareas with whatever separates names in their head:
// newlines, commas, spaces, trailing blank lines, an IPv6 literal still wearing the brackets it
// had in a URL. All of it has to arrive in the settings store as a clean list, because the list is
// what certificates are ordered for and what the self-signed fallback is regenerated against.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_routes';

const { parseHostnameList } = require('../lib/ui-routes/tls-config-routes');
const { settingsSchema } = require('../lib/schemas');
const { redis } = require('../lib/db');

test('TLS hostname list parsing', async t => {
    t.after(() => {
        redis.quit();
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('accepts newlines, commas and stray whitespace', () => {
        assert.deepEqual(parseHostnameList('mail.example.com\nsmtp.example.com'), ['mail.example.com', 'smtp.example.com']);
        assert.deepEqual(parseHostnameList('mail.example.com, smtp.example.com'), ['mail.example.com', 'smtp.example.com']);
        assert.deepEqual(parseHostnameList('  mail.example.com  \r\n\r\n  smtp.example.com  \n'), ['mail.example.com', 'smtp.example.com']);
    });

    await t.test('lower-cases and deduplicates', () => {
        assert.deepEqual(parseHostnameList('Mail.Example.COM\nmail.example.com'), ['mail.example.com']);
    });

    await t.test('unwraps an IPv6 literal', () => {
        // Copied out of a URL, where the brackets belong; a certificate name has none.
        assert.deepEqual(parseHostnameList('[2001:db8::1]'), ['2001:db8::1']);
    });

    await t.test('an empty field is an empty list, not a list with an empty name', () => {
        assert.deepEqual(parseHostnameList(''), []);
        assert.deepEqual(parseHostnameList('   \n  \n'), []);
        assert.deepEqual(parseHostnameList(null), []);
    });
});

test('the settings form refuses a hostname the REST API would refuse', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 500).unref();
    });

    // The textarea is validated as free text, so the parsed list goes through the same schema the
    // REST API applies. Without it the form is the one way to store a "hostname" that no
    // certificate could ever be issued for.
    assert.equal(settingsSchema.tlsHostnames.validate(parseHostnameList('mail.example.com\nsmtp.example.com')).error, undefined);
    assert.equal(settingsSchema.tlsHostnames.validate(parseHostnameList('[2001:db8::1]')).error, undefined);
    assert.ok(settingsSchema.tlsHostnames.validate(['bad name']).error, 'a space is not a hostname');
    assert.ok(settingsSchema.tlsHostnames.validate(['<script>']).error, 'and neither is markup');
});
