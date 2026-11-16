'use strict';

// lib/utils/public-suffix.js answers through tldts, which compiles the Public Suffix List in. Until
// 2026-11 EmailEngine parsed its own copy of the list; these cases were written against that
// implementation and are kept as fixed expectations (a parity run over the 31 678 names derived from
// the list's rules found no difference). They use rules that have been in the list for many years.

const test = require('node:test');
const assert = require('node:assert').strict;

const { getRegistrableDomain } = require('../lib/utils/public-suffix');
const get = getRegistrableDomain;

test('getRegistrableDomain', async t => {
    await t.test('returns the public suffix plus one label', () => {
        assert.equal(get('example.com'), 'example.com');
        assert.equal(get('imap.mail.example.com'), 'example.com');
        assert.equal(get('imap.mail.example.co.uk'), 'example.co.uk');
    });

    await t.test('prefers the matching rule with the most labels', () => {
        // "uk" and "co.uk" both match; "co.uk" wins
        assert.equal(get('example.co.uk'), 'example.co.uk');
        assert.equal(get('co.uk'), null);
    });

    await t.test('treats every label under a wildcard rule as a suffix, the wildcard parent too', () => {
        assert.equal(get('foo.bar.kawasaki.jp'), 'foo.bar.kawasaki.jp');
        assert.equal(get('x.foo.bar.kawasaki.jp'), 'foo.bar.kawasaki.jp');
        assert.equal(get('bar.kawasaki.jp'), null);
        assert.equal(get('kawasaki.jp'), null);
        assert.equal(get('test.ck'), null);
        assert.equal(get('b.test.ck'), 'b.test.ck');
    });

    await t.test('lets an exception rule override the wildcard it carves out of', () => {
        assert.equal(get('city.kawasaki.jp'), 'city.kawasaki.jp');
        assert.equal(get('www.city.kawasaki.jp'), 'city.kawasaki.jp');
        assert.equal(get('www.ck'), 'www.ck');
        assert.equal(get('mail.www.ck'), 'www.ck');
    });

    await t.test('applies the private section like any other rule', () => {
        assert.equal(get('myapp.github.io'), 'myapp.github.io');
        assert.equal(get('github.io'), null);
    });

    await t.test('falls back to the last label for a top-level domain the list does not know', () => {
        assert.equal(get('mail.example.unknowntld'), 'example.unknowntld');
        assert.equal(get('unknowntld'), null);
    });

    await t.test('matches internationalised names in either spelling and answers in the input one', () => {
        assert.equal(get('mail.食狮.公司.cn'), '食狮.公司.cn');
        assert.equal(get('mail.xn--85x722f.xn--55qx5d.cn'), 'xn--85x722f.xn--55qx5d.cn');
        assert.equal(get('www.食狮.com.cn'), '食狮.com.cn');
    });

    await t.test('reads a name with a non-ASCII full stop, or a label a strict check would refuse', () => {
        assert.equal(get('mail.example\u3002com'), 'example.com');
        assert.equal(get('-bad-.example.com'), 'example.com');
        assert.equal(get('dkim_selector.example.com'), 'example.com');
    });

    await t.test('ignores case and a trailing dot', () => {
        assert.equal(get('IMAP.Example.COM'), 'example.com');
        assert.equal(get('imap.example.com.'), 'example.com');
    });

    await t.test('returns null for addresses and for what is not a host name', () => {
        for (const input of ['127.0.0.1', '::1', '[2001:db8::1]', '', '.', 'a..example.com', 'co.uk', null, undefined, 42]) {
            assert.equal(get(input), null, JSON.stringify(input));
        }
    });
});

test('real mail hosts', async t => {
    await t.test('resolves real mail hosts', () => {
        assert.equal(getRegistrableDomain('imap.gmail.com'), 'gmail.com');
        assert.equal(getRegistrableDomain('outlook.office365.com'), 'office365.com');
        assert.equal(getRegistrableDomain('imap.mail.yahoo.co.jp'), 'yahoo.co.jp');
        assert.equal(getRegistrableDomain('mail.example.co.uk'), 'example.co.uk');
        assert.equal(getRegistrableDomain('smtp.example.com.au'), 'example.com.au');
        assert.equal(getRegistrableDomain('mx.myapp.github.io'), 'myapp.github.io');
    });
});
