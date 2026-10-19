'use strict';

// lib/utils/public-suffix.js replaced the psl package and reads the Public Suffix List from
// data/public_suffix_list.dat. The algorithm cases run against small hand-written lists, so they
// do not move when the published list changes; the last block checks the bundled copy itself.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');

const { getRegistrableDomain, parseList, LIST_PATH } = require('../lib/utils/public-suffix');

const LIST = [
    '// comment',
    '',
    'com',
    'uk',
    'co.uk',
    'jp',
    '*.kawasaki.jp',
    '!city.kawasaki.jp',
    '*.ck',
    '!www.ck',
    'github.io',
    '公司.cn',
    'cn',
    'com.cn'
].join('\n');
const rules = parseList(LIST);
const get = host => getRegistrableDomain(host, rules);

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

    await t.test('ignores case and a trailing dot', () => {
        assert.equal(get('IMAP.Example.COM'), 'example.com');
        assert.equal(get('imap.example.com.'), 'example.com');
    });

    await t.test('returns null for addresses and for what is not a host name', () => {
        for (const input of ['127.0.0.1', '::1', '[2001:db8::1]', '', '.', 'a..example.com', null, undefined, 42]) {
            assert.equal(get(input), null, JSON.stringify(input));
        }
    });
});

test('parseList', async t => {
    await t.test('reads only the first token of a rule line and skips comments', () => {
        const parsed = parseList('// com\nexample.com trailing words\n  \n*.wild.example\n!exc.wild.example');
        assert.deepEqual([...parsed.exact].sort(), ['example.com', 'wild.example']);
        assert.deepEqual([...parsed.wildcard], ['wild.example']);
        assert.deepEqual([...parsed.exception], ['exc.wild.example']);
    });

    await t.test('stores internationalised rules in ASCII form', () => {
        assert.ok(parseList('公司.cn').exact.has('xn--55qx5d.cn'));
    });
});

test('bundled public suffix list', async t => {
    const text = fs.readFileSync(LIST_PATH, 'utf-8');

    await t.test('is a complete copy with its licence header', () => {
        // copy-static-files.sh refuses a download missing any of these, and so does this test
        for (const marker of ['===BEGIN ICANN DOMAINS===', '===END ICANN DOMAINS===', '===BEGIN PRIVATE DOMAINS===', '===END PRIVATE DOMAINS===']) {
            assert.ok(text.includes(marker), marker);
        }
        assert.match(text, /Mozilla Public\s+\/\/ License, v\. 2\.0/);
        assert.match(text, /^\/\/ VERSION: \d{4}-\d{2}-\d{2}/m);
    });

    await t.test('resolves real mail hosts', () => {
        assert.equal(getRegistrableDomain('imap.gmail.com'), 'gmail.com');
        assert.equal(getRegistrableDomain('outlook.office365.com'), 'office365.com');
        assert.equal(getRegistrableDomain('imap.mail.yahoo.co.jp'), 'yahoo.co.jp');
        assert.equal(getRegistrableDomain('mail.example.co.uk'), 'example.co.uk');
        assert.equal(getRegistrableDomain('smtp.example.com.au'), 'example.com.au');
        assert.equal(getRegistrableDomain('mx.myapp.github.io'), 'myapp.github.io');
    });
});
