'use strict';

// Open/click tracker injection (lib/add-trackers.js).
//
// This rewrites the HTML of every outgoing message when tracking is enabled, so a mistake here
// ships in real mail: a mangled href breaks the recipient's link, a double-rewritten
// /unsubscribe URL breaks one-click unsubscribe, and a tracker appended to the wrong node
// corrupts the MIME structure. The integration tier (test/integration/tracking-e2e-test.js)
// covers the happy path end to end; these are the edge cases that are impractical to provoke
// against a live mailbox.
//
// lib/db is stubbed before any production import - getServiceSecret() then generates and
// "persists" a secret into the mock, which is all the signing needs.

const test = require('node:test');
const assert = require('node:assert').strict;
const { simpleParser } = require('mailparser');

// --- Mock setup ---
//
// The only production path these tests reach into Redis for is getServiceSecret(), which mints a
// secret with HSETNX and reads it back with HGET. The stub is deliberately kept to that surface
// rather than a full Redis mock: a larger mock would imply requirements that do not exist.

let mockRedisData = {};

const mockRedis = {
    hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
    hsetnx: async (key, field, value) => {
        if (!mockRedisData[key]) {
            mockRedisData[key] = {};
        }
        if (field in mockRedisData[key]) {
            return 0;
        }
        mockRedisData[key][field] = value;
        return 1;
    }
};

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: { redis: mockRedis }
};

const { addTrackers } = require('../lib/add-trackers');
const { verifyServiceSignature } = require('../lib/tools');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Force the process to exit once tests finish; requiring lib/tools opens BullMQ handles.
registerRedisTeardown();

const BASE_URL = 'https://ee.example.com/';
const ACCOUNT = 'acc1';
const MESSAGE_ID = '<msg1@example.com>';

function buildMessage(html) {
    return [
        'From: sender@example.com',
        'To: recipient@example.com',
        'Subject: Tracking test',
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=utf-8',
        '',
        html
    ].join('\r\n');
}

// Returns the decoded text/html body of the rewritten message, so the assertions run against
// the actual delivered HTML rather than the quoted-printable wire form.
async function trackedHtml(source, opts) {
    const out = await addTrackers(source, ACCOUNT, MESSAGE_ID, BASE_URL, opts);
    const parsed = await simpleParser(out);
    return parsed.html || '';
}

// Pulls the signed payload back out of a tracking URL and verifies it the way the /redirect and
// /open.gif handlers do, so a URL that would be rejected as forged cannot pass as valid here.
// Accepts the entity-encoded form the click rewriter emits inside an href attribute.
async function decodeTrackingPayload(url) {
    const parsed = new URL(url.replace(/&amp;/g, '&'));
    const data = parsed.searchParams.get('data');
    const sig = parsed.searchParams.get('sig');
    assert.ok(data, `tracking URL is missing its data blob: ${url}`);
    assert.ok(sig, `tracking URL is missing its signature: ${url}`);

    // The signature covers the DECODED blob, not the base64url text - same order as
    // parseSignedFormData() and the /open.gif + /redirect handlers.
    const decoded = Buffer.from(data, 'base64url').toString();
    assert.ok(await verifyServiceSignature(decoded, sig), `tracking URL signature does not verify: ${url}`);
    return JSON.parse(decoded);
}

function hrefsOf(html) {
    return [...html.matchAll(/<a[^>]*\shref\s*=\s*"([^"]*)"/gi)].map(match => match[1]);
}

test('addTrackers', async t => {
    await t.test('the open tracker is injected just before the body end tag', async () => {
        const html = await trackedHtml(buildMessage('<html><body><p>Hello</p></body></html>'), { trackOpens: true });

        assert.match(html, /<img[^>]+open\.gif/i, 'an open tracking pixel must be present');
        assert.ok(html.indexOf('open.gif') < html.indexOf('</body'), 'the pixel must sit inside the body, not after it');
    });

    await t.test('the open tracker is appended when the html has no body end tag', async () => {
        const html = await trackedHtml(buildMessage('<p>Fragment with no body wrapper</p>'), { trackOpens: true });

        assert.match(html, /open\.gif/);
        assert.ok(html.indexOf('Fragment with no body wrapper') < html.indexOf('open.gif'));
    });

    await t.test('the open tracker pixel is invisible and non-focusable', async () => {
        // A visible or tab-stop pixel shows up as a broken image in the recipient client
        const html = await trackedHtml(buildMessage('<html><body>Hi</body></html>'), { trackOpens: true });
        const img = html.match(/<img[^>]+open\.gif[^>]*>/i)[0];

        assert.match(img, /width="1"/);
        assert.match(img, /height="1"/);
        assert.match(img, /tabindex="-1"/);
        assert.match(img, /alt=""/);
        assert.match(img, /border:\s*0px/);
    });

    await t.test('the open tracker records the account and message id', async () => {
        const html = await trackedHtml(buildMessage('<html><body>Hi</body></html>'), { trackOpens: true });
        const src = html.match(/<img[^>]+src="([^"]+)"/i)[1];

        assert.deepStrictEqual(await decodeTrackingPayload(src), { act: 'open', acc: ACCOUNT, msg: MESSAGE_ID });
    });

    await t.test('exactly one open tracker is added across a multipart message', async () => {
        // Two html parts must not yield two pixels - the recipient would register two opens
        const source = [
            'From: sender@example.com',
            'Subject: multi',
            'MIME-Version: 1.0',
            'Content-Type: multipart/alternative; boundary=BOUND',
            '',
            '--BOUND',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<html><body>First</body></html>',
            '--BOUND',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<html><body>Second</body></html>',
            '--BOUND--',
            ''
        ].join('\r\n');

        const out = (await addTrackers(source, ACCOUNT, MESSAGE_ID, BASE_URL, { trackOpens: true })).toString();
        const pixels = out.split('open.').length - 1;

        assert.strictEqual(pixels, 1, `expected a single open tracker across all html parts, found ${pixels}`);
    });

    await t.test('an http link is rewritten through the redirect endpoint', async () => {
        const html = await trackedHtml(buildMessage('<p><a href="https://example.com/page">click</a></p>'), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.ok(href.startsWith('https://ee.example.com/redirect?'), `expected a redirect URL, got ${href}`);
        assert.deepStrictEqual(await decodeTrackingPayload(href), {
            act: 'click',
            url: 'https://example.com/page',
            acc: ACCOUNT,
            msg: MESSAGE_ID
        });
    });

    await t.test('the link text is left untouched', async () => {
        const html = await trackedHtml(buildMessage('<p><a href="https://example.com/page">Read the announcement</a></p>'), { trackClicks: true });

        assert.match(html, />Read the announcement</, 'only the href is rewritten, never the visible text');
    });

    await t.test('HTML entities in an href are decoded before the URL is recorded', async () => {
        // "&amp;" in the source markup is a literal "&" in the real URL. Signing the encoded
        // form would send the recipient to a URL with a stray "amp;" in the query string.
        const html = await trackedHtml(buildMessage('<p><a href="https://example.com/page?a=1&amp;b=2">click</a></p>'), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.strictEqual((await decodeTrackingPayload(href)).url, 'https://example.com/page?a=1&b=2');
    });

    await t.test('the rewritten href is entity encoded so the markup stays well formed', async () => {
        const html = await trackedHtml(buildMessage('<p><a href="https://example.com/page">click</a></p>'), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.match(href, /&amp;sig=/, 'the query separator must be encoded inside the attribute');
        assert.doesNotMatch(href, /[^&]&sig=/);
    });

    await t.test('an existing tracking link on the same origin is not rewritten again', async () => {
        // Double wrapping would nest one signed blob inside another and break the redirect
        const existing = 'https://ee.example.com/redirect?data=already&amp;sig=signed';
        const html = await trackedHtml(buildMessage(`<p><a href="${existing}">click</a></p>`), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.strictEqual(href, existing);
    });

    await t.test('an unsubscribe link on the same origin is not rewritten', async () => {
        // RFC 8058 one-click unsubscribe has to reach /unsubscribe directly
        const existing = 'https://ee.example.com/unsubscribe?data=blob';
        const html = await trackedHtml(buildMessage(`<p><a href="${existing}">unsubscribe</a></p>`), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.strictEqual(href, existing);
    });

    await t.test('a /redirect path on a DIFFERENT origin is still tracked', async () => {
        // The exemption is origin scoped - somebody else's /redirect is an ordinary link
        const html = await trackedHtml(buildMessage('<p><a href="https://other.example.net/redirect?x=1">click</a></p>'), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.ok(href.startsWith('https://ee.example.com/redirect?'));
        assert.strictEqual((await decodeTrackingPayload(href)).url, 'https://other.example.net/redirect?x=1');
    });

    await t.test('another path on the same origin is tracked normally', async () => {
        const html = await trackedHtml(buildMessage('<p><a href="https://ee.example.com/admin">console</a></p>'), { trackClicks: true });
        const [href] = hrefsOf(html);

        assert.strictEqual((await decodeTrackingPayload(href)).url, 'https://ee.example.com/admin');
    });

    await t.test('non-http schemes and anchors are left alone', async () => {
        const source = buildMessage(
            [
                '<p>',
                '<a href="mailto:someone@example.com">mail</a>',
                '<a href="tel:+3725551234">call</a>',
                '<a href="cid:image001.png">embedded</a>',
                '<a href="#section">anchor</a>',
                '<a href="/relative/path">relative</a>',
                '</p>'
            ].join('')
        );

        const html = await trackedHtml(source, { trackClicks: true });

        assert.deepStrictEqual(hrefsOf(html), ['mailto:someone@example.com', 'tel:+3725551234', 'cid:image001.png', '#section', '/relative/path']);
        assert.doesNotMatch(html, /\/redirect\?/, 'no redirect wrapper may be added for a non-http scheme');
    });

    await t.test('every http link in the message is rewritten', async () => {
        const source = buildMessage(
            '<p><a href="https://a.example.com/1">one</a> <a href="http://b.example.com/2">two</a> <a href="https://c.example.com/3">three</a></p>'
        );

        const html = await trackedHtml(source, { trackClicks: true });
        const hrefs = hrefsOf(html);

        assert.strictEqual(hrefs.length, 3);
        assert.deepStrictEqual(await Promise.all(hrefs.map(async href => (await decodeTrackingPayload(href)).url)), [
            'https://a.example.com/1',
            'http://b.example.com/2',
            'https://c.example.com/3'
        ]);
    });

    await t.test('click tracking alone adds no open pixel, and vice versa', async () => {
        const source = buildMessage('<html><body><a href="https://example.com/p">click</a></body></html>');

        const clicksOnly = await trackedHtml(source, { trackClicks: true });
        assert.doesNotMatch(clicksOnly, /open\.gif/);
        assert.match(clicksOnly, /\/redirect\?/);

        const opensOnly = await trackedHtml(source, { trackOpens: true });
        assert.match(opensOnly, /open\.gif/);
        assert.doesNotMatch(opensOnly, /\/redirect\?/);
        assert.deepStrictEqual(hrefsOf(opensOnly), ['https://example.com/p'], 'the original link must survive untouched');
    });

    await t.test('with tracking disabled the html is returned unchanged', async () => {
        const source = buildMessage('<html><body><a href="https://example.com/p">click</a></body></html>');

        for (const opts of [{}, undefined, { trackClicks: false, trackOpens: false }]) {
            const html = await trackedHtml(source, opts);
            assert.doesNotMatch(html, /open\.gif/);
            assert.doesNotMatch(html, /\/redirect\?/);
            assert.deepStrictEqual(hrefsOf(html), ['https://example.com/p']);
        }
    });

    await t.test('a text/plain part is never rewritten', async () => {
        // Injecting an img tag or a rewritten URL into the plaintext alternative would show up
        // as raw markup for recipients reading the plaintext version.
        const source = [
            'From: sender@example.com',
            'Subject: alt',
            'MIME-Version: 1.0',
            'Content-Type: multipart/alternative; boundary=BOUND',
            '',
            '--BOUND',
            'Content-Type: text/plain; charset=utf-8',
            '',
            'Visit https://example.com/page for details',
            '--BOUND',
            'Content-Type: text/html; charset=utf-8',
            '',
            '<html><body><a href="https://example.com/page">link</a></body></html>',
            '--BOUND--',
            ''
        ].join('\r\n');

        const out = await addTrackers(source, ACCOUNT, MESSAGE_ID, BASE_URL, { trackClicks: true, trackOpens: true });
        const parsed = await simpleParser(out);

        assert.strictEqual(parsed.text.trim(), 'Visit https://example.com/page for details');
        assert.match(parsed.html, /\/redirect\?/, 'the html alternative is still tracked');
    });

    await t.test('single quoted and unspaced href attributes are rewritten too', async () => {
        const html = await trackedHtml(buildMessage(`<p><a class="btn" href='https://example.com/single'>click</a></p>`), { trackClicks: true });

        assert.match(html, /\/redirect\?/, 'an href written with single quotes must not escape tracking');
        assert.doesNotMatch(html, /href='?https:\/\/example\.com\/single/);
    });
});
