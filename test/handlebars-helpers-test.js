'use strict';

// The view helpers registered by lib/handlebars-helpers.js, rendered through a private
// Handlebars instance so the global one vision uses is left alone. Pure: no Redis, no server.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');
const Handlebars = require('handlebars');

const { gt } = require('../lib/translations');
const { registerHandlebarsHelpers } = require('../lib/handlebars-helpers');

const handlebars = Handlebars.create();
registerHandlebarsHelpers(handlebars, { gt });

const render = (source, context) => handlebars.compile(source)(context || {});
const view = name => fs.readFileSync(pathlib.join(__dirname, '..', 'views', `${name}.hbs`), 'utf-8');

test('the translation helper escapes its parameters', async t => {
    await t.test('a parameter carrying a quote cannot leave the attribute it is placed in', () => {
        // The hosted-form success page wrote the redirect URL into href="%s" unescaped; a URL whose
        // host carries %22 decodes to a literal quote in URL.href
        const payload = 'http://x"autofocus"onfocus=alert(1)".com/?account=a';
        const html = render(view('redirect'), { httpRedirectUrl: payload });

        assert.ok(!html.includes('"autofocus"'), `the quote was not escaped: ${html}`);
        assert.match(html, /href="http:\/\/x&quot;autofocus&quot;onfocus&#x3D;alert\(1\)&quot;\.com\/\?account&#x3D;a"/);
        assert.match(html, /<a href="/, 'the markup of the message itself stays live');
    });

    await t.test('markup in a parameter is escaped', () => {
        assert.equal(render('{{_ "Error code: %s" null value}}', { value: '<b>x</b>' }), 'Error code: &lt;b&gt;x&lt;/b&gt;');
    });

    await t.test('an escapeHtml subexpression is escaped once, not twice', () => {
        const html = render('{{_ "Address <em>%s</em>" null (escapeHtml email)}}', { email: 'a&b<c>@example.com' });
        assert.equal(html, 'Address <em>a&amp;b&lt;c&gt;@example.com</em>');
    });

    await t.test('a markup literal is passed through as markup', () => {
        const html = render(`{{_ "Click <a%s>here</a>" null (markup " id='x' href='#'")}}`);
        assert.equal(html, "Click <a id='x' href='#'>here</a>");
    });

    await t.test('the markup helper refuses anything that is not a string', () => {
        assert.equal(render('{{markup value}}', { value: { toString: () => '<script>' } }), '');
    });

    await t.test('the unsubscribe page keeps its re-subscribe link', () => {
        const html = render(view('unsubscribe'), { unsubscribed: true, values: { email: '"><img>@example.com' } });
        assert.match(html, /<a id='resubscribe-link' href='#' class='ee-link'>/);
        assert.ok(!html.includes('"><img>'), 'the address is escaped');
    });
});

test('isodate', async t => {
    await t.test('formats a timestamp', () => {
        assert.equal(render('{{isodate t}}', { t: 0 }), '1970-01-01T00:00:00.000Z');
    });

    await t.test('renders nothing for an invalid time instead of throwing', () => {
        assert.equal(render('{{isodate t}}', { t: 'not a time' }), '');
        assert.equal(render('{{isodate t}}', {}), '');
    });
});

test('lastVal returns text, which Handlebars escapes', () => {
    assert.equal(render('{{lastVal v "/"}}', { v: 'projects/p/topics/<b>x' }), '&lt;b&gt;x');
});

test('ngettext', async t => {
    await t.test('picks the plural form and formats the count', () => {
        assert.equal(render('{{ngettext "%d day" "%d days" n}}', { n: 1 }), '1 day');
        assert.equal(render('{{ngettext "%d day" "%d days" n}}', { n: 3 }), '3 days');
    });

    await t.test('takes a locale', () => {
        let used = null;
        const fakeGt = {
            useLocale(locale) {
                used = locale;
                return { ngettext: (msgid, plural, count) => (count === 1 ? msgid : plural) };
            },
            ngettext: () => 'default %d'
        };
        const local = Handlebars.create();
        registerHandlebarsHelpers(local, { gt: fakeGt });
        assert.equal(local.compile('{{ngettext "%d day" "%d days" n "de"}}')({ n: 2 }), '2 days');
        assert.equal(used, 'de');
        assert.equal(local.compile('{{ngettext "%d day" "%d days" n}}')({ n: 2 }), 'default 2');
    });
});

test('the admin views are cached outside development', () => {
    // Uncached, vision re-read and re-registered every partial with synchronous fs calls on each
    // render, blocking the API worker. Pinned in the source because the view manager is only
    // built inside the running worker.
    const source = fs.readFileSync(pathlib.join(__dirname, '..', 'workers', 'api.js'), 'utf-8');
    const views = source.slice(source.indexOf('server.views({'));
    assert.match(views.slice(0, 2000), /isCached: process\.env\.NODE_ENV !== 'development'/);
});
