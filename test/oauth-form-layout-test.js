'use strict';

// The layout rules of the OAuth2 app form, shared by every provider's new and edit pages. Rendered
// against the real templates and partials, because these are markup decisions: what is asked in which
// order, which fields a provider is given, and which of them the browser treats as required.

const test = require('node:test');
const assert = require('node:assert').strict;
const { compileView } = require('./helpers/admin-templates');
const { oauth2ProviderData } = require('../lib/oauth2-apps');
const { baseScopesContext } = require('../lib/ui-routes/oauth-form-context');
const { authMethodContext } = require('../lib/ui-routes/gmail-service-auth');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const formTemplate = compileView('partials/oauth_form.hbs');

function render(provider, { baseScopes = 'imap', actionCreate = true, values = {}, extra = {} } = {}) {
    const providerData = oauth2ProviderData(provider);
    return formTemplate({
        [`active${providerData.caseName}`]: true,
        providerData,
        values: Object.assign({ provider, baseScopes }, values),
        errors: {},
        pubSubApps: [],
        azureClouds: [{ id: 'global', name: 'Azure global service', selected: true }],
        mainServiceUrl: 'https://ee.example.com',
        defaultRedirectUrl: 'https://ee.example.com/oauth',
        actionCreate,
        ...baseScopesContext(baseScopes),
        ...authMethodContext('serviceKey'),
        ...extra
    });
}

const openingTag = (html, id) => {
    const match = html.match(new RegExp(`<[a-z]+\\b[^>]*\\bid="${id}"[^>]*>`, 's'));
    return match && match[0];
};

const cardTitles = html => [...html.matchAll(/<h6 class="card-title[^"]*">([^<]+)<\/h6>/g)].map(match => match[1].trim());

test('the OAuth2 app form layout', async t => {
    await t.test('the base scope is asked before the credentials on every provider that has one', () => {
        for (const provider of ['gmail', 'gmailService', 'outlook', 'outlookService']) {
            assert.deepEqual(cardTitles(render(provider)), ['Application', 'Base scope', 'Credentials'], provider);
        }
        // Mail.ru has the one mode, so there is nothing to ask
        assert.deepEqual(cardTitles(render('mailRu')), ['Application', 'Credentials']);
    });

    await t.test('the base scope is a choice on create and a fixed fact on edit', () => {
        const created = render('gmail');
        assert.ok(openingTag(created, 'base-scope-tabs'), 'the strip is offered on create');
        assert.match(openingTag(created, 'baseScopesImap'), /\bchecked\b/);

        const edited = render('gmail', { baseScopes: 'api', actionCreate: false });
        assert.equal(openingTag(edited, 'base-scope-tabs'), null, 'a stored scope cannot change');
        assert.match(edited, /<strong>Gmail API<\/strong>/);
    });

    await t.test('the Outlook tenant ID is only offered for the single-tenant choice', () => {
        const multi = render('outlook', { extra: { authorityCommon: true } });
        assert.match(openingTag(multi, 'tenant-field'), /\bhidden\b/);
        assert.match(openingTag(multi, 'tenant'), /\bdisabled\b/, 'a hidden tenant ID is not submitted');

        const single = render('outlook', { extra: { authorityTenant: true }, values: { tenant: 'f8cdef31' } });
        assert.doesNotMatch(openingTag(single, 'tenant-field'), /\bhidden\b/);
        assert.doesNotMatch(openingTag(single, 'tenant'), /\bdisabled\b/);
        assert.match(single, /<option value="tenant" selected>/);
    });

    await t.test('the client secret is required until one is stored', () => {
        assert.match(openingTag(render('gmail'), 'clientSecret'), /\brequired\b/);
        assert.match(openingTag(render('gmail'), 'clientSecret'), /type="password"/, 'not shown while typed');

        const stored = openingTag(render('gmail', { actionCreate: false, extra: { hasClientSecret: true } }), 'clientSecret');
        assert.doesNotMatch(stored, /\brequired\b/, 'an edit can keep the stored secret');
        assert.match(stored, /placeholder="Set, not shown/);
    });

    await t.test('custom scopes are one optional card, open while either list has entries', () => {
        const closed = render('gmail');
        assert.equal((closed.match(/<details/g) || []).length, 1);
        assert.doesNotMatch(openingTag(closed, 'setupScopes'), /\bopen\b/);
        assert.ok(openingTag(closed, 'extraScopes') && openingTag(closed, 'skipScopesList'));

        for (const values of [{ extraScopes: 'https://www.googleapis.com/auth/gmail.send' }, { skipScopes: 'SMTP.Send' }]) {
            assert.match(openingTag(render('gmail', { values }), 'setupScopes'), /\bopen\b/, JSON.stringify(values));
        }
    });

    await t.test('every provider links its setup guide with descriptive text', () => {
        for (const provider of ['gmail', 'gmailService', 'outlook', 'outlookService']) {
            const providerData = oauth2ProviderData(provider);
            if (providerData.tutorialUrl) {
                assert.match(render(provider), new RegExp(`Read the ${providerData.comment.replace(/[()]/g, '\\$&')} setup guide`), provider);
            }
        }
        assert.doesNotMatch(render('outlook'), />here<\/a>/);
    });
});
