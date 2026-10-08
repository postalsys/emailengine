'use strict';

// The admin form's third authentication method for gmailService apps, the attached service account.
// Rendered against the real templates and partials, because what matters is markup: the tab is
// always shown and badged as Pub/Sub only outside that base scope, the service account fields it does
// not use are hidden AND disabled (a hidden required field blocks the browser's submit, and a disabled
// one is left out of it), and a saved app shows its locked method instead of the tabs.

const test = require('node:test');
const assert = require('node:assert').strict;
const { compileView } = require('./helpers/admin-templates');
const { oauth2ProviderData } = require('../lib/oauth2-apps');
const { authMethodContext } = require('../lib/ui-routes/gmail-service-auth');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const formTemplate = compileView('partials/oauth_form.hbs');
const appTemplate = compileView('config/oauth/app.hbs');

// The context the OAuth2 app routes build (authMethodContext() included), reduced to what the form reads
function render(baseScopes, authMethod, { actionCreate = true, locked = false } = {}) {
    const providerData = oauth2ProviderData('gmailService');
    return formTemplate({
        activeGmailService: true,
        providerData,
        values: { provider: 'gmailService', baseScopes, authMethod },
        errors: {},
        pubSubApps: [],
        baseScopesApi: baseScopes === 'api',
        baseScopesImap: baseScopes === 'imap',
        baseScopesPubsub: baseScopes === 'pubsub',
        azureClouds: [],
        actionCreate,
        ...authMethodContext(authMethod, locked)
    });
}

const openingTag = (html, id) => {
    const match = html.match(new RegExp(`<[a-z]+\\b[^>]*\\bid="${id}"[^>]*>`, 's'));
    return match && match[0];
};

// The wrapper around the service account email and client ID fields
const serviceFieldsWrapper = html =>
    html.match(/<div\s+class="(auth-method-section auth-method-section-serviceKey auth-method-section-externalAccount[^"]*)"/)[1];

test('the attached service account on the gmailService form', async t => {
    await t.test('is always a tab, badged as Pub/Sub only outside that base scope', () => {
        for (const scope of ['imap', 'api', 'pubsub']) {
            const html = render(scope, 'serviceKey');
            const radio = openingTag(html, 'authMethodMetadataServer');
            assert.ok(radio, scope);
            assert.match(radio, /name="authMethod"/);
            assert.match(radio, /value="metadataServer"/);
            assert.doesNotMatch(radio, /\bdisabled\b/, `${scope}: always selectable, choosing it picks Pub/Sub`);
            const badge = openingTag(html, 'authMethodScopeBadge');
            assert.ok(badge, scope);
            assert.equal(/\bhidden\b/.test(badge), scope === 'pubsub', scope);
        }
    });

    await t.test('the base scope is asked before the credentials', () => {
        const html = render('imap', 'serviceKey');
        assert.ok(html.indexOf('id="baseScopesPubsub"') < html.indexOf('id="auth-method-tabs"'));
    });

    await t.test('when selected, submits its method and hides and disables the fields it does not use', () => {
        const html = render('pubsub', 'metadataServer');

        assert.match(openingTag(html, 'authMethodMetadataServer'), /\bchecked\b/);
        assert.doesNotMatch(openingTag(html, 'authMethodServiceKey'), /\bchecked\b/);
        assert.match(serviceFieldsWrapper(html), /\bhidden\b/);
        for (const id of ['serviceClientEmail', 'serviceClient']) {
            assert.match(openingTag(html, id), /\bdisabled\b/, id);
        }
        // the project is still needed: the topic and subscription are created in it
        assert.doesNotMatch(openingTag(html, 'googleProjectId'), /\bdisabled\b/);
        assert.ok(openingTag(html, 'metadataProbe'), 'the detect button is offered on the new app form');
    });

    await t.test('the signing methods keep their service account fields enabled', () => {
        for (const method of ['serviceKey', 'externalAccount']) {
            const html = render('pubsub', method);
            assert.doesNotMatch(serviceFieldsWrapper(html), /\bhidden\b/, method);
            assert.doesNotMatch(openingTag(html, 'serviceClientEmail'), /\bdisabled\b/, method);
        }
    });

    await t.test('a saved app shows its method instead of the tabs, with no detect button', () => {
        const html = render('pubsub', 'metadataServer', { actionCreate: false, locked: true });

        assert.equal(openingTag(html, 'auth-method-tabs'), null);
        assert.match(html, /<strong>Attached service account<\/strong>/);
        assert.match(openingTag(html, 'authMethod'), /value="metadataServer"/);
        assert.match(openingTag(html, 'serviceClient'), /\bdisabled\b/, 'the edit form can be saved without the fields');
        assert.equal(openingTag(html, 'metadataProbe'), null, 'nothing on the edit form asks the metadata server');
    });

    await t.test('the app page names the method', () => {
        const html = appTemplate({
            app: { id: 'a', name: 'x', provider: 'gmailService', baseScopes: 'pubsub', accounts: 0, meta: {} },
            providerData: oauth2ProviderData('gmailService'),
            appShowAuthMethod: true,
            ...authMethodContext('metadataServer'),
            baseScopesPubsub: true
        });
        assert.match(html, /Attached service account \(metadata server\)/);
    });
});
