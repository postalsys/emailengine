'use strict';

// `baseScopes: 'api'` is what makes a Gmail OAuth2 app reach the Gmail HTTP API instead of IMAP
// XOAUTH2, and it is not a property of the provider: isApiBasedApp() keys on that field alone, so a
// SERVICE ACCOUNT delegated gmail.modify is as API-based as an interactive app. The schema accepted it,
// verifyGmailService() had a Gmail API probe branch for exactly that combination, and the account
// loader handed those accounts the Gmail API client - but the admin form offered the choice for the
// interactive `gmail` provider only, so the mode was reachable over POST /v1/oauth2 and nowhere else.
//
// The form is rendered here against the real templates and the real partials, because most of the
// defect was in the markup: a route test cannot see which radio rows a provider is given, nor which
// scopes its page tells the operator to enable.

const test = require('node:test');
const assert = require('node:assert').strict;
const { compileView } = require('./helpers/admin-templates');
const { oauth2ProviderData, isApiBasedApp } = require('../lib/oauth2-apps');
const { isSendOnlyGmailApp } = require('../lib/oauth/scope-checker');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const formTemplate = compileView('partials/oauth_form.hbs');
const scopeInfoTemplate = compileView('partials/scope_info.hbs');

// The view context the OAuth2 app routes build, reduced to what these templates read
function context(provider, baseScopes, extra = {}) {
    const providerData = oauth2ProviderData(provider);
    return {
        [`active${providerData.caseName}`]: true,
        providerData,
        values: { provider, baseScopes },
        errors: {},
        disabledScopes: {},
        pubSubApps: [{ id: 'pubsub-app-1', name: 'PubSub SA', googleProjectId: 'proj-1' }],
        baseScopesApi: baseScopes === 'api',
        baseScopesImap: baseScopes === 'imap',
        baseScopesPubsub: baseScopes === 'pubsub',
        azureClouds: [],
        mainServiceUrl: 'https://ee.example.com',
        ...extra
    };
}

function render(provider, baseScopes, { actionCreate = true } = {}) {
    return formTemplate(context(provider, baseScopes, { actionCreate }));
}

// The scopes the stored app's page tells the operator to enable, short-named for readability
function requiredScopes(provider, baseScopes, extra) {
    const html = scopeInfoTemplate(context(provider, baseScopes, extra));
    return {
        scopes: [...html.matchAll(/<code>"([^"]+)"<\/code>/g)].map(match => match[1].replace('https://www.googleapis.com/auth/', '')),
        sendOnlyAlert: /Send-only account limitation/.test(html)
    };
}

// Each base scope panel declares the scope that reveals it; returns { imap: 'shown'|'hidden', ... }
function toggledSections(html) {
    const sections = {};
    for (const match of html.matchAll(/class="([^"]*)"\s*\n?\s*data-base-scopes="(\w+)"/g)) {
        sections[match[2]] = /\bhidden\b/.test(match[1]) ? 'hidden' : 'shown';
    }
    return sections;
}

// The opening tag of the base scope radio for a value, from the choice-tab strip
const scopeRadio = (html, value) => {
    const match = html.match(new RegExp(`<input[^>]*name="baseScopes"[^>]*value="${value}"[^>]*>`, 's'));
    return match && match[0];
};

test('the Gmail API mode is offered to both Gmail providers', async t => {
    await t.test('the mode is a property of baseScopes, not of the provider', () => {
        assert.equal(isApiBasedApp({ provider: 'gmailService', baseScopes: 'api' }), true);
        assert.equal(isApiBasedApp({ provider: 'gmail', baseScopes: 'api' }), true);
        // The default stays IMAP XOAUTH2 for both
        assert.equal(isApiBasedApp({ provider: 'gmailService', baseScopes: 'imap' }), false);
        assert.equal(isApiBasedApp({ provider: 'gmail', baseScopes: 'imap' }), false);
    });

    await t.test('providerData says which providers can reach the API', () => {
        // The form guards the controls that only make sense in that mode on this, rather than on one
        // provider name, so a third Gmail provider would get them by joining GMAIL_PROVIDERS
        assert.equal(oauth2ProviderData('gmail').gmailApi, true);
        assert.equal(oauth2ProviderData('gmailService').gmailApi, true);
        for (const provider of ['outlook', 'outlookService', 'mailRu']) {
            assert.equal(oauth2ProviderData(provider).gmailApi, false, provider);
        }
    });

    await t.test('a send-only app is recognised for both providers', () => {
        // Gated on `provider === 'gmail'` before, so a service account delegated gmail.send alone was
        // presented as a full-access app. The scope presets write a skipScopes entry beside the extra
        // scope, which is what takes the api-mode default back out again.
        for (const provider of ['gmail', 'gmailService']) {
            assert.equal(isSendOnlyGmailApp({ provider, baseScopes: 'api', extraScopes: ['gmail.send'], skipScopes: ['gmail.modify'] }), true, provider);
            assert.equal(
                isSendOnlyGmailApp({
                    provider,
                    baseScopes: 'api',
                    extraScopes: ['https://www.googleapis.com/auth/gmail.send'],
                    skipScopes: ['https://www.googleapis.com/auth/gmail.modify']
                }),
                true,
                `${provider}, full URLs`
            );
            assert.equal(
                isSendOnlyGmailApp({ provider, baseScopes: 'api', extraScopes: ['gmail.send', 'gmail.readonly'], skipScopes: ['gmail.modify'] }),
                false,
                `${provider}, can read`
            );
            assert.equal(isSendOnlyGmailApp({ provider, baseScopes: 'api', extraScopes: [] }), false, `${provider}, default scopes`);
            // Only the API mode can be send-only; an IMAP app takes https://mail.google.com/
            assert.equal(isSendOnlyGmailApp({ provider, baseScopes: 'imap', extraScopes: ['gmail.send'] }), false, `${provider}, IMAP`);
        }

        assert.equal(isSendOnlyGmailApp({ provider: 'outlook', baseScopes: 'api', extraScopes: ['Mail.Send'] }), false, 'not a Gmail app');
        assert.equal(isSendOnlyGmailApp(null), false);
    });

    await t.test('a send scope alone is not send-only while the default is still requested', () => {
        // The app requests the api-mode default (gmail.modify) unless skipScopes takes it out, so
        // judging extraScopes alone reported an app that can read as send-only - and the page then
        // offered the operator a scope list the application does not use
        assert.equal(isSendOnlyGmailApp({ provider: 'gmailService', baseScopes: 'api', extraScopes: ['gmail.send'] }), false);
        assert.equal(isSendOnlyGmailApp({ provider: 'gmail', baseScopes: 'api', extraScopes: ['gmail.send'] }), false);
    });

    await t.test('the create form offers the Gmail API radio to a service account', () => {
        const html = render('gmailService', 'imap');

        assert.match(scopeRadio(html, 'api') || '', /id="baseScopesAPI"/, 'the API radio is offered');
        assert.match(scopeRadio(html, 'imap') || '', /id="baseScopesImap"/, 'IMAP is still offered');
        assert.match(scopeRadio(html, 'pubsub') || '', /id="baseScopesPubsub"/, 'Pub/Sub is still offered');
        assert.match(html, /\/auth\/gmail\.modify/, 'the delegated scope it needs is named');
    });

    await t.test('a stored service-account app in API mode says so', () => {
        const html = render('gmailService', 'api', { actionCreate: false });
        assert.match(html, /<strong>Gmail API<\/strong>/, 'the read-only row names the mode');
    });

    await t.test('the service account gets the Pub/Sub app selector and the scope presets', () => {
        // Both belong to the API mode rather than to the interactive provider: the selector arms
        // watches, and the presets write the delegated scope list
        const html = render('gmailService', 'api');
        assert.match(html, /id="pubSubApp"/);
        assert.match(html, /id="account-type-card-gmail"/);
        assert.doesNotMatch(html.match(/<select[^>]*id="pubSubApp"[^>]*>/)[0], /\bdisabled\b/, 'the selector is usable in API mode');
    });

    await t.test('the stored service accounts stay selectable in every mode', () => {
        // `{{#unless baseScopesApi}}` inside the {{#each}} resolved against the ITEM rather than the
        // page, so every option shipped disabled in every mode. On a stored app's page, where the script
        // leaves the server's visibility alone, that was the only control for its Pub/Sub service
        // account. The select carries the state of the whole control; filterPubSubApps() in the form
        // script owns which options are selectable, and nothing else may write it.
        for (const baseScopes of ['api', 'imap', 'pubsub']) {
            for (const actionCreate of [true, false]) {
                const options = render('gmailService', baseScopes, { actionCreate }).match(/<option[^>]*data-project[^>]*>/g) || [];
                assert.ok(options.length, `options are rendered for ${baseScopes}`);
                for (const option of options) {
                    assert.doesNotMatch(option, /\bdisabled\b/, `${baseScopes}, actionCreate=${actionCreate}`);
                }
            }
        }
    });

    await t.test('one section is revealed per base scope, and the selector follows it', () => {
        // One panel per base scope - the Pub/Sub service account lives in `api`, the topic and
        // subscription names in `pubsub` - which is why visibility is driven by data-base-scopes rather
        // than by element ids
        assert.deepEqual(toggledSections(render('gmailService', 'api')), { imap: 'hidden', api: 'shown', pubsub: 'hidden' });
        assert.deepEqual(toggledSections(render('gmailService', 'pubsub')), { imap: 'hidden', api: 'hidden', pubsub: 'shown' });
        assert.deepEqual(toggledSections(render('gmailService', 'imap')), { imap: 'shown', api: 'hidden', pubsub: 'hidden' });

        // A hidden selector is disabled, so it is left out of the submitted form rather than riding along
        for (const baseScopes of ['imap', 'pubsub']) {
            const select = render('gmailService', baseScopes).match(/<select[^>]*id="pubSubApp"[^>]*>/)[0];
            assert.match(select, /\bdisabled\b/, `the selector is disabled for ${baseScopes}`);
        }
    });

    await t.test("the app page names the scopes a service account's delegation needs", () => {
        // The gmailService branch hardcoded gmail.modify, so an app deliberately holding gmail.send
        // alone was told to enable the scope it had skipped, and never got the limitation warning. Both
        // providers now answer from the app's own scope selection.
        for (const provider of ['gmail', 'gmailService']) {
            assert.deepEqual(requiredScopes(provider, 'api'), { scopes: ['gmail.modify'], sendOnlyAlert: false }, provider);

            assert.deepEqual(
                requiredScopes(provider, 'api', { disabledScopes: { Gmail_Modify: true }, isSendOnlyGmail: true }),
                { scopes: ['gmail.send'], sendOnlyAlert: true },
                `${provider}, send-only`
            );

            assert.deepEqual(
                requiredScopes(provider, 'api', { disabledScopes: { Gmail_Modify: true } }),
                { scopes: ['gmail.readonly', 'gmail.labels'], sendOnlyAlert: false },
                `${provider}, modify skipped but can read`
            );
        }

        // The other base scopes are untouched
        assert.deepEqual(requiredScopes('gmailService', 'imap').scopes, ['https://mail.google.com/']);
        assert.deepEqual(requiredScopes('gmailService', 'pubsub').scopes, []);
    });

    await t.test('the other providers are unchanged', () => {
        const gmail = render('gmail', 'api');
        assert.match(scopeRadio(gmail, 'api') || '', /id="baseScopesAPI"/);
        assert.match(gmail, /id="pubSubApp"/);
        assert.doesNotMatch(gmail, /id="baseScopesPubsub"/, 'an interactive app has no Pub/Sub base scope');
        assert.deepEqual(toggledSections(gmail), { imap: 'hidden', api: 'shown' });

        // Microsoft keeps its own API row and gains no Gmail control
        const outlook = render('outlook', 'api');
        assert.match(scopeRadio(outlook, 'api') || '', /id="baseScopesAPI"/);
        assert.doesNotMatch(outlook, /id="pubSubApp"/);
        assert.doesNotMatch(outlook, /id="account-type-card-gmail"/);

        // Application access has the one mode: its panel is always shown, and there is no strip
        const outlookService = render('outlookService', 'imap');
        assert.deepEqual(toggledSections(outlookService), { api: 'shown' });
        assert.doesNotMatch(outlookService, /class="base-scopes-radio/, 'nothing to choose');
    });
});
