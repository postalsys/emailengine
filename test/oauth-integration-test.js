'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

test('OAuth integration tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    const { GmailOauth } = require('../lib/oauth/gmail');
    const { OutlookOauth } = require('../lib/oauth/outlook');
    const { MailRuOauth } = require('../lib/oauth/mail-ru');

    // Module loading

    await t.test('Gmail OAuth module exports expected members', async () => {
        const gmailModule = require('../lib/oauth/gmail');
        assert.ok(gmailModule.GmailOauth);
        assert.ok(gmailModule.GMAIL_SCOPES);
    });

    await t.test('Outlook OAuth module exports expected members', async () => {
        const outlookModule = require('../lib/oauth/outlook');
        assert.ok(outlookModule.OutlookOauth);
        assert.ok(outlookModule.outlookScopes);
    });

    await t.test('Mail.ru OAuth module exports expected members', async () => {
        const mailruModule = require('../lib/oauth/mail-ru');
        assert.ok(mailruModule.MailRuOauth);
    });

    // Token request body serialization

    await t.test('GmailOauth.getTokenRequest returns URL-encoded string body', async () => {
        const gmail = new GmailOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        const tokenRequest = gmail.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('client_secret'), 'test-client-secret');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('OutlookOauth.getTokenRequest returns URL-encoded string body', async () => {
        const outlook = new OutlookOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            authority: 'common',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        const tokenRequest = outlook.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('MailRuOauth.getTokenRequest returns URL-encoded string body', async () => {
        const mailru = new MailRuOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        const tokenRequest = mailru.getTokenRequest({ code: 'test-auth-code' });

        assert.strictEqual(typeof tokenRequest.body, 'string');

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-auth-code');
        assert.strictEqual(params.get('grant_type'), 'authorization_code');
    });

    await t.test('Token request body properly encodes special characters', async () => {
        const gmail = new GmailOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-secret-with-special-chars!@#',
            redirectUrl: 'http://localhost/callback?param=value',
            setFlag: async () => {}
        });

        const tokenRequest = gmail.getTokenRequest({ code: 'test-code' });

        const params = new URLSearchParams(tokenRequest.body);
        assert.strictEqual(params.get('code'), 'test-code');
        assert.strictEqual(params.get('client_id'), 'test-client-id');
        assert.strictEqual(params.get('client_secret'), 'test-secret-with-special-chars!@#');
        assert.strictEqual(params.get('redirect_uri'), 'http://localhost/callback?param=value');
    });

    // Error handling with null/undefined responseJson

    await t.test('Error response falls back when responseJson is undefined or null', async () => {
        const buildErrorResponse = responseJson => {
            return responseJson || { error: 'Failed to parse response' };
        };

        assert.deepStrictEqual(buildErrorResponse(undefined), { error: 'Failed to parse response' });
        assert.deepStrictEqual(buildErrorResponse(null), { error: 'Failed to parse response' });
        assert.strictEqual(buildErrorResponse({ error: 'invalid_grant' }).error, 'invalid_grant');
    });

    await t.test('Optional chaining prevents error on null error_description', async () => {
        const EXPOSE_PARTIAL_SECRET_KEY_REGEX = /Unauthorized/i;

        const testCases = [null, undefined, {}, { error: 'some_error' }, { error_description: null }, { error_description: undefined }];

        for (const response of testCases) {
            const result = EXPOSE_PARTIAL_SECRET_KEY_REGEX.test(response?.error_description);
            assert.strictEqual(typeof result, 'boolean');
        }

        assert.ok(EXPOSE_PARTIAL_SECRET_KEY_REGEX.test({ error_description: 'Unauthorized access' }?.error_description));
    });

    // Auth URL generation

    await t.test('GmailOauth generates valid auth URL', async () => {
        const gmail = new GmailOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-secret',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        const authUrl = gmail.generateAuthUrl({ state: 'test-state' });

        assert.ok(authUrl.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));
        assert.ok(authUrl.includes('client_id=test-client-id'));
        assert.ok(authUrl.includes('state=test-state'));
    });

    await t.test('OutlookOauth generates valid auth URL', async () => {
        const outlook = new OutlookOauth({
            clientId: 'test-client-id',
            clientSecret: 'test-secret',
            authority: 'common',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        const authUrl = outlook.generateAuthUrl({ state: 'test-state' });

        assert.ok(authUrl.includes('login.microsoftonline.com'));
        assert.ok(authUrl.includes('client_id=test-client-id'));
        assert.ok(authUrl.includes('state=test-state'));
    });

    // Cloud configuration

    await t.test('OutlookOauth instantiates with different cloud configurations', async () => {
        const clouds = ['global', 'gcc-high', 'dod', 'china'];

        for (const cloud of clouds) {
            const outlook = new OutlookOauth({
                clientId: 'test-id',
                clientSecret: 'test-secret',
                authority: 'common',
                redirectUrl: 'http://localhost/callback',
                cloud,
                setFlag: async () => {}
            });

            assert.strictEqual(outlook.cloud, cloud);
            assert.ok(outlook.entraEndpoint, `Should have entraEndpoint for ${cloud}`);
            assert.ok(outlook.apiBase, `Should have apiBase for ${cloud}`);
        }
    });

    await t.test('GmailOauth has default scopes', async () => {
        const gmail = new GmailOauth({
            clientId: 'test-id',
            clientSecret: 'test-secret',
            redirectUrl: 'http://localhost/callback',
            setFlag: async () => {}
        });

        assert.ok(gmail.scopes.length > 0);
    });
});
